package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// The client-facing WireGuard credential page: the operator half of the leg that
// used to live in wg-easy's own UI.
//
// The one rule that shapes this file: a client's private key exists here, and
// nowhere else in the request path. It is used to render a .conf and its QR and
// is never listed, never logged and never put in a template variable of its own —
// the page shows names, addresses and status, and the config is a separate
// download the operator asks for deliberately.

// wgClientsData is the client-WG management page view model.
type wgClientsData struct {
	Title     string
	NodeCount int
	User      string
	Flash     string
	CSRF      string
	NodeID    string
	NodeName  string
	Managed   bool   // the agent owns this master's client interface
	Ready     bool   // endpoint + published key present, so configs can be built
	Notice    string // why configs aren't ready yet (empty when Ready)
	Endpoint  string // host:port clients dial
	Pool      string
	// PortalBase is the public base URL of the self-service portal, so each card
	// can show the link the operator actually hands to a person. Empty ⇒ the portal
	// is off or its URL is unset, and the link column is hidden rather than guessed.
	PortalBase string
	Clients    []wgClientRow
}

// wgClientRow is one issued credential rendered for the page.
type wgClientRow struct {
	ID        string
	Name      string
	Address   string
	Enabled   bool
	Created   string
	PublicKey string
	// Handshake / Transfer describe the live peer as the agent last reported it.
	// Empty when the node has not reported this peer yet.
	Handshake string
	Transfer  string
	Online    bool
}

// handleWGClients renders the master's client-WG credential page.
func (h *Handler) handleWGClients(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		httpError(w, "load node", err)
		return
	}
	user, _ := h.currentUser(r)
	data := wgClientsData{
		Title: "WireGuard clients — " + node.Name, NodeCount: h.fleetCount(r.Context()),
		User: user, Flash: h.takeFlash(w, r), CSRF: h.csrf,
		NodeID: id, NodeName: node.Name,
	}

	spec, err := h.renderer.RenderNodeSpec(r.Context(), id)
	if err != nil {
		data.Notice = "cannot render node spec: " + err.Error()
		h.render(w, h.wgClientsTmpl, "layout", data)
		return
	}
	if spec.Master == nil {
		data.Notice = "This node is not a master, so it has no client interface."
		h.render(w, h.wgClientsTmpl, "layout", data)
		return
	}

	clients, err := h.renderer.ListWGClients(r.Context(), id)
	if err != nil {
		data.Notice = "cannot list credentials: " + err.Error()
		h.render(w, h.wgClientsTmpl, "layout", data)
		return
	}

	cw := spec.Master.ClientWG
	switch {
	case cw == nil:
		// Credentials can be issued and imported BEFORE the handover — that is the
		// migration order — so the page stays usable and says what is missing.
		data.Notice = "wg-easy still owns this master's client interface. Credentials issued here " +
			"take effect once you set `client_awg.managed: true` for this master in the fleet manifest."
	default:
		data.Managed = true
		data.Pool = cw.AddressPool
		host := endpointHost(node, spec)
		switch {
		case host == "":
			data.Notice = "No public endpoint known for this master yet (public_ip). Set it in the manifest or wait for provisioning."
		case node.ClientWGPublicKey == "":
			data.Notice = "The master has not published its client interface key yet — wait for the agent to reconcile once, then reload."
		default:
			data.Ready = true
			data.Endpoint = net.JoinHostPort(host, strconv.Itoa(cw.ListenPort))
		}
	}

	data.PortalBase = h.portalBase
	peers := h.clientPeerStatus(r, id)
	for _, c := range clients {
		row := wgClientRow{
			ID: c.ID, Name: c.Name, Address: c.Address, Enabled: c.Enabled,
			PublicKey: c.PublicKey,
		}
		if !c.CreatedAt.IsZero() {
			row.Created = c.CreatedAt.Format("2006-01-02")
		}
		if p, ok := peers[c.PublicKey]; ok {
			row.Handshake, row.Online = describeHandshake(p.LastHandshake)
			row.Transfer = describeTransfer(p.ReceivedBytes, p.SentBytes)
		}
		data.Clients = append(data.Clients, row)
	}
	h.render(w, h.wgClientsTmpl, "layout", data)
}

// clientPeerStatus returns the last reported per-peer status keyed by public key.
// A node that has not reported yet simply yields an empty map — the page then
// shows credentials without live columns rather than failing.
func (h *Handler) clientPeerStatus(r *http.Request, nodeID string) map[string]domain.ClientPeerStatus {
	st, err := h.store.GetStatus(r.Context(), nodeID)
	if err != nil {
		return nil
	}
	out := make(map[string]domain.ClientPeerStatus, len(st.ClientPeers))
	for _, p := range st.ClientPeers {
		out[p.PublicKey] = p
	}
	return out
}

// describeHandshake renders the age of the last handshake and whether the peer
// counts as online (a client with a keepalive of 25s that has not been heard from
// in three minutes is not connected, whatever its config says).
func describeHandshake(t time.Time) (string, bool) {
	if t.IsZero() {
		return "never", false
	}
	age := time.Since(t)
	return shortDuration(age) + " ago", age < clientOnlineWindow
}

// clientOnlineWindow is how stale a handshake may be and still count as online.
const clientOnlineWindow = 3 * time.Minute

func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func describeTransfer(rx, tx int64) string {
	if rx == 0 && tx == 0 {
		return ""
	}
	return fmt.Sprintf("%s ↓ / %s ↑", humanBytes(rx), humanBytes(tx))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// handleWGClientIssue mints a new credential for the master.
func (h *Handler) handleWGClientIssue(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	dest := "/nodes/" + id + "/wg-clients"
	name := strings.TrimSpace(r.FormValue("name"))
	if !validClientName(name) {
		h.redirectErr(w, r, dest, "issue client",
			errors.New("name must be 1-64 chars of letters, digits, '-', '_' or '.'"))
		return
	}
	if _, err := h.renderer.IssueWGClient(r.Context(), id, name); err != nil {
		h.redirectErr(w, r, dest, "issue client", clientActionError(err, name))
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleWGClientRevoke removes a credential outright.
func (h *Handler) handleWGClientRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id, clientID := r.PathValue("id"), r.PathValue("client")
	dest := "/nodes/" + id + "/wg-clients"
	if err := h.renderer.RevokeWGClient(r.Context(), id, clientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.redirectErr(w, r, dest, "revoke client", errors.New("client not found"))
			return
		}
		h.redirectErr(w, r, dest, "revoke client", err)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleWGClientToggle mutes or unmutes a credential. Muting drops the peer from
// the interface on the next reconcile; the config the user holds stays valid, so
// unmuting restores the connection without reissuing anything.
func (h *Handler) handleWGClientToggle(enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.guard(w, r) {
			return
		}
		id, clientID := r.PathValue("id"), r.PathValue("client")
		dest := "/nodes/" + id + "/wg-clients"
		action := "mute client"
		if enable {
			action = "unmute client"
		}
		if err := h.renderer.SetWGClientEnabled(r.Context(), id, clientID, enable); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				h.redirectErr(w, r, dest, action, errors.New("client not found"))
				return
			}
			h.redirectErr(w, r, dest, action, err)
			return
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
	}
}

// handleWGClientRename changes the label without touching identity or keys.
func (h *Handler) handleWGClientRename(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id, clientID := r.PathValue("id"), r.PathValue("client")
	dest := "/nodes/" + id + "/wg-clients"
	name := strings.TrimSpace(r.FormValue("name"))
	if !validClientName(name) {
		h.redirectErr(w, r, dest, "rename client",
			errors.New("name must be 1-64 chars of letters, digits, '-', '_' or '.'"))
		return
	}
	if err := h.renderer.RenameWGClient(r.Context(), id, clientID, name); err != nil {
		h.redirectErr(w, r, dest, "rename client", clientActionError(err, name))
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleWGClientConfig serves one client's .conf as a download.
func (h *Handler) handleWGClientConfig(w http.ResponseWriter, r *http.Request) {
	cfg, client, err := h.buildClientConfig(r)
	if err != nil {
		httpError(w, "build client config", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// A tunnel config is a credential: never let a cache or a proxy keep a copy.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", clientcfg.ConfigFileName(client)))
	_, _ = w.Write([]byte(cfg))
}

// handleWGClientQR serves the QR of one client's .conf, for phone import.
func (h *Handler) handleWGClientQR(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := h.buildClientConfig(r)
	if err != nil {
		httpError(w, "build client config", err)
		return
	}
	png, err := qrPNG(cfg)
	if err != nil {
		httpError(w, "render QR", err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// buildClientConfig resolves one client's config through the shared builder, so
// the operator UI and the self-service portal always render the same bytes.
func (h *Handler) buildClientConfig(r *http.Request) (string, domain.WGClient, error) {
	res, err := clientcfg.Build(r.Context(), clientSource{h}, r.PathValue("id"), r.PathValue("client"))
	if err != nil {
		return "", domain.WGClient{}, err
	}
	return res.Config, res.Client, nil
}

// clientSource adapts the handler's store + renderer to clientcfg.Source.
type clientSource struct{ h *Handler }

func (s clientSource) GetNode(ctx context.Context, id string) (domain.Node, error) {
	return s.h.store.GetNode(ctx, id)
}

func (s clientSource) RenderNodeSpec(ctx context.Context, id string) (domain.NodeSpec, error) {
	return s.h.renderer.RenderNodeSpec(ctx, id)
}

func (s clientSource) ListWGClients(ctx context.Context, id string) ([]domain.WGClient, error) {
	return s.h.renderer.ListWGClients(ctx, id)
}

// qrPNG encodes a client config as a QR image. The config is a credential, so it
// is served from its own endpoint as bytes rather than embedded in the page as a
// data: URL — a page the browser may cache should not carry a private key.
func qrPNG(s string) ([]byte, error) {
	return qrcode.Encode(s, qrcode.Medium, 320)
}

// clientActionError turns the failures an operator actually hits into sentences
// that say what to do. Everything else passes through untouched — inventing a
// friendly message for an unrecognised error would only hide it.
func clientActionError(err error, name string) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errors.New("master not registered — provision it first")
	case errors.Is(err, domain.ErrPoolExhausted):
		return errors.New("the client address pool is full — revoke an unused client, or widen client_awg.address_pool for this master")
	case isUniqueViolation(err):
		// The single most likely mistake, and by default it surfaces as a raw
		// SQLite constraint string.
		return fmt.Errorf("a client named %q already exists on this master — pick a different name", name)
	default:
		return err
	}
}

// isUniqueViolation recognises the store's duplicate-name/address refusal. The
// driver reports it as a message rather than a typed error, so this matches on
// the text it is documented to produce.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
