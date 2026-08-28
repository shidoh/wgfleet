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
	// FlashOK is the counterpart nobody had: a one-shot confirmation that the last
	// action worked, so the page can close its loop instead of silently reloading.
	FlashOK string
	// IfaceDown is non-empty when the master's own client-interface health check is
	// failing: every client below is offline for THAT reason, not their own.
	IfaceDown string
	CSRF      string
	NodeID    string
	NodeName  string
	Managed   bool // the agent owns this master's client interface
	Ready     bool // endpoint + published key present, so configs can be built
	// Notice explains a state the operator can act on (configs not ready yet).
	// Err is a FAILURE: the page could not load what it is meant to show. They are
	// rendered differently and must not be merged — an error printed as a hint is
	// how a page ends up calmly announcing "0 clients" when it simply could not
	// read them.
	Notice string
	Err    string
	// NotMaster is a dead end, not a failure: only a master has a client
	// interface, and this page is reachable on another node only by a stale
	// bookmark. Rendering it in the red alert treatment reserved for real errors
	// tells the operator something broke when nothing did.
	NotMaster bool
	// Iface is the interface the credentials on this page attach to. Nil until the
	// agent owns the leg; shown so the operator does not have to open the manifest
	// to answer "what pool / port / MTU does a config get".
	Iface    *wgIfaceView
	Endpoint string // host:port clients dial
	// PortalBase is the public base URL of the self-service portal, so each card
	// can show the link the operator actually hands to a person. Empty ⇒ the portal
	// is off or its URL is unset, and the link column is hidden rather than guessed.
	PortalBase string
	Clients    []wgClientRow
}

// wgIfaceView describes the interface these credentials attach to. Everything a
// generated config inherits is here, so the operator can answer "what will this
// person get" without opening the manifest.
type wgIfaceView struct {
	Pool       string
	ListenPort int
	ServerAddr string
	MTU        int
	DNS        string
	AllowedIPs string
	// RouteCount and FullTunnel describe the routing table without making the
	// operator read it: an expanded list runs to dozens of entries, and printed
	// raw in a table cell it is a wall nobody checks.
	RouteCount int
	FullTunnel bool
	Backend    string
	AWG        string
	// IPv6 and UDP describe two things that change what a client's traffic DOES and
	// were visible nowhere in the product: the operator could not answer "is IPv6
	// blocked?" or "is client UDP being carried?" from any surface, only by reading
	// `nft list ruleset` on the master.
	IPv6 string
	UDP  string
}

// wgClientRow is one issued credential rendered for the page.
type wgClientRow struct {
	ID      string
	Name    string
	Address string
	Enabled bool
	Created string
	// Handshake / Transfer describe the live peer as the agent last reported it.
	// Empty when the node has not reported this peer yet.
	Handshake string
	Transfer  string
	// State is the ONE chip the card head shows. Absence used to carry meaning:
	// an enabled credential that was simply offline rendered no badge at all and
	// looked exactly like a card nobody had parsed yet. Four conditions the
	// operator must act on differently now say so in words.
	State string
	// StateKind selects the chip's colour variant: online | idle | never | unreported.
	StateKind string
}

// peerState resolves a credential's live state into the head chip. The two
// "no handshake" cases are deliberately NOT merged: "never connected" means the
// node reports the peer and it has never completed a handshake (bad config on
// the person's side, or blocked), while "not reported" means the peer is absent
// from the node's status entirely (reconcile pending, or the node is silent).
// They demand opposite next actions.
func peerState(reported bool, hs time.Time) (label, kind string) {
	switch {
	case !reported:
		return "not reported", "unreported"
	case hs.IsZero():
		return "never connected", "never"
	case time.Since(hs) < clientOnlineWindow:
		return "online", "online"
	default:
		return "idle · " + shortDuration(time.Since(hs)), "idle"
	}
}

// handleWGClients renders the master's client-WG credential page.
func (h *Handler) handleWGClients(w http.ResponseWriter, r *http.Request) {
	data, err := h.wgClientsView(w, r)
	if err != nil {
		httpError(w, "load node", err)
		return
	}
	// Read the one-shot flashes HERE and nowhere else. They are read-and-clear, and
	// wgClientsView is shared with the 10-second poll — so a tick landing between an
	// action's redirect and the page render ate the message. Worse, the cookie path
	// is "/", so a clients tab left open would eat a FAILURE flash raised by an
	// action on another page in another tab: the operator clicks Provision, it
	// fails, and the node page renders as though it worked.
	data.Flash = h.takeFlash(w, r)
	data.FlashOK = h.takeFlashOK(w, r)
	h.render(w, h.wgClientsTmpl, "layout", data)
}

// handleWGClientsPanel answers the 10-second poll with the credentials panel and
// nothing else.
//
// It exists because the poll used to re-fetch the WHOLE page and pick the panel
// out of it with hx-select. The three-way split this page is built on — failure,
// not-a-master, normal — means two of those responses contain no panel at all, so
// one transient store error made the selector match nothing; htmx swapped in the
// empty string and outerHTML removed the panel, its LIVE chip and the poll itself.
// The operator saw a page that had silently lost its client list, with no error
// anywhere, until they reloaded.
//
// So this endpoint never renders a partial answer. It either has the panel or it
// answers 204, which htmx treats as "nothing to do" — the poll stays alive and
// the next tick tries again. Rendering the whole page and discarding 80% of it
// was also the bulk of the cost of leaving this tab open all day.
func (h *Handler) handleWGClientsPanel(w http.ResponseWriter, r *http.Request) {
	data, err := h.wgClientsView(w, r)
	if err != nil || data.Err != "" || data.NotMaster {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.render(w, h.wgClientsTmpl, "credentials-panel", data)
}

// wgClientsView builds the page's view model. The error return is reserved for
// "cannot even identify the node"; everything else is reported inside the model,
// because the page has a designed treatment for each case and the fragment
// endpoint needs to tell them apart.
func (h *Handler) wgClientsView(w http.ResponseWriter, r *http.Request) (wgClientsData, error) {
	id := r.PathValue("id")
	node, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		return wgClientsData{}, err
	}
	user, _ := h.currentUser(r)
	data := wgClientsData{
		Title: "AWG clients — " + node.Name, NodeCount: h.fleetCount(r.Context()),
		User: user, CSRF: h.csrf,
		NodeID: id, NodeName: node.Name,
	}

	// Each of these is a dead end, and the template renders NOTHING else when Err
	// is set. Rendering the issue form and an empty credential list next to a
	// failure is how the page ends up asserting "no clients" on a node it could
	// not read — or offering to issue one on a node that cannot hold any.
	spec, err := h.renderer.RenderNodeSpec(r.Context(), id)
	if err != nil {
		data.Err = "Cannot render this node's spec: " + err.Error()
		return data, nil
	}
	if spec.Master == nil {
		data.NotMaster = true
		return data, nil
	}

	clients, err := h.renderer.ListWGClients(r.Context(), id)
	if err != nil {
		data.Err = "Cannot list credentials: " + err.Error()
		return data, nil
	}

	cw := spec.Master.ClientWG
	switch {
	case cw == nil:
		// Credentials can be issued and imported BEFORE the handover — that is the
		// migration order — so the page stays usable and says what is missing. The
		// No Notice here: the CLIENT INTERFACE panel owns this fact and can format
		// the manifest key as markup. Setting it too printed the same sentence twice,
		// once with raw backticks.
	default:
		data.Managed = true
		data.Iface = ifaceView(cw)
		host := endpointHost(node, spec)
		switch {
		case host == "":
			data.Notice = "No public endpoint known for this master yet (public_ip). Set it in the manifest or wait for provisioning."
		case node.ClientWGPublicKey == "":
			// The distinction this used to carry in a bool — "waiting helps" versus
			// "waiting never will" — is already the difference between these two
			// Notice texts, which is where the operator actually reads it. The field
			// was set, never rendered, and explained itself in a comment instead.
			data.Notice = "The master has not published its client interface key yet — wait one reconcile pass, then reload."
		default:
			data.Ready = true
			data.Endpoint = net.JoinHostPort(host, strconv.Itoa(cw.ListenPort))
		}
	}

	data.PortalBase = h.portalBase
	if data.Managed {
		data.IfaceDown = h.clientInterfaceDown(r, id)
	}
	peers := h.clientPeerStatus(r, id)
	for _, c := range clients {
		row := wgClientRow{
			ID: c.ID, Name: c.Name, Address: c.Address, Enabled: c.Enabled,
		}
		if !c.CreatedAt.IsZero() {
			row.Created = c.CreatedAt.Format("2006-01-02")
		}
		p, reported := peers[c.PublicKey]
		if reported {
			row.Handshake, _ = describeHandshake(p.LastHandshake)
			row.Transfer = describeTransfer(p.ReceivedBytes, p.SentBytes)
		}
		row.State, row.StateKind = peerState(reported, p.LastHandshake)
		data.Clients = append(data.Clients, row)
	}
	return data, nil
}

// clientPeerStatus returns the last reported per-peer status keyed by public key.
// A node that has not reported yet simply yields an empty map — the page then
// shows credentials without live columns rather than failing.
// clientInterfaceDown reports the master's own client-interface health check when
// it is failing. It is the difference between "these forty people are offline" and
// "this one interface is down", which the per-client chips cannot express: each of
// them is individually a fact, not a fault, and forty calm grey chips under a
// pulsing green LIVE badge is the page's most misleading possible state.
func (h *Handler) clientInterfaceDown(r *http.Request, nodeID string) string {
	st, err := h.store.GetStatus(r.Context(), nodeID)
	if err != nil {
		return ""
	}
	for _, c := range st.Checks {
		if strings.HasPrefix(c.Name, "client-wg") && !c.OK {
			if c.Detail != "" {
				return c.Detail
			}
			return "the agent reports its client interface is not up"
		}
	}
	return ""
}

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
	c, err := h.renderer.IssueWGClient(r.Context(), id, name)
	if err != nil {
		h.redirectErr(w, r, dest, "issue client", clientActionError(err, name))
		return
	}
	// Land ON the new credential, and say so. The page's headline action used to
	// end in a bare redirect: the card is inserted ALPHABETICALLY among all the
	// others, unhighlighted, with its hand-out collapsed — so the only evidence
	// anything happened was the counter in the panel heading going up by one.
	h.setFlashOK(w, "Issued "+name+" — its config and link are below.")
	http.Redirect(w, r, dest+"#client-"+c.ID, http.StatusSeeOther)
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
		action := "pause client access"
		if enable {
			action = "resume client access"
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
	// 1024, not 320. Measured on a real client config (867 bytes): 117x117
	// modules at Medium recovery. At 320px that is 2.7 pixels per module and a
	// phone camera cannot resolve it — the page used to shrink it further, to 168.
	// The page now shows it at 512, an exact 2:1 downscale (pixel-for-pixel on a
	// HiDPI screen), which puts 4.4 pixels on each module — above the ~4 that
	// ordinary cameras need.
	return qrcode.Encode(s, qrcode.Medium, 1024)
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
	case isUniqueViolation(err, "address"):
		// Reachable when an import runs alongside the UI: renaming would not help,
		// so saying "pick a different name" would send the operator in circles.
		return errors.New("that address is already taken on this master — another credential (or an import running now) holds it")
	case isUniqueViolation(err, "name"):
		// The single most likely mistake, and by default it surfaces as a raw
		// SQLite constraint string.
		return fmt.Errorf("a client named %q already exists on this master — pick a different name", name)
	default:
		return err
	}
}

// isUniqueViolation recognises the store's duplicate refusal for ONE column. The
// driver reports it as a message rather than a typed error and names the column
// it tripped, which is what lets a name collision and an address collision get
// different advice — they need opposite actions.
func isUniqueViolation(err error, column string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") && strings.Contains(msg, column)
}

// ifaceView projects the client interface spec onto the page's INTERFACE panel.
func ifaceView(cw *domain.ClientWGSpec) *wgIfaceView {
	v := &wgIfaceView{
		Pool: cw.AddressPool, ListenPort: cw.ListenPort, ServerAddr: cw.ServerAddress,
		MTU: cw.MTU, DNS: strings.Join(cw.DNS, ", "),
		AllowedIPs: strings.Join(cw.AllowedIPs, ", "),
		RouteCount: len(cw.AllowedIPs),
		// The default route is worth calling out rather than printing: it is the one
		// value that silently costs a client access to its own local network.
		FullTunnel: len(cw.AllowedIPs) == 0 || (len(cw.AllowedIPs) == 1 && cw.AllowedIPs[0] == "0.0.0.0/0"),
		Backend:    string(cw.ResolvedBackend()),
	}
	// The IPv6 half of the client policy. "off" is not nothing: it means the client
	// keeps its own native IPv6, so every dual-stack destination happy eyeballs
	// prefers leaves the tunnel while the app says connected.
	if cw.IPv6Prefix != "" {
		v.IPv6 = "blocked · " + cw.IPv6Prefix + " (clients route ::/0 here and are refused audibly)"
	} else {
		v.IPv6 = "off · clients keep their own IPv6, which bypasses the tunnel"
	}
	// UDP is carried through the proxy whenever the master has an address to bind a
	// transparent listener on — the same condition the agent renders the rules from.
	if cw.ServerAddress != "" {
		v.UDP = "carried through the proxy (TPROXY)"
	} else {
		v.UDP = "not intercepted — pending the gateway address"
	}
	switch {
	case cw.AWG == nil:
		// Named by what it is rather than by the protocol: the console says AWG
		// throughout, and "plain WireGuard" here made the one place the operator
		// looks to check obfuscation the one place that used the other word.
		v.AWG = "off — no obfuscation"
	case cw.AWG.Shared.HeaderProtectionKey != "":
		// Header protection is the one 3.x parameter existing clients cannot
		// survive, so it is worth naming separately from the timers.
		v.AWG = "3.x · header protection + timers"
	case cw.AWG.AWG3Enabled():
		v.AWG = "3.x · timers only"
	default:
		v.AWG = "2.0"
	}
	return v
}
