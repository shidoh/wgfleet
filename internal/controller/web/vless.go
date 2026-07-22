package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// clientsData is the client-VLESS management page view model.
type clientsData struct {
	Title      string
	NodeCount  int
	User       string
	Flash      string
	CSRF       string
	NodeID     string
	NodeName   string
	Enabled    bool        // the master runs the client VLESS inbound
	Ready      bool        // endpoint + published key present, so links can be built
	Notice     string      // why links aren't ready yet (empty when Ready)
	Endpoint   string      // host:port clients dial
	Clients    []clientRow // issued credentials with links + QR
	RouteThru  []string    // CIDRs routed through the tunnel (config-managed)
	RoutingB64 string      // v2rayTun routing object (base64) built from RouteThru
	RoutingQR  template.URL
}

// clientRow is one issued VLESS credential rendered for the page.
type clientRow struct {
	Name    string
	UUID    string
	ShortID string
	Link    string       // vless:// share link
	QR      template.URL // data:image/png;base64,… QR of Link (template.URL so it isn't sanitized to #ZgotmplZ)
	SubURL  string       // subscription URL (carries the routing header)
	SubQR   template.URL // QR of SubURL
}

// handleClients renders the master's client-VLESS credential management page.
func (h *Handler) handleClients(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		httpError(w, "load node", err)
		return
	}
	user, _ := h.currentUser(r)
	data := clientsData{
		Title: "VLESS clients — " + node.Name, NodeCount: h.fleetCount(r.Context()),
		User: user, Flash: h.takeFlash(w, r), CSRF: h.csrf,
		NodeID: id, NodeName: node.Name,
	}

	spec, err := h.renderer.RenderNodeSpec(r.Context(), id)
	if err != nil {
		data.Notice = "cannot render node spec: " + err.Error()
		h.render(w, h.clientsTmpl, "layout", data)
		return
	}
	if spec.Master == nil || spec.Master.ClientVLESS == nil {
		data.Notice = "This master does not run the client VLESS transport. Enable it with " +
			"`client_vless.enabled: true` on this master in the fleet manifest."
		h.render(w, h.clientsTmpl, "layout", data)
		return
	}
	cv := spec.Master.ClientVLESS
	data.Enabled = true

	host := endpointHost(node, spec)
	pubkey := node.ClientVLESSPublicKey
	switch {
	case host == "":
		data.Notice = "No public endpoint known for this master yet (public_ip). Set it in the manifest or wait for provisioning."
	case pubkey == "":
		data.Notice = "The master has not published its client VLESS key yet — wait for the agent to reconcile once, then reload."
	default:
		data.Ready = true
		data.Endpoint = net.JoinHostPort(host, strconv.Itoa(cv.ListenPort))
	}

	// Routing object (config-managed): the internal nets clients should route THROUGH
	// the tunnel. Shown as base64 + QR, and served in the subscription's routing header.
	data.RouteThru = h.renderer.ClientVLESSRouteThrough(id)
	if len(data.RouteThru) > 0 {
		data.RoutingB64 = buildRoutingObject(data.RouteThru)
		data.RoutingQR = h.qr(data.RoutingB64)
	}

	clients, err := h.renderer.ListVLESSClients(r.Context(), id)
	if err != nil {
		data.Notice = "listing clients failed: " + err.Error()
		h.render(w, h.clientsTmpl, "layout", data)
		return
	}
	for _, c := range clients {
		row := clientRow{Name: c.Name, UUID: c.UUID, ShortID: c.ShortID}
		if data.Ready {
			row.Link = buildVlessLink(host, cv.ListenPort, *cv, pubkey, node.Name, c)
			row.QR = h.qr(row.Link)
			// Subscription URL: fetched by the client, it returns this vless link and
			// carries the routing object in the `routing` response header. Built from
			// the host the operator is browsing (the mgmt/ZT overlay).
			row.SubURL = subscriptionURL(r, id, c.UUID)
			row.SubQR = h.qr(row.SubURL)
		}
		data.Clients = append(data.Clients, row)
	}
	h.render(w, h.clientsTmpl, "layout", data)
}

// handleSubscription serves a client's subscription: the vless link (base64 body,
// standard subscription format) plus the v2rayTun `routing` header carrying the
// route-through-tunnel rules. Auth-exempt — the client fetches it unauthenticated,
// identified by its UUID token (already its secret credential).
func (h *Handler) handleSubscription(w http.ResponseWriter, r *http.Request) {
	master := r.PathValue("master")
	token := r.PathValue("token")
	clients, err := h.renderer.ListVLESSClients(r.Context(), master)
	if err != nil {
		http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
		return
	}
	var found domain.VLESSClient
	for _, c := range clients {
		if c.UUID == token {
			found = c
			break
		}
	}
	if found.UUID == "" {
		http.NotFound(w, r)
		return
	}
	node, err := h.store.GetNode(r.Context(), master)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	spec, err := h.renderer.RenderNodeSpec(r.Context(), master)
	if err != nil || spec.Master == nil || spec.Master.ClientVLESS == nil {
		http.Error(w, "subscription not ready", http.StatusServiceUnavailable)
		return
	}
	cv := spec.Master.ClientVLESS
	host := endpointHost(node, spec)
	if host == "" || node.ClientVLESSPublicKey == "" {
		http.Error(w, "subscription not ready", http.StatusServiceUnavailable)
		return
	}
	link := buildVlessLink(host, cv.ListenPort, *cv, node.ClientVLESSPublicKey, node.Name, found)

	if cidrs := h.renderer.ClientVLESSRouteThrough(master); len(cidrs) > 0 {
		w.Header().Set("routing", buildRoutingObject(cidrs))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "24")
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(link + "\n"))))
}

// qr renders s as a PNG QR data-URI safe for an <img src>. template.URL keeps
// html/template from sanitizing the data: URI to "#ZgotmplZ" (a broken image).
func (h *Handler) qr(s string) template.URL {
	png, err := qrcode.Encode(s, qrcode.Medium, 256)
	if err != nil {
		h.log.Warn("web: QR encode failed", "error", err)
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

// subscriptionURL builds the client's subscription URL from the request host (so it
// matches the mgmt/ZT address the operator is browsing). HTTP: the panel rides the
// ZT overlay without TLS.
func subscriptionURL(r *http.Request, master, uuid string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/sub/%s/%s", scheme, r.Host, url.PathEscape(master), url.PathEscape(uuid))
}

// routingRule / routingObject mirror the v2rayTun (Xray) routing schema. IP rules
// with outboundTag "proxy" send those CIDRs THROUGH the tunnel.
type routingObject struct {
	DomainStrategy string        `json:"domainStrategy"`
	DomainMatcher  string        `json:"domainMatcher"`
	Balancers      []any         `json:"balancers"`
	Name           string        `json:"name"`
	Rules          []routingRule `json:"rules"`
}

type routingRule struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag"`
	Name        string   `json:"__name__"`
	IP          []string `json:"ip"`
}

// buildRoutingObject returns the base64-encoded v2rayTun routing object that routes
// cidrs through the tunnel (outboundTag "proxy").
func buildRoutingObject(cidrs []string) string {
	obj := routingObject{
		DomainStrategy: "AsIs",
		DomainMatcher:  "hybrid",
		Balancers:      []any{},
		Name:           "wgfleet internal via VPN",
		Rules: []routingRule{{
			Type:        "field",
			OutboundTag: "proxy",
			Name:        "wgfleet internal via VPN",
			IP:          append([]string(nil), cidrs...),
		}},
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// handleClientIssue mints a new VLESS credential for the master.
func (h *Handler) handleClientIssue(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	dest := "/nodes/" + id + "/clients"
	if !validClientName(name) {
		h.redirectErr(w, r, dest, "issue client", errors.New("name must be 1-64 chars of letters, digits, '-', '_' or '.'"))
		return
	}
	if _, err := h.renderer.IssueVLESSClient(r.Context(), id, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.redirectErr(w, r, dest, "issue client", errors.New("master not registered"))
			return
		}
		h.redirectErr(w, r, dest, "issue client", err)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleClientRevoke removes a VLESS credential from the master.
func (h *Handler) handleClientRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	name := r.PathValue("name")
	dest := "/nodes/" + id + "/clients"
	if err := h.renderer.RevokeVLESSClient(r.Context(), id, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.redirectErr(w, r, dest, "revoke client", errors.New("client not found"))
			return
		}
		h.redirectErr(w, r, dest, "revoke client", err)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// buildVlessLink assembles the vless:// share link for one credential, matching
// the master's inbound (REALITY + xhttp/vision, empty-SNI, path/mode). host:port
// is the master's public endpoint; the fragment labels the profile in the client.
func buildVlessLink(host string, port int, cv domain.ClientVLESSServerSpec, pubkey, nodeName string, c domain.VLESSClient) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("pbk", pubkey)
	q.Set("fp", "chrome")
	q.Set("sid", c.ShortID)
	// Empty-SNI (the client-leg default): send no SNI, the reported RU-TSPU bypass.
	// Otherwise carry the camouflage SNI (always one of the server's serverNames).
	if cv.AllowEmptySNI {
		q.Set("sni", "")
	} else {
		q.Set("sni", cv.ServerName)
	}
	if cv.Mode == domain.RealityModeVision {
		q.Set("type", "tcp")
		q.Set("flow", "xtls-rprx-vision")
	} else {
		q.Set("type", "xhttp")
		path := cv.XHTTPPath
		if path == "" {
			path = "/"
		}
		q.Set("path", path)
		mode := cv.XHTTPMode
		if mode == "" {
			mode = "packet-up"
		}
		q.Set("mode", mode)
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(c.UUID),
		Host:     net.JoinHostPort(host, strconv.Itoa(port)),
		RawQuery: q.Encode(),
		Fragment: fmt.Sprintf("%s-%s", nodeName, c.Name),
	}
	return u.String()
}

// endpointHost resolves the public host clients dial the master at: the stored
// public IP, falling back to the compose spec's (manifest public_ip).
func endpointHost(node domain.Node, spec domain.NodeSpec) string {
	if node.PublicIP != "" {
		return node.PublicIP
	}
	if spec.Master != nil {
		return spec.Master.Compose.PublicIP
	}
	return ""
}

// validClientName bounds the operator-supplied label so it is safe as a store key
// and vless:// fragment (no spaces/control chars, reasonable length).
func validClientName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
