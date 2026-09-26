package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/shidoh/wgfleet/internal/mihomo"
)

// clientsData is the client-VLESS management page view model.
type clientsData struct {
	Title       string
	NodeCount   int
	User        string
	Flash       string
	CSRF        string
	NodeID      string
	NodeName    string
	Enabled     bool         // the master runs the client VLESS inbound
	Ready       bool         // endpoint + published key present, so links can be built
	Notice      string       // why links aren't ready yet (empty when Ready)
	Endpoint    string       // host:port clients dial
	Clients     []clientRow  // issued credentials with links + QR
	RouteThru   []string     // CIDRs routed through the tunnel (config-managed)
	RoutingLink string       // v2rayTun://import_route/<base64> deep link (clipboard/QR import)
	RoutingQR   template.URL // QR of RoutingLink
}

// routingImportPrefix is the v2rayTun deep-link scheme its "import from clipboard"
// (and QR) expects in front of the base64 routing object. A bare base64 is not
// recognised — only this deep link imports.
const routingImportPrefix = "v2rayTun://import_route/"

// clientRow is one issued VLESS credential rendered for the page.
type clientRow struct {
	Name    string
	UUID    string
	ShortID string
	Link    string       // vless:// share link
	QR      template.URL // data:image/png;base64,… QR of Link (template.URL so it isn't sanitized to #ZgotmplZ)
	SubURL  string       // subscription URL (carries the routing header)
	SubQR   template.URL // QR of SubURL
	// DeviceID/DeviceName name the device this credential is attached to
	// (ADR-0035). Both empty ⇒ unattached. VLESS has no personal portal link of
	// its own to retire, unlike AWG.
	DeviceID, DeviceName string
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
		data.RoutingLink = routingImportPrefix + buildRoutingObject(id, data.RouteThru)
		data.RoutingQR = h.qr(data.RoutingLink)
	}

	clients, err := h.renderer.ListVLESSClients(r.Context(), id)
	if err != nil {
		data.Notice = "listing clients failed: " + err.Error()
		h.render(w, h.clientsTmpl, "layout", data)
		return
	}
	devicesByCred := h.vlessCredentialDevices(r.Context(), id)
	for _, c := range clients {
		row := clientRow{Name: c.Name, UUID: c.UUID, ShortID: c.ShortID}
		if d, ok := devicesByCred[c.Name]; ok {
			row.DeviceID, row.DeviceName = d.ID, d.Name
		}
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

// vlessCredentialDevices maps a VLESS credential's name (its Ref, since
// client_vless_credentials has no ID of its own) on masterID to the device it is
// attached to, for the credential cards to link.
func (h *Handler) vlessCredentialDevices(ctx context.Context, masterID string) map[string]domain.ClientDevice {
	out := map[string]domain.ClientDevice{}
	if h.devices == nil {
		return out
	}
	devs, err := h.devices.ListDevices(ctx)
	if err != nil {
		return out
	}
	for _, d := range devs {
		if c, ok := d.Credential(domain.CredentialVLESS, masterID); ok {
			out[c.Ref] = d
		}
	}
	return out
}

// handleClientClash serves a ready-to-use Clash/mihomo (Clash Verge Rev) YAML
// config for one client. It bundles what a macOS tun client needs that a bare
// vless link cannot express: tun strict-route (so RFC1918 reaches the tunnel — the
// macOS default bypasses it), and DNS pointed at the master's blocky over the
// tunnel (so the operator's private-domain split resolves). Auth-gated (operator
// download from the UI).
func (h *Handler) handleClientClash(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := r.PathValue("name")
	node, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		httpError(w, "load node", err)
		return
	}
	spec, err := h.renderer.RenderNodeSpec(r.Context(), id)
	if err != nil || spec.Master == nil || spec.Master.ClientVLESS == nil {
		http.Error(w, "client VLESS not enabled on this master", http.StatusNotFound)
		return
	}
	cv := spec.Master.ClientVLESS
	host := endpointHost(node, spec)
	if host == "" || node.ClientVLESSPublicKey == "" {
		http.Error(w, "config not ready (no endpoint / published key yet)", http.StatusServiceUnavailable)
		return
	}
	clients, err := h.renderer.ListVLESSClients(r.Context(), id)
	if err != nil {
		httpError(w, "list clients", err)
		return
	}
	var found domain.VLESSClient
	for _, c := range clients {
		if c.Name == name {
			found = c
			break
		}
	}
	if found.UUID == "" {
		http.NotFound(w, r)
		return
	}
	yaml := buildClashConfig(host, *cv, node.ClientVLESSPublicKey, node.MgmtAddr, found)
	// Carries the client's private key; a credential, cached like any other file
	// without this.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "wgfleet-"+name+".yaml"))
	_, _ = w.Write([]byte(yaml))
}

// clashTemplate is the mihomo (Clash Verge Rev) client config: a vless+reality
// proxy, a tun with strict-route, DNS via the master's blocky over the tunnel,
// and MATCH → proxy (the master then routes geo/exits/internal).
const clashTemplate = `# wgfleet client — %s
mixed-port: 7890
mode: rule
log-level: info
ipv6: false
unified-delay: true

# strict-route forces even RFC1918 into the tunnel (the macOS default bypasses it).
tun:
  enable: true
  stack: gvisor
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack: [any:53]

dns:
  enable: true
  ipv6: false
%s
proxies:
  - name: wgfleet
    type: vless
    server: %q
    port: %d
    uuid: %q
    tls: true
    udp: true
    servername: %q
%s    reality-opts:
      public-key: %q
      short-id: "%s"
%s
rules:
  - MATCH,wgfleet
`

// buildClashConfig renders a mihomo (Clash Verge Rev) client config for one
// credential. blockyAddr empty ⇒ plain public DNS (no split).
func buildClashConfig(host string, cv domain.ClientVLESSServerSpec, pubkey, blockyAddr string, c domain.VLESSClient) string {
	e := cv.EndpointFor(host, pubkey, c)
	dns := "  nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n"
	if blockyAddr != "" {
		// redir-host + the master blocky dialed THROUGH the proxy: private-domain
		// split resolves, real IPs come back and route through the tunnel.
		//
		// TCP :53, not DoT (:853): the resolver is the pool's own gateway (blocky,
		// ADR-0024), and the master's client interface (wg0) only opens ClientDNSPort
		// (UDP+TCP :53, internal/netfw render.go) — :853 is admitted solely on the
		// veth namespace mihomo runs in (NetnsHostIface). A DoT dial over the AWG leg
		// would hit that :53-only allow and drop. The field capture that showed every
		// client DNS flow on :853 was against a bare IP in the handed-out config; this
		// is the one place that spells the scheme explicitly. Same function the mihomo
		// device profile uses (mihomo.ClientNameserver), so this download and every
		// per-device profile read one definition of "how a client names its resolver".
		dns = fmt.Sprintf("  enhanced-mode: redir-host\n  default-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n  nameserver:\n    - %q\n",
			mihomo.ClientNameserver(blockyAddr, "wgfleet"))
	}
	// One derivation (domain.ClientVLESSEndpoint) for this download, the vless://
	// link and the device profile: three hand-written copies of the same defaults
	// were three chances to disagree.
	var transport string
	if e.Vision {
		transport = "    network: tcp\n    flow: xtls-rprx-vision\n"
	} else {
		transport = fmt.Sprintf("    network: xhttp\n    xhttp-opts:\n      path: %q\n      mode: %s\n", e.XHTTPPath, e.XHTTPMode)
		// XMUX: reuse the underlying XHTTP connection across requests so the REALITY
		// handshake + dest-steal is amortized instead of paid per request — the
		// strongest mitigation for the handshake-parallelism volume-freeze. xhttp-only
		// (vision ignores it). The tuple is domain's, not a local copy: Task 4's device
		// profile reads the same three values.
		if e.Mux {
			transport += "      reuse-settings:\n" +
				fmt.Sprintf("        max-concurrency: %q\n", domain.ClientVLESSXMUXMaxConcurrency) +
				fmt.Sprintf("        h-max-request-times: %q\n", domain.ClientVLESSXMUXHMaxRequestTimes) +
				fmt.Sprintf("        h-max-reusable-secs: %q\n", domain.ClientVLESSXMUXHMaxReusableSecs)
		}
	}
	// client-fingerprint is the uTLS ClientHello fingerprint. "" omits it (operator
	// chose "none", the client's Go-default fingerprint).
	var fingerprint string
	if e.Fingerprint != "" {
		fingerprint = fmt.Sprintf("    client-fingerprint: %s\n", e.Fingerprint)
	}
	// Scalars are %q-quoted: host/uuid/servername/public-key are spec/store-derived and
	// could otherwise carry a character YAML reads specially (a leading digit, ':', '#',
	// a bare '*'/'&'), silently corrupting the emitted config. short-id was already
	// quoted.
	return fmt.Sprintf(clashTemplate,
		c.Name, dns, e.Host, e.Port, e.UUID, e.MihomoServerName(), fingerprint, e.PublicKey, e.ShortID, transport)
}

// handleSubscription serves a client's subscription: the vless link (base64 body,
// standard subscription format) plus the v2rayTun `routing` header carrying the
// route-through-tunnel rules. Auth-exempt — the client fetches it unauthenticated,
// identified by its UUID token (already its secret credential).
func (h *Handler) handleSubscription(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.subLimit != nil && !h.subLimit.Allowed(ip) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	master := r.PathValue("master")
	token := r.PathValue("token")
	clients, err := h.renderer.ListVLESSClients(r.Context(), master)
	if err != nil {
		http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
		return
	}
	// Constant-time match: the token is a secret credential (the client's UUID), so
	// compare against every candidate with subtle.ConstantTimeCompare and do NOT break
	// early — an early return leaks, via response timing, how far down the list a valid
	// prefix reached. The whole loop runs regardless of where (or whether) it matches.
	var found domain.VLESSClient
	for _, c := range clients {
		if subtle.ConstantTimeCompare([]byte(c.UUID), []byte(token)) == 1 {
			found = c
		}
	}
	if found.UUID == "" {
		if h.subLimit != nil {
			h.subLimit.Fail(ip)
		}
		http.NotFound(w, r)
		return
	}
	if h.subLimit != nil {
		h.subLimit.Reset(ip)
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
		w.Header().Set("routing", buildRoutingObject(master, cidrs))
	}
	// The body is the secret — a vless:// link with the UUID in it — and this route
	// is authExempt, which makes it the most exposed of the three and the one that
	// had no cache directive at all.
	w.Header().Set("Cache-Control", "no-store")
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

// routingObject / routingRule mirror the v2rayTun (Xray) routing schema, INCLUDING
// the id fields v2rayTun keys its rules by — without them the clipboard/header
// import is silently dropped (the docs require "exactly as you got from the
// application"). IP rules with outboundTag "proxy" send those CIDRs THROUGH the
// tunnel. The ids are derived from the master so re-renders are byte-stable (a
// re-import updates the same rule instead of duplicating it).
type routingObject struct {
	DomainStrategy string        `json:"domainStrategy"`
	ID             string        `json:"id"`
	Balancers      []any         `json:"balancers"`
	DomainMatcher  string        `json:"domainMatcher"`
	Rules          []routingRule `json:"rules"`
	Name           string        `json:"name"`
}

type routingRule struct {
	ID          string   `json:"id"`
	OutboundTag string   `json:"outboundTag"`
	Type        string   `json:"type"`
	Name        string   `json:"__name__"`
	IP          []string `json:"ip"`
}

// buildRoutingObject returns the base64-encoded v2rayTun routing object that routes
// cidrs through the tunnel (outboundTag "proxy"), for masterID.
func buildRoutingObject(masterID string, cidrs []string) string {
	obj := routingObject{
		DomainStrategy: "AsIs",
		ID:             routingUUID(masterID + "|wgfleet-routing"),
		Balancers:      []any{},
		DomainMatcher:  "hybrid",
		Rules: []routingRule{{
			ID:          routingUUID(masterID + "|wgfleet-routing-rule"),
			OutboundTag: "proxy",
			Type:        "field",
			Name:        "wgfleet internal via VPN",
			IP:          append([]string(nil), cidrs...),
		}},
		Name: "wgfleet internal via VPN",
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// routingUUID derives a stable upper-case UUID from a seed (v2rayTun keys routing
// rules by id; a stable id makes a re-import update rather than duplicate).
func routingUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]))
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
	// The same act as revoking an AmneziaWG credential, and for a long time the only
	// one of the pair without a server-side gate: the AWG side got the confirmation
	// page while this one kept a JavaScript-only prompt, i.e. one that vanishes
	// silently whenever the deferred script has not parsed yet. Two identical buttons
	// one page apart, one of them a floor and one of them not.
	if h.needsConfirmation(w, r, confirmView{
		Title:        "Revoke " + name,
		Heading:      "Revoke " + name + "?",
		Consequence:  "The credential and its UUID are deleted permanently and the person using it will need a new one — the old link and QR cannot be restored. Access stops on the master's NEXT reconcile pass, not the instant you confirm: for a credential you believe is compromised, watch the node go green again before you call it cut off.",
		Detail:       "A VLESS credential has no pause: revoking is the only way to cut it off, and the only way back is to issue a new one under a new UUID.",
		Action:       dest + "/" + name + "/revoke",
		ConfirmLabel: "Revoke " + name,
		CancelHref:   dest,
	}) {
		return
	}
	if err := h.renderer.RevokeVLESSClient(r.Context(), id, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.redirectErr(w, r, dest, "revoke client", errors.New("client not found"))
			return
		}
		h.redirectErr(w, r, dest, "revoke client", err)
		return
	}
	h.audit(r, "revoke VLESS client", "node", id, "client", name)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// buildVlessLink assembles the vless:// share link for one credential, matching
// the master's inbound (REALITY + xhttp/vision, empty-SNI, path/mode). host:port
// is the master's public endpoint; the fragment labels the profile in the client.
func buildVlessLink(host string, port int, cv domain.ClientVLESSServerSpec, pubkey, nodeName string, c domain.VLESSClient) string {
	e := cv.EndpointFor(host, pubkey, c)
	e.Port = port
	return e.Link(fmt.Sprintf("%s-%s", nodeName, c.Name))
}

// clientIP returns the source IP of the request for per-IP rate limiting. It uses
// the transport RemoteAddr only — NOT X-Forwarded-For / X-Real-IP, which a client
// can forge to evade the throttle (the endpoint rides the ZT overlay with no trusted
// proxy in front). Falls back to the raw RemoteAddr if it has no port.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// endpointHost resolves the public host clients dial the master at: the spec's
// public IP (manifest-then-store, resolved by the controller), falling back to
// whatever the store registered. Same order as clientcfg.EndpointHost, and for
// the same reason — the manifest is where the address is declared, the store row
// is a stale copy from first provisioning.
func endpointHost(node domain.Node, spec domain.NodeSpec) string {
	if spec.Master != nil && spec.Master.Compose.PublicIP != "" {
		return spec.Master.Compose.PublicIP
	}
	return node.PublicIP
}

// validClientName bounds the operator-supplied label so it is safe as a store key
// and vless:// fragment (no spaces/control chars, reasonable length).
//
// Note (#11, accepted): the charset permits "." including "." / ".." — harmless
// here because the name is a store key + display label only, never a path segment
// (issuance keys VLESS credentials by name in the DB, and no file is written per
// client). If this label ever becomes a filesystem path, reject "." and ".." then.
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
