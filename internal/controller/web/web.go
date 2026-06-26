// Package web serves the controller's read-only operations dashboard: the fleet
// node list, per-node detail (inventory + latest status + health checks), and a
// preview of each node's rendered desired NodeSpec. It is server-rendered with
// the standard library html/template + embed.FS, with htmx for live refresh —
// no JS build step and no extra Go dependency (see ADR-0002 note).
//
// The dashboard binds the mgmt/ZT address only (never the public interface) and
// is read-only; provision/drain actions are a later, carefully-gated addition.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// csrfCookie is the name of the double-submit cookie carrying the CSRF token.
const csrfCookie = "wgfleet_csrf"

// flashCookie carries a one-shot error message across an action's redirect, so a
// failed mutation lands back on its originating page (styled) instead of dumping a
// bare http.Error text page. It is read-and-cleared on the next render.
const flashCookie = "wgfleet_flash"

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// SpecRenderer previews a node's desired NodeSpec. *keybroker.Broker satisfies it.
type SpecRenderer interface {
	RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error)
	// ExitTransportInfo returns an exit's resolved active transport + enabled set
	// for the fleet list (cheap — no spec render). ok=false for non-exits.
	ExitTransportInfo(node domain.Node) (active domain.MasterTransport, enabled []domain.MasterTransport, ok bool)
}

// Provisioner triggers asynchronous node provisioning. *provmgr.Manager satisfies
// it. May be nil (then the provision action is unavailable).
type Provisioner interface {
	Provisionable(nodeID string) bool
	TriggerAsync(nodeID string) error
	// TriggerUpgrade rolls a node's agent binary forward (upload + restart) over
	// SSH in the background.
	TriggerUpgrade(nodeID string) error
	// ManifestNodes returns declared-but-not-yet-provisioned nodes as Pending
	// stubs, so the dashboard shows the full declared fleet.
	ManifestNodes() []domain.Node
}

// Handler is the dashboard HTTP handler.
type Handler struct {
	store    store.Store
	renderer SpecRenderer
	prov     Provisioner
	listTmpl *template.Template // layout + nodes list (also holds "nodes-table")
	nodeTmpl *template.Template // layout + node detail
	mux      *http.ServeMux
	csrf     string       // per-process CSRF token, embedded in forms and double-submit cookie
	log      *slog.Logger // structured logger; surfaces render failures the page swallows
	// persistTransport durably records an active-transport switch in the manifest
	// (the platform's source of truth) so the change survives restart / re-provision.
	// nil ⇒ store-only (the live override still applies, but is not made durable).
	persistTransport func(exitName string, t domain.MasterTransport) error
	// exportBackup streams an age-encrypted controller backup for the given age
	// recipient. nil ⇒ the export endpoint reports 501 Not Implemented.
	exportBackup func(ctx context.Context, recipient string) ([]byte, error)
}

// New builds the dashboard handler. renderer and prov may be nil (the spec
// preview / provision action are then omitted). Each page is parsed as its own
// template set so the per-page "content" definitions do not collide.
func New(st store.Store, renderer SpecRenderer, prov Provisioner, persistTransport func(exitName string, t domain.MasterTransport) error, exportBackup func(ctx context.Context, recipient string) ([]byte, error)) (*Handler, error) {
	listTmpl, err := parsePage("templates/layout.html", "templates/nodes.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse list templates: %w", err)
	}
	nodeTmpl, err := parsePage("templates/layout.html", "templates/node.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse node templates: %w", err)
	}
	token, err := newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("web: generate csrf token: %w", err)
	}
	h := &Handler{store: st, renderer: renderer, prov: prov, listTmpl: listTmpl, nodeTmpl: nodeTmpl, mux: http.NewServeMux(), csrf: token, log: slog.Default(), persistTransport: persistTransport, exportBackup: exportBackup}

	staticHandler := http.FileServer(http.FS(staticFS))
	h.mux.Handle("GET /static/", staticHandler)
	h.mux.HandleFunc("GET /{$}", h.handleIndex)
	h.mux.HandleFunc("GET /partials/nodes", h.handleNodesPartial)
	h.mux.HandleFunc("GET /nodes/{id}", h.handleNode)
	// Mutating actions. POST-only; guarded by the mgmt/ZT bind, a Sec-Fetch-Site
	// check, and a CSRF token (form field or X-CSRF-Token header) — see guard().
	h.mux.HandleFunc("POST /nodes/{id}/provision", h.handleProvision)
	h.mux.HandleFunc("POST /nodes/{id}/upgrade", h.handleUpgrade)
	h.mux.HandleFunc("POST /nodes/{id}/drain", h.handleDrain(true))
	h.mux.HandleFunc("POST /nodes/{id}/undrain", h.handleDrain(false))
	h.mux.HandleFunc("POST /nodes/{id}/decommission", h.handleDecommission)
	h.mux.HandleFunc("POST /nodes/{id}/recommission", h.handleRecommission)
	h.mux.HandleFunc("POST /nodes/{id}/transport/{transport}", h.handleTransport)
	h.mux.HandleFunc("POST /nodes/{id}/delete", h.handleDelete)
	h.mux.HandleFunc("POST /backup", h.handleBackupExport)
	return h, nil
}

// handleTransport switches an exit's active master↔exit transport (ADR-0025).
// It writes the change to the manifest first (the platform's source of truth, so
// the switch survives a controller restart and a node delete/re-provision), then
// records the live store override; the keybroker re-renders with the new active
// transport and the master hot-reloads mihomo (the standby proxy moves in/out of
// the wg-best group) — existing connections are undisturbed. Writing the manifest
// before the store means a manifest-write failure aborts cleanly with nothing
// changed, instead of leaving a live override the config does not reflect.
func (h *Handler) handleTransport(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	t := domain.MasterTransport(r.PathValue("transport"))
	if !t.Valid() {
		http.Error(w, "unknown transport "+string(t), http.StatusBadRequest)
		return
	}
	if h.persistTransport != nil {
		if err := h.persistTransport(id, t); err != nil {
			h.redirectErr(w, r, "/nodes/"+id, "persist transport to manifest", err)
			return
		}
	}
	if err := h.store.SetNodeActiveTransport(r.Context(), id, t); err != nil {
		h.redirectErr(w, r, "/nodes/"+id, "set transport", err)
		return
	}
	http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
}

// handleProvision kicks off asynchronous SSH bootstrap of a fleet node. The node
// goes Provisioning immediately; the agent takes over once installed.
func (h *Handler) handleProvision(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.prov == nil {
		http.Error(w, "provisioning is not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if err := h.prov.TriggerAsync(id); err != nil {
		h.redirectErr(w, r, "/nodes/"+id, "provision", err)
		return
	}
	http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
}

// handleUpgrade rolls a node's agent binary forward (upload + restart) over SSH
// in the background. The data plane survives an agent restart, so this is
// non-disruptive; the agent re-registers on the new version.
func (h *Handler) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.prov == nil {
		http.Error(w, "upgrade is not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if err := h.prov.TriggerUpgrade(id); err != nil {
		h.redirectErr(w, r, "/nodes/"+id, "upgrade", err)
		return
	}
	http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
}

// handleDecommission flags a node for teardown. The agent reverses its data
// plane on its next reconcile; the operator then deletes it. It is gated on the
// node being drained first — decommissioning a node still in the load balancer
// would tear down its data plane under live client traffic (a one-click outage).
func (h *Handler) handleDecommission(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	// Enforce drain→decommission order (not just advise it in the confirm copy).
	if n, err := h.store.GetNode(r.Context(), id); err == nil && !n.Drain {
		h.redirectErr(w, r, "/nodes/"+id, "decommission refused", fmt.Errorf("take the node out of routing first (Drain), then decommission"))
		return
	}
	if err := h.store.SetNodeDecommission(r.Context(), id, true); err != nil {
		h.redirectErr(w, r, "/nodes/"+id, "set decommission", err)
		return
	}
	http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
}

// handleRecommission clears a node's decommission flag — the in-UI reverse of an
// accidental Decommission. The agent stops tearing the node down and reconciles
// it back to its desired state on the next pass.
func (h *Handler) handleRecommission(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := h.store.SetNodeDecommission(r.Context(), id, false); err != nil {
		h.redirectErr(w, r, "/nodes/"+id, "cancel decommission", err)
		return
	}
	http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
}

// handleDrain sets/clears a node's drain flag, then redirects back to its detail
// page. The master agent picks the change up on its next reconcile.
func (h *Handler) handleDrain(drain bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.guard(w, r) {
			return
		}
		id := r.PathValue("id")
		if err := h.store.SetNodeDrain(r.Context(), id, drain); err != nil {
			h.redirectErr(w, r, "/nodes/"+id, "set drain", err)
			return
		}
		http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
	}
}

// handleDelete removes a node from inventory (after it has been drained and torn
// down) and redirects to the fleet list.
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := h.store.DeleteNode(r.Context(), id); err != nil {
		h.redirectErr(w, r, "/nodes/"+id, "delete node", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// guard authorizes a mutating request. It is layered defense for the
// unauthenticated admin surface (docs/DESIGN.md §10): a Sec-Fetch-Site check blocks
// browser-driven cross-origin posts, and a CSRF token (rendered into every form,
// also delivered as a double-submit cookie) is REQUIRED — so a request without
// the token, even one a lenient Sec-Fetch-Site would let through, is rejected.
// On failure it writes a 403 and returns false.
func (h *Handler) guard(w http.ResponseWriter, r *http.Request) bool {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request blocked", http.StatusForbidden)
		return false
	}
	if !h.checkCSRF(r) {
		http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// sameOrigin rejects browser cross-site POSTs using the Fetch metadata header.
// Browsers send Sec-Fetch-Site: same-origin for our own forms and cross-site for
// forged ones; an absent header (non-browser clients like curl) is allowed here
// because such clients carry no ambient credentials — the CSRF token in guard()
// is what actually authorizes them.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "same-site", "none":
		return true
	default:
		return false
	}
}

// checkCSRF reports whether the request carries the expected CSRF token, supplied
// either as the X-CSRF-Token header or a csrf_token form field. The comparison is
// constant-time.
func (h *Handler) checkCSRF(r *http.Request) bool {
	tok := r.Header.Get("X-CSRF-Token")
	if tok == "" {
		tok = r.FormValue("csrf_token")
	}
	return tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(h.csrf)) == 1
}

// setCSRFCookie publishes the token as a SameSite=Strict double-submit cookie so
// non-form clients (and a future htmx header hook) can echo it back. It is not
// HttpOnly-sensitive: the same value is already rendered into the page.
func (h *Handler) setCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    h.csrf,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
}

// redirectErr surfaces a failed action back on its originating page: it stashes a
// short-lived flash cookie with the message and 303-redirects there. The next
// render reads-and-clears the flash into the page's styled .error-note, so a
// failure no longer replaces the whole console with a bare http.Error text page.
func (h *Handler) redirectErr(w http.ResponseWriter, r *http.Request, dest, what string, err error) {
	msg := what
	if err != nil {
		msg = what + ": " + err.Error()
	}
	h.log.Warn("web action failed", "action", what, "path", r.URL.Path, "error", err)
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookie,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(msg)),
		Path:     "/",
		MaxAge:   30,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// takeFlash reads-and-clears the one-shot flash error cookie. It returns "" when
// no flash is set. Clearing is best-effort (a Set-Cookie with MaxAge<0).
func (h *Handler) takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(flashCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return ""
	}
	return string(raw)
}

// newCSRFToken returns a 32-byte random token, base64url-encoded.
func newCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func parsePage(files ...string) (*template.Template, error) {
	return template.New("layout").Funcs(funcMap()).ParseFS(templatesFS, files...)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

type stateStat struct {
	Label string
	Class string
	Count int
}

type listData struct {
	Title     string
	NodeCount int
	Nodes     []nodeRow
	Summary   []stateStat
	Flash     string // one-shot error surfaced from a failed action redirect
	CSRF      string // CSRF token for the backup-export form
}

// nodeRow is a fleet-list row: the inventory node plus a few derived operational
// signals from its latest status report, so the list shows where each node is at
// a glance (egress, freshness, censorship signals) without opening the detail page.
type nodeRow struct {
	domain.Node
	HasStatus     bool
	EgressIP      string
	LastHandshake time.Time
	ActiveEgress  string // set only when failed over to a non-preferred egress
	EgressBlocked bool
	LowThroughput bool
	// Transport (exits, ADR-0025): the resolved active master↔exit transport, and
	// whether the exit runs more than one (so the list can flag the switchable ones).
	Transport     domain.MasterTransport
	DualTransport bool
}

// nodeRows joins the inventory with each node's latest status for the fleet list.
func (h *Handler) nodeRows(ctx context.Context) ([]nodeRow, error) {
	ns, err := h.nodes(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]nodeRow, 0, len(ns))
	for _, n := range ns {
		row := nodeRow{Node: n}
		if st, err := h.store.GetStatus(ctx, n.ID); err == nil {
			row.HasStatus = true
			row.EgressIP = st.EgressIP
			row.LastHandshake = st.LastHandshake
			if e := st.ActiveEgress(); e != "" && e != "warp" {
				row.ActiveEgress = e
			}
			row.EgressBlocked = st.EgressBlocked()
			row.LowThroughput = st.EgressThroughputDegraded()
		}
		if h.renderer != nil && n.Role == domain.RoleExit {
			if active, enabled, ok := h.renderer.ExitTransportInfo(n); ok {
				row.Transport = active
				row.DualTransport = len(enabled) > 1
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// nodes returns the live store inventory merged with declared-but-unprovisioned
// manifest nodes (shown as Pending). Store rows win on conflict, except for
// inventory the agent may not report (mgmt addr, region, public IP): the manifest
// is authoritative there, so a blank store value is backfilled from it — otherwise
// a node that registered without a seeded inventory (auto-created, or its agent.yaml
// lacks mgmt_addr) shows "—" for fields the operator did configure.
func (h *Handler) nodes(ctx context.Context) ([]domain.Node, error) {
	stored, err := h.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	if h.prov == nil {
		return stored, nil
	}
	manifest := make(map[string]domain.Node)
	for _, mn := range h.prov.ManifestNodes() {
		manifest[mn.ID] = mn
	}
	seen := make(map[string]struct{}, len(stored))
	merged := make([]domain.Node, 0, len(stored))
	for _, n := range stored {
		if mn, ok := manifest[n.ID]; ok {
			n = backfillFromManifest(n, mn)
		}
		seen[n.ID] = struct{}{}
		merged = append(merged, n)
	}
	for _, mn := range h.prov.ManifestNodes() {
		if _, ok := seen[mn.ID]; !ok {
			merged = append(merged, mn)
		}
	}
	sortByName(merged)
	return merged, nil
}

// backfillFromManifest fills inventory fields the agent does not report (and that
// the manifest owns) when the store row left them blank. Display-only — it never
// changes the persisted node.
func backfillFromManifest(n, mn domain.Node) domain.Node {
	if n.MgmtAddr == "" {
		n.MgmtAddr = mn.MgmtAddr
	}
	if n.Region == "" {
		n.Region = mn.Region
	}
	if n.PublicIP == "" {
		n.PublicIP = mn.PublicIP
	}
	return n
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	rows, err := h.nodeRows(r.Context())
	if err != nil {
		httpError(w, "list nodes", err)
		return
	}
	data := listData{
		Title:     "Fleet",
		NodeCount: len(rows),
		Nodes:     rows,
		Summary:   summarize(rows),
		Flash:     h.takeFlash(w, r),
		CSRF:      h.csrf,
	}
	h.render(w, h.listTmpl, "layout", data)
}

func (h *Handler) handleNodesPartial(w http.ResponseWriter, r *http.Request) {
	rows, err := h.nodeRows(r.Context())
	if err != nil {
		httpError(w, "list nodes", err)
		return
	}
	h.render(w, h.listTmpl, "nodes-table", listData{Nodes: rows})
}

type nodeData struct {
	Title           string
	NodeCount       int
	Node            domain.Node
	HasStatus       bool
	Status          domain.NodeStatus
	SpecText        string
	SpecErr         string
	CanProvision    bool
	CanUpgrade      bool   // node is provisioned + upgradable over SSH
	CanDecommission bool   // node is drained — safe to tear its data plane down
	CanDelete       bool   // node has been decommissioned — safe to remove from inventory
	Flash           string // one-shot error surfaced from a failed action redirect
	WGEasyURL       string // master only: link to its wg-easy admin UI (mgmt overlay)
	MihomoURL       string // master only: link to its mihomo (Clash) web dashboard (mgmt overlay)
	MetricsURL      string // link to the node's agent Prometheus /metrics on the mgmt overlay
	WireSkew        string // non-empty (reason) when the agent's wire version is incompatible
	CSRF            string // CSRF token embedded in the action forms
	// Transport switch (ADR-0025): populated from the rendered spec. A dual-transport
	// exit (len(Transports) > 1) renders a switch; ActiveTransport is highlighted.
	Transports      []domain.MasterTransport
	ActiveTransport domain.MasterTransport
	RealityInfo     *domain.RealityServerSpec
}

func (h *Handler) handleNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		// Not in the store yet — show it from the manifest (Pending) so it can be
		// provisioned. Only nodes the manifest knows are shown.
		if mn, ok := h.manifestNode(id); ok {
			node = mn
		} else {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
	} else if mn, ok := h.manifestNode(id); ok {
		// Backfill manifest-owned inventory (mgmt/region/public IP) the agent may not
		// report, so the detail page matches the list (see nodes()).
		node = backfillFromManifest(node, mn)
	}
	data := nodeData{Title: node.Name, NodeCount: 1, Node: node, CSRF: h.csrf, CanDelete: node.Decommission, CanDecommission: node.Drain && !node.Decommission, Flash: h.takeFlash(w, r), MetricsURL: metricsURL(node)}
	if node.WireVersion != 0 {
		if compat := api.CheckWire(node.WireVersion); compat != api.WireCompatible {
			data.WireSkew = api.IncompatibilityDetail(compat, node.WireVersion)
		}
	}

	if st, err := h.store.GetStatus(r.Context(), id); err == nil {
		data.HasStatus = true
		data.Status = st
	}
	// Render the desired spec once: for the preview text and, for a master, the
	// wg-easy admin UI link.
	if h.renderer == nil {
		data.SpecErr = "spec preview unavailable"
	} else if spec, err := h.renderer.RenderNodeSpec(r.Context(), id); err != nil {
		data.SpecErr = "cannot render spec: " + err.Error()
	} else {
		data.SpecText = formatSpec(spec)
		data.WGEasyURL = wgEasyURL(node, spec)
		data.MihomoURL = mihomoURL(node, spec)
		if spec.Role == domain.RoleExit {
			data.Transports = spec.Transports()
			data.ActiveTransport = spec.ActiveTransport.OrDefault()
			data.RealityInfo = spec.Reality
		}
	}
	// Offer provisioning when the node can be bootstrapped and is not already
	// active (Provisioning/Reconciling/Ready) — i.e. Pending or Error.
	if h.prov != nil && h.prov.Provisionable(id) {
		switch node.State {
		case domain.StatePending, domain.StateError, "":
			data.CanProvision = true
		default:
			// An already-provisioned node (Reconciling/Ready/Degraded) can have its
			// agent binary rolled forward in place.
			data.CanUpgrade = true
		}
	}

	h.render(w, h.nodeTmpl, "layout", data)
}

// wgEasyURL builds the master's wg-easy admin UI URL on the mgmt/ZT overlay, or
// "" for non-masters or when the mgmt address is unknown. The port follows the
// rendered compose spec (operator override) or the default.
func wgEasyURL(node domain.Node, spec domain.NodeSpec) string {
	if node.Role != domain.RoleMaster || node.MgmtAddr == "" {
		return ""
	}
	host := node.MgmtAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	port := compose.DefaultWGEasyWebPort
	if spec.Master != nil && spec.Master.Compose.WGEasyWebPort != 0 {
		port = spec.Master.Compose.WGEasyWebPort
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// metricsURL builds the node's agent Prometheus /metrics URL on the mgmt/ZT
// overlay, or "" when the mgmt address is unknown. Every node (master and exit)
// runs the agent, which binds /metrics on <mgmt_addr>:9301 by default.
func metricsURL(node domain.Node) string {
	if node.MgmtAddr == "" {
		return ""
	}
	host := node.MgmtAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return fmt.Sprintf("http://%s:%d/metrics", host, config.DefaultAgentMetricsPort)
}

// mihomoURL builds the master's mihomo (Clash) web dashboard URL on the mgmt/ZT
// overlay, or "" for non-masters, when the API is not exposed, or when the
// dashboard is disabled. The dashboard is served at <external-controller>/ui; the
// port comes from the external-controller listener, the host from MgmtAddr (so a
// 0.0.0.0 bind still yields a reachable link).
func mihomoURL(node domain.Node, spec domain.NodeSpec) string {
	if node.Role != domain.RoleMaster || node.MgmtAddr == "" || spec.Master == nil {
		return ""
	}
	if spec.Master.ExternalController == "" || spec.Master.DashboardDisabled {
		return ""
	}
	host := node.MgmtAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	_, port, err := net.SplitHostPort(spec.Master.ExternalController)
	if err != nil || port == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:%s/ui", host, port)
}

func (h *Handler) render(w http.ResponseWriter, tmpl *template.Template, name string, data any) {
	h.setCSRFCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		// Headers may already be sent; surface best-effort in-page AND log it, so a
		// render failure is not silently swallowed into an HTML comment nobody sees.
		h.log.Error("web: template render failed", "template", name, "error", err)
		_, _ = fmt.Fprintf(w, "\n<!-- template error: %v -->", err)
	}
}

// manifestNode returns a Pending stub for a node declared in the fleet manifest
// but not yet in the store.
func (h *Handler) manifestNode(id string) (domain.Node, bool) {
	if h.prov == nil {
		return domain.Node{}, false
	}
	for _, n := range h.prov.ManifestNodes() {
		if n.ID == id {
			return n, true
		}
	}
	return domain.Node{}, false
}

func sortByName(nodes []domain.Node) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
}

func summarize(nodes []nodeRow) []stateStat {
	counts := map[domain.NodeState]int{}
	for _, n := range nodes {
		counts[n.State]++
	}
	order := []struct {
		state domain.NodeState
		label string
		class string
	}{
		{domain.StateReady, "Ready", "ready"},
		{domain.StateReconciling, "Reconciling", "reconciling"},
		{domain.StateProvisioning, "Provisioning", "provisioning"},
		{domain.StatePending, "Pending", "pending"},
		{domain.StateDegraded, "Degraded", "degraded"},
		{domain.StateError, "Error", "error"},
	}
	var out []stateStat
	for _, o := range order {
		out = append(out, stateStat{Label: o.label, Class: o.class, Count: counts[o.state]})
	}
	return out
}

func funcMap() template.FuncMap {
	return template.FuncMap{
		// lower accepts any stringish value (string, domain.Role, domain.NodeState).
		"lower":   func(v any) string { return strings.ToLower(fmt.Sprint(v)) },
		"relTime": relTime,
		// transportLabel renders a human label for a master↔exit transport.
		"transportLabel": func(t domain.MasterTransport) string {
			switch t.OrDefault() {
			case domain.TransportRealityXHTTP:
				return "REALITY"
			case domain.TransportAWG:
				return "AmneziaWG"
			default:
				return string(t)
			}
		},
		"absTime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
	}
}

// relTime renders a coarse relative time ("12s ago", "never"). It takes the
// clock via time.Since; for deterministic tests, formatSince is used directly.
func relTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return formatSince(time.Since(t))
}

func formatSince(d time.Duration) string {
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func httpError(w http.ResponseWriter, what string, err error) {
	http.Error(w, fmt.Sprintf("%s: %v", what, err), http.StatusInternalServerError)
}
