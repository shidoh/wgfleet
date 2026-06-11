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
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// csrfCookie is the name of the double-submit cookie carrying the CSRF token.
const csrfCookie = "wgfleet_csrf"

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// SpecRenderer previews a node's desired NodeSpec. *keybroker.Broker satisfies it.
type SpecRenderer interface {
	RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error)
}

// Provisioner triggers asynchronous node provisioning. *provmgr.Manager satisfies
// it. May be nil (then the provision action is unavailable).
type Provisioner interface {
	Provisionable(nodeID string) bool
	TriggerAsync(nodeID string) error
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
	csrf     string // per-process CSRF token, embedded in forms and double-submit cookie
}

// New builds the dashboard handler. renderer and prov may be nil (the spec
// preview / provision action are then omitted). Each page is parsed as its own
// template set so the per-page "content" definitions do not collide.
func New(st store.Store, renderer SpecRenderer, prov Provisioner) (*Handler, error) {
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
	h := &Handler{store: st, renderer: renderer, prov: prov, listTmpl: listTmpl, nodeTmpl: nodeTmpl, mux: http.NewServeMux(), csrf: token}

	staticHandler := http.FileServer(http.FS(staticFS))
	h.mux.Handle("GET /static/", staticHandler)
	h.mux.HandleFunc("GET /{$}", h.handleIndex)
	h.mux.HandleFunc("GET /partials/nodes", h.handleNodesPartial)
	h.mux.HandleFunc("GET /nodes/{id}", h.handleNode)
	// Mutating actions. POST-only; guarded by the mgmt/ZT bind, a Sec-Fetch-Site
	// check, and a CSRF token (form field or X-CSRF-Token header) — see guard().
	h.mux.HandleFunc("POST /nodes/{id}/provision", h.handleProvision)
	h.mux.HandleFunc("POST /nodes/{id}/drain", h.handleDrain(true))
	h.mux.HandleFunc("POST /nodes/{id}/undrain", h.handleDrain(false))
	h.mux.HandleFunc("POST /nodes/{id}/decommission", h.handleDecommission)
	h.mux.HandleFunc("POST /nodes/{id}/delete", h.handleDelete)
	return h, nil
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
		http.Error(w, "provision: "+err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/nodes/"+id, http.StatusSeeOther)
}

// handleDecommission flags a node for teardown. The agent reverses its data
// plane on its next reconcile; the operator then deletes it.
func (h *Handler) handleDecommission(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := h.store.SetNodeDecommission(r.Context(), id, true); err != nil {
		http.Error(w, "set decommission: "+err.Error(), http.StatusNotFound)
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
			http.Error(w, "set drain: "+err.Error(), http.StatusNotFound)
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
		http.Error(w, "delete node: "+err.Error(), http.StatusNotFound)
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
	Nodes     []domain.Node
	Summary   []stateStat
}

// nodes returns the live store inventory merged with declared-but-unprovisioned
// manifest nodes (shown as Pending). Store rows win on conflict.
func (h *Handler) nodes(ctx context.Context) ([]domain.Node, error) {
	stored, err := h.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	if h.prov == nil {
		return stored, nil
	}
	seen := make(map[string]struct{}, len(stored))
	for _, n := range stored {
		seen[n.ID] = struct{}{}
	}
	merged := stored
	for _, mn := range h.prov.ManifestNodes() {
		if _, ok := seen[mn.ID]; !ok {
			merged = append(merged, mn)
		}
	}
	sortByName(merged)
	return merged, nil
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.nodes(r.Context())
	if err != nil {
		httpError(w, "list nodes", err)
		return
	}
	data := listData{
		Title:     "Fleet",
		NodeCount: len(nodes),
		Nodes:     nodes,
		Summary:   summarize(nodes),
	}
	h.render(w, h.listTmpl, "layout", data)
}

func (h *Handler) handleNodesPartial(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.nodes(r.Context())
	if err != nil {
		httpError(w, "list nodes", err)
		return
	}
	h.render(w, h.listTmpl, "nodes-table", listData{Nodes: nodes})
}

type nodeData struct {
	Title        string
	NodeCount    int
	Node         domain.Node
	HasStatus    bool
	Status       domain.NodeStatus
	SpecText     string
	SpecErr      string
	CanProvision bool
	CSRF         string // CSRF token embedded in the action forms
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
	}
	data := nodeData{Title: node.Name, NodeCount: 1, Node: node, CSRF: h.csrf}

	if st, err := h.store.GetStatus(r.Context(), id); err == nil {
		data.HasStatus = true
		data.Status = st
	}
	data.SpecText, data.SpecErr = h.specPreview(r.Context(), id)
	// Offer provisioning when the node can be bootstrapped and is not already
	// active (Provisioning/Reconciling/Ready) — i.e. Pending or Error.
	if h.prov != nil && h.prov.Provisionable(id) {
		switch node.State {
		case domain.StatePending, domain.StateError, "":
			data.CanProvision = true
		}
	}

	h.render(w, h.nodeTmpl, "layout", data)
}

// specPreview renders the node's desired NodeSpec as readable text, or an error
// string suitable for display.
func (h *Handler) specPreview(ctx context.Context, id string) (text, errMsg string) {
	if h.renderer == nil {
		return "", "spec preview unavailable"
	}
	spec, err := h.renderer.RenderNodeSpec(ctx, id)
	if err != nil {
		return "", "cannot render spec: " + err.Error()
	}
	return formatSpec(spec), ""
}

func (h *Handler) render(w http.ResponseWriter, tmpl *template.Template, name string, data any) {
	h.setCSRFCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		// Headers may already be sent; surface best-effort.
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

func summarize(nodes []domain.Node) []stateStat {
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
