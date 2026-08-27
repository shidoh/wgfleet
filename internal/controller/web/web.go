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
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
	"github.com/shidoh/wgfleet/internal/domain"
)

// csrfCookie is the name of the double-submit cookie carrying the CSRF token.
const csrfCookie = "wgfleet_csrf"

// sessionCookie carries the HMAC-signed login session (see internal/.../auth).
const sessionCookie = "wgfleet_session"

// flashCookie carries a one-shot error message across an action's redirect, so a
// failed mutation lands back on its originating page (styled) instead of dumping a
// bare http.Error text page. It is read-and-cleared on the next render.
const flashCookie = "wgfleet_flash"

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// SpecRenderer previews a node's desired NodeSpec. *keybroker.Broker satisfies it.
type SpecRenderer interface {
	RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error)
	// ExitTransportInfo returns an exit's resolved active transport + enabled set
	// for the fleet list (cheap — no spec render). ok=false for non-exits.
	ExitTransportInfo(node domain.Node) (active domain.MasterTransport, enabled []domain.MasterTransport, ok bool)
	// IssueVLESSClient mints and persists a client-facing VLESS credential for a
	// master (client VLESS transport); ListVLESSClients / RevokeVLESSClient manage
	// the issued set. Credentials are non-secret (the REALITY key stays on-node).
	IssueVLESSClient(ctx context.Context, masterID, name string) (domain.VLESSClient, error)
	ListVLESSClients(ctx context.Context, masterID string) ([]domain.VLESSClient, error)
	RevokeVLESSClient(ctx context.Context, masterID, name string) error
	// ClientVLESSRouteThrough returns the CIDRs the master's clients should route
	// through the tunnel (for the routing object + subscription header).
	ClientVLESSRouteThrough(masterID string) []string
	// Client-facing WireGuard credentials (the leg wg-easy used to own). Unlike the
	// VLESS ones these carry a secret — the client's private key — because the
	// controller renders the .conf and its QR; treat what ListWGClients returns
	// accordingly.
	IssueWGClient(ctx context.Context, masterID, name string) (domain.WGClient, error)
	ListWGClients(ctx context.Context, masterID string) ([]domain.WGClient, error)
	SetWGClientEnabled(ctx context.Context, masterID, clientID string, enabled bool) error
	RenameWGClient(ctx context.Context, masterID, clientID, name string) error
	RevokeWGClient(ctx context.Context, masterID, clientID string) error
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
	store         store.Store
	renderer      SpecRenderer
	prov          Provisioner
	listTmpl      *template.Template // layout + nodes list (also holds "nodes-table")
	nodeTmpl      *template.Template // layout + node detail
	authTmpl      *template.Template // auth-layout (login / setup screens)
	profileTmpl   *template.Template // layout + admin profile / change-password
	clientsTmpl   *template.Template // layout + client-VLESS credential management (master)
	wgClientsTmpl *template.Template // layout + client-WireGuard credential management (master)
	mux           *http.ServeMux
	csrf          string       // per-process CSRF token, embedded in forms and double-submit cookie
	log           *slog.Logger // structured logger; surfaces render failures the page swallows
	// persistTransport durably records an active-transport switch in the manifest
	// (the platform's source of truth) so the change survives restart / re-provision.
	// nil ⇒ store-only (the live override still applies, but is not made durable).
	persistTransport func(exitName string, t domain.MasterTransport) error
	// exportBackup streams an age-encrypted controller backup for the given age
	// recipient. nil ⇒ the export endpoint reports 501 Not Implemented.
	exportBackup func(ctx context.Context, recipient string) ([]byte, error)
	sessionTTL   time.Duration
	loginLimit   *auth.Limiter
	// subLimit throttles the auth-exempt /sub/{master}/{token} fetch per source IP:
	// the token is a client's UUID, so a per-IP consecutive-fail lock blunts a
	// brute-force sweep without one bad caller locking out every legitimate client.
	subLimit *auth.IPLimiter
	// roller drives the fleet-wide rolling agent upgrade. nil ⇒ the fleet page
	// omits the action entirely.
	roller Roller
	// portalBase is the public base URL of the client self-service portal, used to
	// show the operator the link they hand to a person. Empty ⇒ no link is shown.
	portalBase string
}

// SetPortalBase wires the client portal's public URL. Optional and set after New
// for the same reason SetRoller is: it is deployment information, not something
// the handler needs to exist.
func (h *Handler) SetPortalBase(base string) { h.portalBase = strings.TrimRight(base, "/") }

// SetRoller wires the rolling-upgrade coordinator. Optional and set after New so
// the controller can build the coordinator over the same store this handler
// reads, without threading it through an already-wide constructor.
func (h *Handler) SetRoller(r Roller) { h.roller = r }

// New builds the dashboard handler. renderer and prov may be nil (the spec
// preview / provision action are then omitted). Each page is parsed as its own
// template set so the per-page "content" definitions do not collide.
func New(st store.Store, renderer SpecRenderer, prov Provisioner, persistTransport func(exitName string, t domain.MasterTransport) error, exportBackup func(ctx context.Context, recipient string) ([]byte, error), sessionTTL time.Duration) (*Handler, error) {
	listTmpl, err := parsePage("templates/layout.html", "templates/nodes.html", "templates/rollout.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse list templates: %w", err)
	}
	nodeTmpl, err := parsePage("templates/layout.html", "templates/node.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse node templates: %w", err)
	}
	authTmpl, err := parsePage("templates/auth.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse auth templates: %w", err)
	}
	profileTmpl, err := parsePage("templates/layout.html", "templates/profile.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse profile templates: %w", err)
	}
	clientsTmpl, err := parsePage("templates/layout.html", "templates/clients.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse clients templates: %w", err)
	}
	wgClientsTmpl, err := parsePage("templates/layout.html", "templates/wgclients.html", "templates/wgclients_panel.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse wg clients templates: %w", err)
	}
	token, err := newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("web: generate csrf token: %w", err)
	}
	h := &Handler{store: st, renderer: renderer, prov: prov, listTmpl: listTmpl, nodeTmpl: nodeTmpl, authTmpl: authTmpl, profileTmpl: profileTmpl, clientsTmpl: clientsTmpl, wgClientsTmpl: wgClientsTmpl, mux: http.NewServeMux(), csrf: token, log: slog.Default(), persistTransport: persistTransport, exportBackup: exportBackup, sessionTTL: sessionTTL, loginLimit: auth.NewLimiter(5, time.Minute), subLimit: auth.NewIPLimiter(10, time.Minute, 4096)}

	staticHandler := http.FileServer(http.FS(staticFS))
	h.mux.Handle("GET /static/", staticHandler)
	h.mux.HandleFunc("GET /login", h.handleLoginForm)
	h.mux.HandleFunc("POST /login", h.handleLogin)
	h.mux.HandleFunc("POST /logout", h.handleLogout)
	h.mux.HandleFunc("GET /setup", h.handleSetupForm)
	h.mux.HandleFunc("POST /setup", h.handleSetup)
	h.mux.HandleFunc("GET /{$}", h.handleIndex)
	h.mux.HandleFunc("GET /partials/nodes", h.handleNodesPartial)
	h.mux.HandleFunc("GET /partials/rollout", h.handleRolloutPartial)
	h.mux.HandleFunc("GET /nodes/{id}", h.handleNode)
	h.mux.HandleFunc("GET /nodes/{id}/status", h.handleNodeStatus)
	// Mutating actions. POST-only; guarded by the mgmt/ZT bind, a Sec-Fetch-Site
	// check, and a CSRF token (form field or X-CSRF-Token header) — see guard().
	h.mux.HandleFunc("POST /nodes/{id}/provision", h.handleProvision)
	h.mux.HandleFunc("POST /nodes/{id}/upgrade", h.handleUpgrade)
	h.mux.HandleFunc("POST /nodes/{id}/drain", h.handleDrain(true))
	h.mux.HandleFunc("POST /nodes/{id}/undrain", h.handleDrain(false))
	h.mux.HandleFunc("POST /nodes/{id}/decommission", h.handleDecommission)
	h.mux.HandleFunc("POST /nodes/{id}/recommission", h.handleRecommission)
	h.mux.HandleFunc("POST /nodes/{id}/transport/{transport}", h.handleTransport)
	// Client-facing VLESS credential management (master only).
	h.mux.HandleFunc("GET /nodes/{id}/clients", h.handleClients)
	h.mux.HandleFunc("POST /nodes/{id}/clients/issue", h.handleClientIssue)
	h.mux.HandleFunc("POST /nodes/{id}/clients/{name}/revoke", h.handleClientRevoke)
	h.mux.HandleFunc("GET /nodes/{id}/clients/{name}/clash", h.handleClientClash)
	// Client-facing WireGuard credential management (master only).
	h.mux.HandleFunc("GET /nodes/{id}/wg-clients", h.handleWGClients)
	h.mux.HandleFunc("GET /nodes/{id}/wg-clients/panel", h.handleWGClientsPanel)
	h.mux.HandleFunc("POST /nodes/{id}/wg-clients/issue", h.handleWGClientIssue)
	h.mux.HandleFunc("POST /nodes/{id}/wg-clients/{client}/revoke", h.handleWGClientRevoke)
	h.mux.HandleFunc("POST /nodes/{id}/wg-clients/{client}/mute", h.handleWGClientToggle(false))
	h.mux.HandleFunc("POST /nodes/{id}/wg-clients/{client}/unmute", h.handleWGClientToggle(true))
	h.mux.HandleFunc("POST /nodes/{id}/wg-clients/{client}/rename", h.handleWGClientRename)
	h.mux.HandleFunc("GET /nodes/{id}/wg-clients/{client}/config", h.handleWGClientConfig)
	h.mux.HandleFunc("GET /nodes/{id}/wg-clients/{client}/qr", h.handleWGClientQR)
	// Client subscription (auth-exempt; UUID-token in path). Serves the vless link
	// with the routing object in the `routing` response header.
	h.mux.HandleFunc("GET /sub/{master}/{token}", h.handleSubscription)
	h.mux.HandleFunc("POST /nodes/{id}/delete", h.handleDelete)
	h.mux.HandleFunc("POST /backup", h.handleBackupExport)
	h.mux.HandleFunc("POST /rollout/start", h.handleRolloutStart)
	h.mux.HandleFunc("POST /rollout/abort", h.handleRolloutAbort)
	h.mux.HandleFunc("GET /profile", h.handleProfile)
	h.mux.HandleFunc("POST /profile/password", h.handleChangePassword)
	return h, nil
}

type authPage struct {
	Title  string
	Screen string // "login" | "setup"
	CSRF   string
	Error  string
}

func (h *Handler) renderAuth(w http.ResponseWriter, screen, errMsg string) {
	h.setCSRFCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title := "Sign in"
	if screen == "setup" {
		title = "Create admin"
	}
	if err := h.authTmpl.ExecuteTemplate(w, "auth-layout", authPage{Title: title, Screen: screen, CSRF: h.csrf, Error: errMsg}); err != nil {
		h.log.Error("web: auth template render failed", "screen", screen, "error", err)
	}
}

func (h *Handler) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.renderAuth(w, "login", "")
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if !h.loginLimit.Allowed() {
		h.renderAuth(w, "login", "too many attempts — try again in a minute")
		return
	}
	rec, err := h.store.GetAuth(r.Context())
	user := r.FormValue("username")
	pass := r.FormValue("password")
	// Run the bcrypt compare even on a bad/missing record to avoid a timing oracle.
	hash := "$2a$12$0000000000000000000000000000000000000000000000000000z"
	if err == nil {
		hash = rec.PasswordHash
	}
	// Run the bcrypt compare and a constant-time username check unconditionally so
	// a wrong username and a wrong password are indistinguishable by timing (no
	// user enumeration). hash is the stored hash, or the dummy above when no row.
	userOK := err == nil && subtle.ConstantTimeCompare([]byte(user), []byte(rec.Username)) == 1
	passOK := auth.CheckPassword(hash, pass)
	if err != nil || !userOK || !passOK {
		h.loginLimit.Fail()
		h.renderAuth(w, "login", "invalid username or password")
		return
	}
	h.loginLimit.Reset()
	h.issueSession(w, rec.Username, rec.SessionSecret)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	h.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if ok, err := h.store.AuthConfigured(r.Context()); ok || err != nil {
		if err != nil {
			h.log.Error("web: setup: auth check", "error", err)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	h.renderAuth(w, "setup", "")
}

func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if ok, err := h.store.AuthConfigured(r.Context()); ok || err != nil {
		if err != nil {
			h.log.Error("web: setup: auth check", "error", err)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	if user == "" {
		h.renderAuth(w, "setup", "username is required")
		return
	}
	if len(pass) < auth.MinPasswordLen {
		h.renderAuth(w, "setup", fmt.Sprintf("password must be at least %d characters", auth.MinPasswordLen))
		return
	}
	if pass != r.FormValue("confirm") {
		h.renderAuth(w, "setup", "passwords do not match")
		return
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		h.renderAuth(w, "setup", "could not hash password")
		return
	}
	secret, err := auth.NewSecret()
	if err != nil {
		h.renderAuth(w, "setup", "could not initialize session secret")
		return
	}
	if err := h.store.SetAuthCredential(r.Context(), user, hash, secret); err != nil {
		h.log.Error("web: setup: save admin", "error", err)
		h.renderAuth(w, "setup", "could not save admin — check server logs")
		return
	}
	h.issueSession(w, user, secret)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type profileData struct {
	Title           string
	NodeCount       int
	User            string // logged-in admin (topbar)
	Username        string
	PasswordChanged time.Time
	Flash           string
	CSRF            string
}

func (h *Handler) handleProfile(w http.ResponseWriter, r *http.Request) {
	rec, err := h.store.GetAuth(r.Context())
	if err != nil {
		httpError(w, "load profile", err)
		return
	}
	user, _ := h.currentUser(r)
	h.render(w, h.profileTmpl, "layout", profileData{
		Title: "Profile", NodeCount: h.fleetCount(r.Context()), User: user, Username: rec.Username,
		PasswordChanged: rec.UpdatedAt, Flash: h.takeFlash(w, r), CSRF: h.csrf,
	})
}

// fleetCount is the number of nodes in the fleet (for the global topbar). It is
// best-effort — 0 on a store error.
func (h *Handler) fleetCount(ctx context.Context) int {
	ns, err := h.nodes(ctx)
	if err != nil {
		return 0
	}
	return len(ns)
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	rec, err := h.store.GetAuth(r.Context())
	if err != nil {
		h.redirectErr(w, r, "/profile", "load credential", err)
		return
	}
	if !auth.CheckPassword(rec.PasswordHash, r.FormValue("current")) {
		h.redirectErr(w, r, "/profile", "change password refused", fmt.Errorf("current password is incorrect"))
		return
	}
	pass := r.FormValue("password")
	if len(pass) < auth.MinPasswordLen {
		h.redirectErr(w, r, "/profile", "change password refused", fmt.Errorf("new password must be at least %d characters", auth.MinPasswordLen))
		return
	}
	if pass != r.FormValue("confirm") {
		h.redirectErr(w, r, "/profile", "change password refused", fmt.Errorf("passwords do not match"))
		return
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		h.redirectErr(w, r, "/profile", "hash password", err)
		return
	}
	secret, err := auth.NewSecret()
	if err != nil {
		h.redirectErr(w, r, "/profile", "rotate secret", err)
		return
	}
	if err := h.store.SetAuthPassword(r.Context(), hash, secret); err != nil {
		h.redirectErr(w, r, "/profile", "save password", err)
		return
	}
	// Re-issue THIS session under the new secret so the operator stays logged in.
	h.issueSession(w, rec.Username, secret)
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
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

// issueSession sets (or refreshes) the signed session cookie for user.
func (h *Handler) issueSession(w http.ResponseWriter, user string, secret []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    auth.Sign(secret, user, time.Now().Add(h.sessionTTL)),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSession expires the session cookie (logout).
func (h *Handler) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// currentUser returns the authenticated user from a valid session cookie.
func (h *Handler) currentUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	rec, err := h.store.GetAuth(r.Context())
	if err != nil {
		return "", false
	}
	return auth.Verify(rec.SessionSecret, c.Value)
}

// authExempt reports paths reachable without a session.
func authExempt(p string) bool {
	switch {
	case p == "/login", p == "/logout", p == "/setup":
		return true
	case strings.HasPrefix(p, "/static/"):
		return true
	case strings.HasPrefix(p, "/sub/"):
		// Client subscription endpoint: fetched unauthenticated by the VPN client,
		// gated instead by the per-client UUID token in the path (its own secret).
		return true
	default:
		return false
	}
}

// ServeHTTP gates every non-exempt route behind a valid session. With no admin
// configured yet it sends everything to first-run /setup; an unauthenticated
// request is redirected to /login (or, for an htmx request, answered 401 with
// HX-Redirect so the live polls navigate cleanly instead of swapping login into
// a card).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if authExempt(r.URL.Path) {
		h.mux.ServeHTTP(w, r)
		return
	}
	if ok, err := h.store.AuthConfigured(r.Context()); !ok {
		if err != nil {
			h.log.Error("web: auth check failed", "error", err)
		}
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, ok := h.currentUser(r); !ok {
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	h.mux.ServeHTTP(w, r)
}

type stateStat struct {
	Label string
	Class string
	Count int
}

type listData struct {
	Title     string
	NodeCount int
	User      string // logged-in admin (topbar)
	Nodes     []nodeRow
	Summary   []stateStat
	Topology  *topology    // master↔exit routing picture; nil when there is no master
	Flash     string       // one-shot error surfaced from a failed action redirect
	CSRF      string       // CSRF token for the backup-export form
	Rollout   *rolloutData // rolling agent upgrade panel; nil when not configured
}

// topology is the master↔exit routing picture shown on the fleet list — now the
// ONLY fleet view (the flat node table was folded into it): a master trunk with,
// indented beneath it, the exits it balances grouped into Carrying and Reserve
// rows joined by a CSS rail. Each row carries the full per-node inventory + live
// operational signals the table used to show and links to its detail page.
// Latency and the carrying flag come from the master's latest status report
// (ExitHealth, mihomo's view of the tunnels). nil only when the fleet is empty
// (the template then shows the empty state). Master is nil for a degenerate
// no-master fleet — the exits still render so no node is hidden.
type topology struct {
	Master *topoMaster // the load-balancer hub; nil when there is no master node

	// Carrying holds the exits currently carrying traffic, Reserve everything
	// else; both sorted by lowercased name. Drained/errored/decommissioning nodes
	// are by definition not carrying, so they land in Reserve — there is no third
	// group. The split is what makes the rendered bus's live segment fall out of
	// the grouping instead of needing measurement.
	Carrying []topoExit
	Reserve  []topoExit
}

// topoCard holds the inventory + status fields every node card shares (master and
// exit alike), carrying everything the old fleet-table row did so removing the
// table loses no information.
type topoCard struct {
	ID       string
	Name     string
	Region   string
	State    domain.NodeState
	MgmtAddr string
	PublicIP string
	// Live status signals (zero/false when no status has been reported yet).
	HasStatus     bool
	LastHandshake time.Time
	LastSeen      time.Time
	// Censorship / lifecycle sub-badges — same set + copy as the table's STATE cell.
	Drain         bool
	EgressBlocked bool
	LowThroughput bool
	Decommission  bool
	ActiveEgress  string // non-empty only when failed over to a non-preferred egress
}

// topoMaster is the master hub card.
type topoMaster struct {
	topoCard
	Balancing int // number of exits the master is balancing
}

// topoExit is one exit card in the topology diagram.
type topoExit struct {
	topoCard
	EgressIP      string
	Transport     domain.MasterTransport
	DualTransport bool   // exit runs more than one transport (switchable on the node page)
	Carrying      bool   // currently carrying traffic (every live member of the active tier)
	Latency       string // preformatted url-test delay ("107ms" / "1.088s"); "" if unknown
	Slow          bool   // latency above the slow threshold → render amber
}

// cardOf projects a fleet-list row into the inventory + status fields every
// topology card shares.
func cardOf(r nodeRow) topoCard {
	return topoCard{
		ID:            r.ID,
		Name:          r.Name,
		Region:        r.Region,
		State:         r.State,
		MgmtAddr:      hostOnly(r.MgmtAddr),
		PublicIP:      r.PublicIP,
		HasStatus:     r.HasStatus,
		LastHandshake: r.LastHandshake,
		LastSeen:      r.LastSeen,
		Drain:         r.Drain,
		EgressBlocked: r.EgressBlocked,
		LowThroughput: r.LowThroughput,
		Decommission:  r.Decommission,
		ActiveEgress:  r.ActiveEgress,
	}
}

// slowExitLatency is the master↔exit url-test delay at or above which an exit's
// latency reads as "slow" (amber) in the topology. Chosen well above a healthy
// cross-continent tunnel (~100–250ms) so only genuinely degraded paths flag.
const slowExitLatency = 600 * time.Millisecond

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
	user, _ := h.currentUser(r)
	data := listData{
		Title:     "Fleet",
		NodeCount: len(rows),
		User:      user,
		Nodes:     rows,
		Summary:   summarize(rows),
		Topology:  h.buildTopology(r.Context(), rows),
		Flash:     h.takeFlash(w, r),
		CSRF:      h.csrf,
		Rollout:   h.rolloutView(),
	}
	h.render(w, h.listTmpl, "layout", data)
}

// handleNodeStatus renders just the Status card body for the per-node detail
// page's htmx poll, so an operator triaging a node sees health checks and
// handshake age update live without reloading the page.
func (h *Handler) handleNodeStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		if mn, ok := h.manifestNode(id); ok {
			node = mn
		} else {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
	}
	data := nodeData{Node: node}
	if st, err := h.store.GetStatus(r.Context(), id); err == nil {
		data.HasStatus = true
		data.Status = st
	}
	if data.CanDelete && h.renderer != nil && node.Role == domain.RoleMaster {
		if clients, err := h.renderer.ListWGClients(r.Context(), id); err == nil {
			data.WGClientCount = len(clients)
		}
	}
	h.render(w, h.nodeTmpl, "node-status", data)
}

func (h *Handler) handleNodesPartial(w http.ResponseWriter, r *http.Request) {
	rows, err := h.nodeRows(r.Context())
	if err != nil {
		httpError(w, "list nodes", err)
		return
	}
	h.render(w, h.listTmpl, "nodes-table", listData{
		NodeCount: len(rows),
		Nodes:     rows,
		Summary:   summarize(rows),
		Topology:  h.buildTopology(r.Context(), rows),
	})
}

type nodeData struct {
	Title           string
	NodeCount       int
	User            string // logged-in admin (topbar)
	Node            domain.Node
	HasStatus       bool
	Status          domain.NodeStatus
	Spec            specView
	HasSpec         bool
	SpecErr         string
	CanProvision    bool
	CanUpgrade      bool // node is provisioned + upgradable over SSH
	CanDecommission bool // node is drained — safe to tear its data plane down
	CanDelete       bool // node has been decommissioned — safe to remove from inventory
	// WGClientCount is how many end-user credentials the delete would take with it.
	// The store cascades them (schema v11 ON DELETE CASCADE), so the confirm has to
	// say so: the only recovery is the age backup or re-issuing to every person by
	// hand, and "removes it permanently" reads as being about the node alone.
	WGClientCount int
	Flash         string // one-shot error surfaced from a failed action redirect
	WGEasyURL     string // master only: link to its wg-easy admin UI (mgmt overlay)
	MihomoURL     string // master only: link to its mihomo (Clash) web dashboard (mgmt overlay)
	MetricsURL    string // link to the node's agent Prometheus /metrics on the mgmt overlay
	WireSkew      string // non-empty (reason) when the agent's wire version is incompatible
	CSRF          string // CSRF token embedded in the action forms
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
	user, _ := h.currentUser(r)
	data := nodeData{Title: node.Name, NodeCount: h.fleetCount(r.Context()), User: user, Node: node, CSRF: h.csrf, CanDelete: node.Decommission, CanDecommission: node.Drain && !node.Decommission, Flash: h.takeFlash(w, r), MetricsURL: metricsURL(node)}
	if node.WireVersion != 0 {
		if compat := api.CheckWire(node.WireVersion); compat != api.WireCompatible {
			data.WireSkew = api.IncompatibilityDetail(compat, node.WireVersion)
		}
	}

	if st, err := h.store.GetStatus(r.Context(), id); err == nil {
		data.HasStatus = true
		data.Status = st
	}
	if data.CanDelete && h.renderer != nil && node.Role == domain.RoleMaster {
		if clients, err := h.renderer.ListWGClients(r.Context(), id); err == nil {
			data.WGClientCount = len(clients)
		}
	}
	// Render the desired spec once: for the preview text and, for a master, the
	// wg-easy admin UI link.
	if h.renderer == nil {
		data.SpecErr = "spec preview unavailable"
	} else if spec, err := h.renderer.RenderNodeSpec(r.Context(), id); err != nil {
		data.SpecErr = "cannot render spec: " + err.Error()
	} else {
		data.Spec, data.HasSpec = buildSpecView(spec), true
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

// buildTopology assembles the fleet-list routing diagram from the joined rows: the
// (first) master, the exits it balances, and each exit's live latency/carrying flag
// taken from the master's latest ExitHealth report. It returns nil only for an
// empty fleet (the template then shows the empty state). With no master it still
// returns the exits (Master nil) so removing the flat table hides no node; with a
// master but no exits it returns just the master. Read-only.
func (h *Handler) buildTopology(ctx context.Context, rows []nodeRow) *topology {
	if len(rows) == 0 {
		return nil
	}
	var masterRow *nodeRow
	var exits []nodeRow
	for i := range rows {
		switch rows[i].Role {
		case domain.RoleMaster:
			if masterRow == nil {
				masterRow = &rows[i]
			}
		case domain.RoleExit:
			exits = append(exits, rows[i])
		}
	}
	topo := &topology{}
	// The master's view of each tunnel (latency + which one carries traffic) is only
	// available from a master's status report.
	var health []domain.ExitTunnelHealth
	if masterRow != nil {
		if st, err := h.store.GetStatus(ctx, masterRow.ID); err == nil {
			health = st.ExitHealth
		}
		topo.Master = &topoMaster{topoCard: cardOf(*masterRow), Balancing: len(exits)}
	}
	for _, ex := range exits {
		te := topoExit{
			topoCard:      cardOf(ex),
			EgressIP:      ex.EgressIP,
			Transport:     ex.Transport,
			DualTransport: ex.DualTransport,
		}
		if d, carrying, ok := exitDelay(health, ex.Name); ok {
			te.Carrying = carrying
			te.Latency = formatDelay(d)
			te.Slow = d >= slowExitLatency
		}
		if te.Carrying {
			topo.Carrying = append(topo.Carrying, te)
			continue
		}
		topo.Reserve = append(topo.Reserve, te)
	}
	byName := func(s []topoExit) {
		sort.SliceStable(s, func(a, b int) bool {
			return strings.ToLower(s[a].Name) < strings.ToLower(s[b].Name)
		})
	}
	byName(topo.Carrying)
	byName(topo.Reserve)
	return topo
}

// exitDelay picks the most representative ExitHealth entry for an exit node from
// the master's report. Tunnel names are the exit name, optionally suffixed by the
// active transport (e.g. "exit-de-1" and "exit-de-1-reality"). It prefers the
// load-balancer-selected (carrying) entry, otherwise the matching entry with the
// largest measured delay (the active-transport proxy). ok=false when none match or
// no delay was measured.
//
// The prefix match means a dual-transport exit (ADR-0025) can have TWO health
// entries — "exit-de-1" (AWG) and "exit-de-1-reality". This function assumes at
// most one of them is ever Selected at a time: today the keybroker always
// renders the standby transport as Drained (internal/controller/keybroker/broker.go,
// the ExitTunnel literals for the AWG and reality tunnels both set
// Drained: baseDrained || <other transport active>), and ADR-0029's tiered
// consistent-hashing selection only marks a live, non-drained tier member as
// carrying — so a drained standby is never Selected. If a future change ever
// undrains both transports of the same exit at once, `carrying` here would
// still just OR the two together (harmless), but the `d`/`ok` "largest delay
// wins among Selected" tie-break would silently pick one arbitrarily instead of
// surfacing that the exit is dual-carrying — worth revisiting at that point.
func exitDelay(health []domain.ExitTunnelHealth, exitName string) (d time.Duration, carrying bool, ok bool) {
	for _, e := range health {
		if e.Name != exitName && !strings.HasPrefix(e.Name, exitName+"-") {
			continue
		}
		if e.Selected {
			carrying = true
		}
		if e.Delay > 0 && (!ok || e.Selected || e.Delay > d) {
			d = e.Delay
			ok = true
		}
	}
	return d, carrying, ok
}

// formatDelay renders a url-test delay the way the design shows it: "107ms" below
// a second, "1.088s" at or above. Empty for a non-positive delay.
func formatDelay(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.3fs", d.Seconds())
	}
}

// hostOnly strips a :port from a mgmt address for display ("10.20.3.10:8443" →
// "10.20.3.10"), leaving a bare host untouched.
func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
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
		// add1 renders a 1-based index for range positions (rollout step numbers).
		"add1": func(i int) int { return i + 1 },
		// transportLabel renders a human label for a master↔exit transport.
		"transportLabel": func(t domain.MasterTransport) string {
			switch t.OrDefault() {
			case domain.TransportRealityXHTTP:
				return "REALITY"
			case domain.TransportAWG:
				// "AWG", not "AmneziaWG": it sits in a 10.5px badge beside REALITY, and
				// the long form made the fleet's primary transport twice the width of
				// its fallback while saying the same thing.
				return "AWG"
			default:
				return string(t)
			}
		},
		// transportSlug renders a short CSS-class token for a master↔exit transport
		// ("reality" / "amnezia"), so templates can style the badge by variant.
		"transportSlug": func(t domain.MasterTransport) string {
			switch t.OrDefault() {
			case domain.TransportRealityXHTTP:
				return "reality"
			case domain.TransportAWG:
				return "amnezia"
			default:
				return strings.ToLower(string(t))
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
