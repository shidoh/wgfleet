// Package portal serves the client-facing self-service surface: one person, one
// credential, their own config and QR. Nothing else.
//
// It is deliberately a SEPARATE handler on a SEPARATE listener rather than a page
// inside the operator UI. wg-easy's admin UI could be opened to the client pool
// because it managed clients and nothing more; the controller's UI provisions,
// decommissions and drains nodes and exports an encrypted backup of the whole
// fleet. Exposing that to end users to replace a credential page would be a large
// and quiet escalation, so the portal has no route that can change fleet state,
// no listing of anyone else's credentials, and no session or admin concept at all.
package portal

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
)

// Handler serves the portal.
type Handler struct {
	src     clientcfg.Source
	masters func() []string // the masters whose credentials this portal serves
	mux     *http.ServeMux
	tmpl    *template.Template
	log     *slog.Logger
	// limit throttles token lookups per source IP. The token is a credential ID —
	// unguessable, but a portal reachable from the client pool is still a place
	// someone can grind, and a per-IP consecutive-failure lock costs a legitimate
	// user nothing.
	limit *auth.IPLimiter
}

// New builds the portal handler over a source of node/spec/credential state.
func New(src clientcfg.Source, masters func() []string) (*Handler, error) {
	tmpl, err := template.New("portal").Parse(portalHTML)
	if err != nil {
		return nil, fmt.Errorf("portal: parse template: %w", err)
	}
	h := &Handler{
		src:     src,
		masters: masters,
		mux:     http.NewServeMux(),
		tmpl:    tmpl,
		log:     slog.Default(),
		limit:   auth.NewIPLimiter(10, time.Minute, 4096),
	}
	h.mux.HandleFunc("GET /c/{token}", h.handlePage)
	h.mux.HandleFunc("GET /c/{token}/config", h.handleConfig)
	h.mux.HandleFunc("GET /c/{token}/qr", h.handleQR)
	// Anything else is a 404 with no hint about what does exist.
	h.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// pageData is the single page's view model. It carries no private key: the config
// itself is fetched from its own endpoint, so a page left open in a browser tab
// is not a copy of a credential.
type pageData struct {
	Name     string
	Address  string
	Endpoint string
	Enabled  bool
	Token    string
}

// resolve finds the credential a token refers to and renders its config.
func (h *Handler) resolve(r *http.Request) (clientcfg.Result, error) {
	ip := clientIP(r)
	if !h.limit.Allowed(ip) {
		return clientcfg.Result{}, errTooManyAttempts
	}
	token := r.PathValue("token")
	if !validToken(token) {
		h.limit.Fail(ip)
		return clientcfg.Result{}, store.ErrNotFound
	}
	master, err := clientcfg.FindByID(r.Context(), h.src, h.masters(), token)
	if err != nil {
		h.limit.Fail(ip)
		return clientcfg.Result{}, err
	}
	res, err := clientcfg.Build(r.Context(), h.src, master, token)
	if err != nil {
		return clientcfg.Result{}, err
	}
	h.limit.Reset(ip)
	return res, nil
}

var errTooManyAttempts = errors.New("too many attempts; try again in a minute")

func (h *Handler) handlePage(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolve(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	spec, _ := h.src.RenderNodeSpec(r.Context(), res.Master.ID)
	endpoint := ""
	if spec.Master != nil && spec.Master.ClientWG != nil {
		if host := clientcfg.EndpointHost(res.Master, spec); host != "" {
			endpoint = net.JoinHostPort(host, fmt.Sprint(spec.Master.ClientWG.ListenPort))
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The page names a credential; keep it out of any shared cache or referrer.
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := h.tmpl.Execute(w, pageData{
		Name:     res.Client.Name,
		Address:  res.Client.Address,
		Endpoint: endpoint,
		Enabled:  res.Client.Enabled,
		Token:    r.PathValue("token"),
	}); err != nil {
		h.log.Warn("portal: render failed", "err", err)
	}
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolve(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", clientcfg.ConfigFileName(res.Client)))
	_, _ = w.Write([]byte(res.Config))
}

func (h *Handler) handleQR(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolve(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	png, err := qrcode.Encode(res.Config, qrcode.Medium, 320)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// fail answers without telling the caller which part went wrong. A portal open to
// the client pool should not distinguish "no such credential" from "that one is
// on a master that is not ready" — both are 404 to anyone holding a bad link.
func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTooManyAttempts):
		http.Error(w, "too many attempts; try again in a minute", http.StatusTooManyRequests)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// validToken bounds what reaches the store lookup: credential IDs are hex.
func validToken(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '-':
		default:
			return false
		}
	}
	return true
}

// clientIP is the source address for rate limiting. The transport address only —
// never a forwarded-for header, which the caller controls and could use to make
// the limiter forget them.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// portalHTML is the whole portal: one page, two buttons, no navigation. Inline
// styles keep it a single self-contained response — the portal serves no static
// assets, so there is nothing else on this listener to reach for.
const portalHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Your VPN profile</title>
<style>
:root { color-scheme: dark; }
body { margin:0; min-height:100vh; display:grid; place-items:center;
  background:#11151c; color:#e6edf3; font:16px/1.5 system-ui, -apple-system, sans-serif; }
.card { width:min(420px, 92vw); background:#171d26; border:1px solid #232c39;
  border-radius:14px; padding:28px; }
h1 { margin:0 0 4px; font-size:20px; }
.sub { margin:0 0 20px; color:#8b98a9; font-size:14px; }
dl { margin:0 0 22px; display:grid; grid-template-columns:auto 1fr; gap:8px 16px; font-size:14px; }
dt { color:#8b98a9; } dd { margin:0; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
.actions { display:flex; gap:10px; flex-wrap:wrap; }
a.btn { flex:1; text-align:center; padding:11px 16px; border-radius:9px; text-decoration:none;
  border:1px solid #2b3646; color:#e6edf3; background:#1d2531; }
a.btn.primary { background:#2f6feb; border-color:#2f6feb; }
.muted { margin:18px 0 0; padding:12px 14px; border-radius:9px;
  background:#2a1f14; border:1px solid #4a3a24; color:#e8c48a; font-size:14px; }
</style></head>
<body><main class="card">
<h1>{{.Name}}</h1>
<p class="sub">Your VPN profile</p>
<dl>
  <dt>Address</dt><dd>{{.Address}}</dd>
  {{if .Endpoint}}<dt>Server</dt><dd>{{.Endpoint}}</dd>{{end}}
</dl>
{{if .Enabled}}
<div class="actions">
  <a class="btn primary" href="/c/{{.Token}}/qr">Show QR</a>
  <a class="btn" href="/c/{{.Token}}/config">Download</a>
</div>
{{else}}
<p class="muted">This profile is currently paused. Your configuration stays valid — ask your
administrator to resume it.</p>
{{end}}
</main></body></html>
`
