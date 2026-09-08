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
	"slices"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Handler serves the portal.
type Handler struct {
	src      clientcfg.Source
	masters  func() []string // the masters whose credentials this portal serves
	mux      *http.ServeMux
	tmpl     *template.Template
	failTmpl *template.Template
	log      *slog.Logger
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
	failTmpl, err := template.New("portal-fail").Parse(failHTML)
	if err != nil {
		return nil, fmt.Errorf("portal: parse failure template: %w", err)
	}
	h := &Handler{
		src:      src,
		masters:  masters,
		mux:      http.NewServeMux(),
		tmpl:     tmpl,
		failTmpl: failTmpl,
		log:      slog.Default(),
		limit:    auth.NewIPLimiter(10, time.Minute, 4096),
	}
	h.mux.HandleFunc("GET /c/{token}", h.handlePage)
	h.mux.HandleFunc("GET /c/{token}/config", h.handleConfig)
	h.mux.HandleFunc("GET /c/{token}/qr", h.handleQR)
	// The reserve doors, under the same token. They are handed out from the same
	// page as the main profile — the day the master stops answering is the day
	// nobody can be told a new URL.
	h.mux.HandleFunc("GET /c/{token}/l/{exit}/config", h.handleLifelineConfig)
	h.mux.HandleFunc("GET /c/{token}/l/{exit}/qr", h.handleLifelineQR)
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
	// Reserves are the exits this credential can also be dialled through, and only
	// the ones that can hand out a config right now. The console lists the others
	// with the reason they cannot — the operator is who can act on that — but a
	// person reading this page can do nothing with "the exit has not published its
	// key yet" except distrust the ones that do work.
	Reserves []reserveView
}

// reserveView is one reserve door as the page shows it. ID and Name are both
// carried because they are two different things: the ID is what the URL names and
// what validExit bounds, the Name is what the operator called the node and the
// only one of the two a person has any chance of recognising when they are told
// over the phone which reserve to switch to. They coincide until a node is
// registered under a name of its own, which is exactly when showing the wrong one
// would matter.
type reserveView struct {
	ID       string
	Name     string
	Endpoint string
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
		// Only a token that does not exist counts against the caller. A store
		// failure is ours, and charging it to them means a hiccup tells every
		// legitimate user their profile was revoked — and locks out the ones who
		// respond by reloading.
		if errors.Is(err, store.ErrNotFound) {
			h.limit.Fail(ip)
		}
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
	// A paused profile is offered nothing to download, reserve doors included — the
	// two routes behind them refuse it too — so the listing is not even attempted:
	// it is a walk over every exit's spec for a section that cannot be rendered.
	var reserves []reserveView
	if res.Client.Enabled {
		reserves = h.reserves(r, res.Master.ID)
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
		Reserves: reserves,
	}); err != nil {
		h.log.Warn("portal: render failed", "err", err)
	}
}

// reserves lists the reserve doors this page offers. A listing that fails costs
// the page nothing: the main profile is what the person came for and is still
// valid, and a page that 503s because one exit's spec would not render would take
// away the working config to report a fault only the operator can fix.
func (h *Handler) reserves(r *http.Request, masterID string) []reserveView {
	exits, err := clientcfg.ListLifelineExits(r.Context(), h.src, masterID)
	if err != nil {
		h.log.Warn("portal: could not list the reserve exits", "err", err)
		return nil
	}
	out := make([]reserveView, 0, len(exits))
	for _, e := range exits {
		if !e.Ready {
			continue
		}
		out = append(out, reserveView{ID: e.ID, Name: e.Name, Endpoint: e.Endpoint})
	}
	return out
}

var errPaused = errors.New("this profile is paused")

// errNoReserve is a door the fleet HAS but cannot open yet: the exit is in the
// manifest, its key or its endpoint is not there. It wraps store.ErrNotFound so
// the caller meets the same page an exit name we have never heard of gets —
// otherwise the two answers differ and the portal becomes an oracle for which
// exits exist. It is deliberately never charged to the rate limiter: the
// condition is ours, and a person who bookmarked a reserve link would lock
// themselves out of their own working profile by reloading it.
var errNoReserve = fmt.Errorf("this exit has no reserve config yet: %w", store.ErrNotFound)

// resolveLifeline is resolve for a RESERVE config: the same token, the same
// limiter, plus the exit named in the path.
func (h *Handler) resolveLifeline(r *http.Request) (clientcfg.Result, error) {
	ip := clientIP(r)
	if !h.limit.Allowed(ip) {
		return clientcfg.Result{}, errTooManyAttempts
	}
	token, exit := r.PathValue("token"), r.PathValue("exit")
	// Both are caller-supplied strings and both are bounded before anything they
	// name is looked up. A malformed exit is charged exactly like a malformed
	// token, or the reserve route would be the cheaper of the two to grind.
	if !validToken(token) || !validExit(exit) {
		h.limit.Fail(ip)
		return clientcfg.Result{}, store.ErrNotFound
	}
	master, err := clientcfg.FindByID(r.Context(), h.src, h.masters(), token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.limit.Fail(ip)
		}
		return clientcfg.Result{}, err
	}
	// Readiness is resolved BEFORE the build so the two cases the build folds into
	// one error can be told apart here: an exit the fleet does not have is the
	// caller's doing and is charged, an exit that is not ready is ours and is not.
	exits, err := clientcfg.ListLifelineExits(r.Context(), h.src, master)
	if err != nil {
		return clientcfg.Result{}, err
	}
	i := slices.IndexFunc(exits, func(e clientcfg.LifelineExit) bool { return e.ID == exit })
	if i < 0 {
		h.limit.Fail(ip)
		return clientcfg.Result{}, store.ErrNotFound
	}
	if !exits[i].Ready {
		return clientcfg.Result{}, errNoReserve
	}
	res, err := clientcfg.BuildLifeline(r.Context(), h.src, master, token, exit)
	if err != nil {
		return clientcfg.Result{}, err
	}
	h.limit.Reset(ip)
	return res, nil
}

// handleLifelineConfig serves one reserve .conf. It gates on Enabled exactly as
// the primary does — the console does not, because there the operator is handing
// a file to a person for later, while here the URL is one somebody kept and
// reloads, which is how a peer the server has already dropped gets re-imported.
func (h *Handler) handleLifelineConfig(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolveLifeline(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !res.Client.Enabled {
		h.fail(w, errPaused)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Named after the exit: a person holds one of these per door, and two files
	// called laptop.conf in a Downloads folder is how the wrong one is imported on
	// the day it matters.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", clientcfg.LifelineFileName(res.Client, r.PathValue("exit"))))
	_, _ = w.Write([]byte(res.Config))
}

func (h *Handler) handleLifelineQR(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolveLifeline(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !res.Client.Enabled {
		h.fail(w, errPaused)
		return
	}
	png, err := qrcode.Encode(res.Config, qrcode.Medium, 1024)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// handleConfig serves the .conf file the page links to.
func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolve(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !res.Client.Enabled {
		h.fail(w, errPaused)
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
	if !res.Client.Enabled {
		h.fail(w, errPaused)
		return
	}
	// Big enough that a phone camera can resolve the modules. Measured on a real
	// config (867 bytes): 117x117 modules, so 320px put 2.7 pixels on each one.
	// This is the surface actual people scan, so it matters more here than in the
	// operator UI.
	png, err := qrcode.Encode(res.Config, qrcode.Medium, 1024)
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
// on a master that is not ready" — both look identical to anyone holding a bad
// link. What it CAN do is say it in a sentence: the most likely reader is not an
// attacker probing tokens but a person whose VPN just stopped working and who
// reopened the only link they have.
func (h *Handler) fail(w http.ResponseWriter, err error) {
	status, heading, body := http.StatusNotFound,
		"This link is no longer working",
		"Your profile may have been replaced or switched off. Your VPN app keeps using the profile it "+
			"already has, so nothing on your device needs deleting — ask whoever sent you this link for a new one."
	switch {
	case errors.Is(err, errPaused):
		// The page already hides the buttons and says the profile is paused, but the
		// two URLs behind them ignored Enabled entirely — so anyone who had the link
		// in their history, or simply reloaded, downloaded a full config with a live
		// private key for a peer the server has removed. The page and the file have
		// to agree, and the person needs to know it is a pause, not a loss: this is
		// the one failure here that someone can actually do something about.
		status, heading, body = http.StatusForbidden,
			"This profile is paused",
			"It has been switched off for now and will not connect. Nothing is wrong with your device and "+
				"nothing needs deleting — ask whoever sent you this link to switch it back on."
	case errors.Is(err, errTooManyAttempts):
		status, heading, body = http.StatusTooManyRequests,
			"Too many tries",
			"Wait a minute, then open the link again."
	case !errors.Is(err, store.ErrNotFound):
		// A server-side failure. The old page folded this into the message above,
		// which opened by telling the person to wait and then explained that their
		// profile was probably revoked — advice for the wrong problem, and the one
		// case where waiting IS the right answer got it as a hedge.
		status, heading, body = http.StatusServiceUnavailable,
			"Something is wrong on our side",
			"This is not a problem with your profile — it is still valid and your VPN app is unaffected. "+
				"Try the link again in a few minutes."
		h.log.Error("portal: could not resolve a credential", "err", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := h.failTmpl.Execute(w, struct{ Heading, Body string }{heading, body}); err != nil {
		h.log.Warn("portal: render failed", "err", err)
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

// validExit bounds what reaches the store for a RESERVE config. It runs before
// the lookup for the same reason validToken does — the path segment is a
// stranger's string until it is checked — and it defers to
// domain.ValidLifelineExitName so this bound and the manifest's are the SAME
// rule. They were not, once: this accepted lowercase only while the manifest
// asked for nothing but a non-empty name, so an exit named "EU-1" was listed on
// the page with a download and a QR that both 404'd and both charged the
// limiter, locking the reader out of their own working profile.
func validExit(s string) bool { return domain.ValidLifelineExitName(s) }

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
// portalCSS is shared by BOTH portal pages. They used to carry their own copies
// and had already drifted — the heading's bottom margin and the body font size
// differed between a page and its own error state, which are meant to be the same
// card.
const portalCSS = `
:root { color-scheme: dark; }
/* align-items:start, not place-items:center. A card taller than the viewport —
   a long name plus the paused notice, or a phone held sideways — clips at the TOP
   when centred, and the part that goes off-screen is the part that says what to
   do. The console's own auth screen rejected centring for the same reason. */
body { margin:0; min-height:100vh; display:grid; justify-items:center; align-items:start;
  padding:32px 16px 48px; box-sizing:border-box;
  background:#11151c; color:#e6edf3; font:16px/1.5 system-ui, -apple-system, sans-serif; }
.card { width:min(420px, 92vw); background:#171d26; border:1px solid #232c39;
  border-radius:14px; padding:28px; }
h1 { margin:0 0 4px; font-size:20px; }
.sub { margin:0 0 20px; color:#8b98a9; font-size:15px; }
/* .lead is the failure page's body, and it is not a subtitle. It was .sub — the
   class built for the one-line name under a heading — so the whole explanation a
   person reads when their VPN has just stopped rendered in the weakest grey on the
   page, at the size meant for a caption. It is the only text there; it gets the
   page's own colour. */
.lead { margin:0; color:#e6edf3; font-size:16px; }
p { font-size:15px; }
dl { margin:12px 0 0; display:grid; grid-template-columns:auto 1fr; gap:8px 16px; font-size:15px; }
ol.steps { margin:0 0 22px; padding-left:20px; font-size:15px; }
ol.steps li { margin-bottom:8px; }
details { margin-top:18px; font-size:15px; color:#8b98a9; }
summary { cursor:pointer; padding:10px 0; }
dt { color:#8b98a9; } dd { margin:0; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
.actions { display:flex; gap:10px; flex-wrap:wrap; }
/* The primary action takes the full width so it stays visually dominant on a
   narrow phone, where flex:1 would otherwise make both buttons equal. */
a.btn { flex:1 1 140px; text-align:center; padding:14px 16px; border-radius:9px; text-decoration:none;
  border:1px solid #2b3646; color:#e6edf3; background:#1d2531; }
/* Two axes, and the first version measured only one. #2559c4 rather than #2f6feb
   because the brighter blue put the LABEL at 3.87:1, below AA — but the fill it was
   darkened to sits at 2.66:1 against the card, and border-color was set to the same
   value, so the only call-to-action on the product's public surface had no boundary
   at all: on a phone in daylight, a faintly bluer rectangle. The label keeps its
   5.38:1; the border now carries the 3:1 that WCAG asks of a component edge. */
a.btn.primary { background:#2559c4; border-color:#6f9bf0; flex:1 1 100%; }
a.btn:active { transform:scale(.98); filter:brightness(1.15); }
a.btn:focus-visible { outline:2px solid #e6edf3; outline-offset:2px; }
.notice { margin:0 0 20px; padding:14px 16px; border-radius:9px;
  background:#2a1f14; border:1px solid #4a3a24; color:#e8c48a; font-size:15px; }
.notice b { color:#f5cf9a; }
.qr-img { display:block; width:100%; height:auto; margin-top:14px; border-radius:9px; background:#fff; padding:8px; box-sizing:border-box; }
/* The reserve block is separated by a rule rather than a second card: it is the
   same profile, handed out for a different day, and a card of its own would read
   as a second product to install. */
.reserve { margin-top:24px; padding-top:22px; border-top:1px solid #232c39; }
.reserve h2 { margin:0 0 6px; font-size:17px; }
.reserve > p { margin:0 0 4px; color:#8b98a9; font-size:15px; }
.reserve-item { margin-top:18px; }
.reserve-name { margin:0 0 8px; font-size:15px; }
.reserve-name span { color:#8b98a9; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px; }
`

const portalHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Your VPN profile</title>
<style>` + portalCSS + `</style></head>
<body><main class="card">
<h1>Your VPN profile</h1>
<p class="sub">{{.Name}}</p>
{{if .Enabled}}
{{/* Promoted out of the step list. Installing the ordinary WireGuard app is the
     single most common way this fails for a person, and as list item 1 — with the
     reason hidden behind a tooltip a phone cannot open — it was the easiest line
     on the page to skim past. */}}
<p class="notice">Install <b>AmneziaWG</b>, not the ordinary WireGuard app. This profile is
obfuscated so it can get through the block, and the plain WireGuard app cannot read it.</p>
<ol class="steps">
  <li>Install <b>AmneziaWG</b> on this device.</li>
  <li>Tap <b>Download profile</b>, then open the file with AmneziaWG.</li>
  <li>Switch the tunnel on.</li>
</ol>
<div class="actions">
  <a class="btn primary" href="/c/{{.Token}}/config">Download profile</a>
</div>
{{/* In the page, not a new tab. It used to open the raw PNG on its own, which
     left the person on an unstyled full-screen image of their own key with no
     caption, no instruction and no way back but a browser gesture. */}}
<details>
  <summary>Set up a second device</summary>
  <p>On the other device, open AmneziaWG, choose <b>Add tunnel → Scan QR code</b>, and point it here.</p>
  <img class="qr-img" src="/c/{{.Token}}/qr" alt="QR code for this profile" loading="lazy">
</details>
{{/* The reserve doors, handed out WITH the main profile and never later: the day
     the master stops answering is the day nobody can be told a new link. Only the
     doors that can actually hand out a config are here — see pageData.Reserves —
     and with none of them the whole section is absent, because a heading
     promising a fallback that is not there is worse than saying nothing. */}}
{{if .Reserves}}
<section class="reserve">
  <h2>If the main server stops working</h2>
  <p>Add these profiles now, while everything works. If the main one stops connecting, switch to any of them.</p>
  {{range .Reserves}}
  <div class="reserve-item">
    <p class="reserve-name">{{.Name}} <span>{{.Endpoint}}</span></p>
    <div class="actions">
      <a class="btn" href="/c/{{$.Token}}/l/{{.ID}}/config">Download reserve profile</a>
    </div>
    <img class="qr-img" src="/c/{{$.Token}}/l/{{.ID}}/qr" alt="QR code for the {{.Name}} reserve profile" loading="lazy">
  </div>
  {{end}}
</section>
{{end}}
<details>
  <summary>Technical details</summary>
  <dl>
    <dt>Address</dt><dd>{{.Address}}</dd>
    {{if .Endpoint}}<dt>Server</dt><dd>{{.Endpoint}}</dd>{{end}}
  </dl>
</details>
{{else}}
<p class="notice">This profile is paused, so it will not connect right now. Nothing is broken
and nothing on your device needs deleting — the same profile works again the moment it is
resumed. Ask whoever gave you this link to resume it.</p>
{{end}}
</main></body></html>
`

// failHTML is the portal's error page: the same card, one sentence, no detail
// about which check failed.
const failHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Your VPN profile</title>
<style>` + portalCSS + `</style></head>
<body><main class="card"><h1>{{.Heading}}</h1><p class="lead">{{.Body}}</p></main></body></html>
`
