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
	"net/netip"
	"slices"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Options are the deployment facts the portal cannot derive from a request.
type Options struct {
	// PublicURL is controller.client_portal_url: where people reach the portal.
	// Set, it is the only base a subscription link is built from.
	PublicURL string
	// Bind is controller.client_portal. Without PublicURL the link is built from
	// it; a request's Host is believed only when the bind is a wildcard, and then
	// only as an IP literal on the bound port — the Host header is the caller's to
	// write, and a link the page tells someone to import must not be.
	Bind string
}

// Handler serves the portal.
type Handler struct {
	src      clientcfg.PortalSource
	masters  func() []string // the masters whose credentials this portal serves
	opts     Options
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

// New builds the portal handler over a source of node/spec/credential/device
// state.
func New(src clientcfg.PortalSource, masters func() []string, opts Options) (*Handler, error) {
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
		opts:     opts,
		mux:      http.NewServeMux(),
		tmpl:     tmpl,
		failTmpl: failTmpl,
		log:      slog.Default(),
		limit:    auth.NewIPLimiter(10, time.Minute, 4096),
	}
	h.mux.HandleFunc("GET /c/{token}", h.handlePage)
	h.mux.HandleFunc("GET /c/{token}/config", h.handleConfig)
	h.mux.HandleFunc("GET /c/{token}/qr", h.handleQR)
	// The device's mihomo subscription (ADR-0035). Same token, same limiter; the
	// app re-fetches it on its own, which is what turns a flag day into a refresh
	// instead of a re-import.
	h.mux.HandleFunc("GET /c/{token}/mihomo", h.handleProfile)
	h.mux.HandleFunc("GET /c/{token}/mihomo/qr", h.handleProfileQR)
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
	// SubscriptionURL is the device's mihomo subscription — the page's headline;
	// "" when the portal knows no address it can vouch for.
	SubscriptionURL string
	// HasWG: there is an AmneziaWG .conf to offer as the fallback path.
	HasWG bool
	// VLESSLinks hold the UUID, which is why the page is no-store like the rest.
	VLESSLinks []string
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

var errTooManyAttempts = errors.New("too many attempts; try again in a minute")

// resolveDevice finds the device a token names. The limiter is charged for a
// token that is malformed or names nothing; never for a store failure.
func (h *Handler) resolveDevice(r *http.Request) (domain.ClientDevice, error) {
	ip := clientIP(r)
	if !h.limit.Allowed(ip) {
		return domain.ClientDevice{}, errTooManyAttempts
	}
	token := r.PathValue("token")
	if !validToken(token) {
		h.limit.Fail(ip)
		return domain.ClientDevice{}, store.ErrNotFound
	}
	dev, err := clientcfg.ResolveDevice(r.Context(), h.src, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.limit.Fail(ip)
		}
		return domain.ClientDevice{}, err
	}
	// No Reset here: resolveDevice only clears the FIRST guessable field (the
	// token). resolveLifeline has a SECOND one (the exit name) still to check, and
	// a Reset here would erase every charge from grinding it before that check
	// ever ran — see the fix in resolveLifeline's own history. Each caller resets
	// once ITS OWN full chain of guessable fields has passed, not before.
	return dev, nil
}

// selectWG is the device's AWG credential for /config, /qr and the reserve
// doors — clientcfg.SelectWG, the same choice the page shows. A device without
// one is not the caller's fault and is not charged. Like resolveDevice, it does
// not reset the limiter itself — resolveLifeline builds on it with a further
// guessable field (the exit) and must defer the reset past that check.
func (h *Handler) selectWG(r *http.Request) (clientcfg.WGSelection, error) {
	dev, err := h.resolveDevice(r)
	if err != nil {
		return clientcfg.WGSelection{}, err
	}
	return clientcfg.SelectWG(r.Context(), h.src, h.masters(), dev)
}

func (h *Handler) handlePage(w http.ResponseWriter, r *http.Request) {
	dev, err := h.resolveDevice(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	v, err := clientcfg.ViewDevice(r.Context(), h.src, h.masters(), dev)
	if err != nil {
		h.fail(w, err)
		return
	}
	// The token is the only guessable field this route has, and resolveDevice
	// already charged it if it was bad — so once ViewDevice also succeeds, this
	// source has earned a clean slate.
	h.limit.Reset(clientIP(r))
	data := pageData{
		Name:            dev.Name,
		Enabled:         v.Active,
		Token:           r.PathValue("token"),
		HasWG:           v.WG != nil,
		SubscriptionURL: h.subscriptionURL(r, dev.Token),
		VLESSLinks:      v.VLESSLinks,
	}
	// The reserve doors are a fallback for the AWG .conf specifically, so they are
	// listed only when there IS one to fall back from — a device with no active AWG
	// credential (paused, or VLESS-only) gets no reserve section, same as the two
	// routes behind it refuse a paused credential.
	if v.WG != nil {
		data.Address = v.WG.Input.Client.Address
		data.Endpoint = v.WG.Input.Endpoint
		data.Reserves = h.reserves(r, v.WG.MasterID)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The page names a credential; keep it out of any shared cache or referrer.
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := h.tmpl.Execute(w, data); err != nil {
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

// resolveLifeline is the device resolution and AWG selection the main routes
// use, plus the exit named in the path.
func (h *Handler) resolveLifeline(r *http.Request) (clientcfg.Result, error) {
	ip := clientIP(r)
	if !h.limit.Allowed(ip) {
		return clientcfg.Result{}, errTooManyAttempts
	}
	exit := r.PathValue("exit")
	// The exit name is caller-supplied like the token, and is bounded and charged
	// BEFORE the device (and so the store) is ever touched — a malformed exit must
	// not be a cheaper oracle than a malformed token.
	if !validExit(exit) {
		h.limit.Fail(ip)
		return clientcfg.Result{}, store.ErrNotFound
	}
	sel, err := h.selectWG(r)
	if err != nil {
		return clientcfg.Result{}, err
	}
	// Readiness is resolved BEFORE the build so the two cases the build folds into
	// one error can be told apart here: an exit the fleet does not have is the
	// caller's doing and is charged, an exit that is not ready is ours and is not.
	exits, err := clientcfg.ListLifelineExits(r.Context(), h.src, sel.MasterID)
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
	res, err := clientcfg.BuildLifeline(r.Context(), h.src, sel.MasterID, sel.Input.Client.ID, exit)
	if err != nil {
		return clientcfg.Result{}, err
	}
	h.limit.Reset(ip)
	return res, nil
}

// handleLifelineConfig serves one reserve .conf. selectWG (inside
// resolveLifeline) already refused a paused or absent credential — BuildLifeline
// itself does not check Enabled — so there is no separate gate here.
func (h *Handler) handleLifelineConfig(w http.ResponseWriter, r *http.Request) {
	res, err := h.resolveLifeline(r)
	if err != nil {
		h.fail(w, err)
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
	png, err := qrcode.Encode(res.Config, qrcode.Medium, 1024)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// handleConfig serves the .conf file the page links to. selectWG returns only
// an ENABLED and READY credential — "all paused" arrives as
// ErrNoActiveCredential (403), so there is no separate Enabled gate here.
func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	sel, err := h.selectWG(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	cfg, err := wg.RenderClientConfig(sel.Input)
	if err != nil {
		h.fail(w, err)
		return
	}
	// The token is the only guessable field this route has, and selectWG (via
	// resolveDevice) already charged it if it was bad — so once the config also
	// rendered, this source has earned a clean slate.
	h.limit.Reset(clientIP(r))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", clientcfg.ConfigFileName(sel.Input.Client)))
	_, _ = w.Write([]byte(cfg))
}

func (h *Handler) handleQR(w http.ResponseWriter, r *http.Request) {
	sel, err := h.selectWG(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	cfg, err := wg.RenderClientConfig(sel.Input)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.limit.Reset(clientIP(r))
	// Big enough that a phone camera can resolve the modules. Measured on a real
	// config (867 bytes): 117x117 modules, so 320px put 2.7 pixels on each one.
	// This is the surface actual people scan, so it matters more here than in the
	// operator UI.
	png, err := qrcode.Encode(cfg, qrcode.Medium, 1024)
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
	case errors.Is(err, errPaused), errors.Is(err, clientcfg.ErrNoActiveCredential):
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
	case errors.Is(err, clientcfg.ErrNoAWG):
		// selectWG (handleConfig/handleQR/the reserve doors) asked for the AWG .conf
		// of a device that is real but has no AWG credential on any master — a
		// VLESS-only device, say. That is not a grind — see ErrNoAWG's own doc — so
		// it falls straight through to the default 404 above, uncharged, rather than
		// into the store-failure branch below.
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

func (h *Handler) handleProfile(w http.ResponseWriter, r *http.Request) {
	dev, err := h.resolveDevice(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	yml, err := clientcfg.BuildDeviceProfile(r.Context(), h.src, h.masters(), dev)
	if err != nil {
		h.fail(w, err)
		return
	}
	// The token is the only guessable field this route has, and resolveDevice
	// already charged it if it was bad — so once the profile also rendered, this
	// source has earned a clean slate.
	h.limit.Reset(clientIP(r))
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	// The body carries the device's AWG private key.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Hours. After a flag day (ADR-0033) this is how long a device can take to
	// follow without anyone touching it.
	w.Header().Set("Profile-Update-Interval", "24")
	w.Header().Set("Content-Disposition", clientcfg.AttachmentHeader(clientcfg.ProfileFileName(dev)))
	_, _ = w.Write([]byte(yml))
}

func (h *Handler) handleProfileQR(w http.ResponseWriter, r *http.Request) {
	dev, err := h.resolveDevice(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	link := h.subscriptionURL(r, dev.Token)
	if link == "" {
		h.fail(w, fmt.Errorf("portal: no trusted address to build the subscription link: %w", clientcfg.ErrNotReady))
		return
	}
	// The token is the only guessable field this route has, and resolveDevice
	// already charged it if it was bad.
	h.limit.Reset(clientIP(r))
	// The QR of the LINK, not the profile: an app scans it and subscribes, and what
	// it fetches keeps updating — a QR of the YAML would be a snapshot that never
	// does, and too large to scan anyway.
	png, err := qrcode.Encode(link, qrcode.Medium, 1024)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// subscriptionURL is the profile's address as the device should import it, or ""
// when the portal knows no address it can vouch for.
func (h *Handler) subscriptionURL(r *http.Request, token string) string {
	path := "/c/" + token + "/mihomo"
	if h.opts.PublicURL != "" {
		return strings.TrimRight(h.opts.PublicURL, "/") + path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := trustedHost(h.opts.Bind, r.Host)
	if host == "" {
		return ""
	}
	return scheme + "://" + host + path
}

// trustedHost is the bind address when it names a host; with a wildcard bind,
// the request's Host only if it is an IP literal on the bound port.
func trustedHost(bind, reqHost string) string {
	bh, bp, err := net.SplitHostPort(bind)
	if err != nil {
		return ""
	}
	if bh != "" {
		if ip, err := netip.ParseAddr(bh); err != nil || !ip.IsUnspecified() {
			return bind
		}
	}
	rh, rp, err := net.SplitHostPort(reqHost)
	if err != nil || rp != bp {
		return ""
	}
	if _, err := netip.ParseAddr(rh); err != nil {
		return ""
	}
	return reqHost
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
.sub-url { width:100%; box-sizing:border-box; margin:6px 0 0; padding:12px; border-radius:9px;
  border:1px solid #2b3646; background:#11151c; color:#e6edf3;
  font:13px ui-monospace, SFMono-Regular, Menlo, monospace; }
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
<p class="notice">Use a <b>mihomo</b> app: <b>FlClash</b> (Android, macOS), <b>ClashMetaForAndroid</b>,
<b>ClashX Meta</b> or <b>Clash Verge Rev</b> (macOS). One link sets up both connections and switches between them on its own.</p>
{{if .SubscriptionURL}}
<ol class="steps">
  <li>Install one of the apps above on this device.</li>
  <li>Add a profile <b>from URL</b> and paste the link below — or scan the QR.</li>
  <li>Switch on <b>TUN</b> mode in the app, then connect.</li>
</ol>
<input class="sub-url" type="text" readonly value="{{.SubscriptionURL}}" aria-label="Subscription link" onclick="this.select()">
<img class="qr-img" src="/c/{{.Token}}/mihomo/qr" alt="QR code of the subscription link" loading="lazy">
{{else}}
<p class="sub">The subscription link is not available here — ask whoever sent you this page.</p>
{{end}}
<p class="sub">For another device, ask for a separate link — one link belongs to one device.</p>
<p class="sub">Connected with a profile file you were sent? Add the link above as a new profile, switch to it, then delete the file profile — only the link keeps itself up to date.</p>
{{if .HasWG}}
<details>
  <summary>AmneziaWG app instead</summary>
  <p>Install <b>AmneziaWG</b>, not the ordinary WireGuard app: this profile is obfuscated and the plain app cannot read it.</p>
  <div class="actions"><a class="btn" href="/c/{{.Token}}/config">Download profile</a></div>
  <img class="qr-img" src="/c/{{.Token}}/qr" alt="QR code for the AmneziaWG profile" loading="lazy">
</details>
{{end}}
{{if .VLESSLinks}}
<details>
  <summary>VLESS link</summary>
  {{range .VLESSLinks}}<input class="sub-url" type="text" readonly value="{{.}}" aria-label="VLESS link" onclick="this.select()">{{end}}
</details>
{{end}}
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
{{if .HasWG}}
<details>
  <summary>Technical details</summary>
  <dl>
    <dt>Address</dt><dd>{{.Address}}</dd>
    {{if .Endpoint}}<dt>Server</dt><dd>{{.Endpoint}}</dd>{{end}}
  </dl>
</details>
{{end}}
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
