package portal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// devTok is the portal token of the device fixture testPortal builds: "laptop",
// holding the aaaabbbbccccdddd AWG credential on master-xa-1.
const devTok = "0123456789abcdef0123456789abcdef"

// stubSource is a fixed one-master, two-credential world, plus two reserve doors:
// one exit that can hand out a config and one that cannot yet. Both are needed
// together — the portal's rule is that the second is invisible, and a fixture
// with only ready exits cannot tell "hidden" from "absent".
type stubSource struct {
	node    domain.Node
	spec    domain.NodeSpec
	clients []domain.WGClient
	// exits is the manifest order of the fleet's lifeline exits; exitNodes and
	// exitSpecs are their records, and hosts the address a client would dial.
	exits     []string
	exitNodes map[string]domain.Node
	exitSpecs map[string]domain.NodeSpec
	hosts     map[string]string
	checks    map[string][]domain.HealthCheck
	// devices are the fleet's client devices (ADR-0035), keyed by portal token.
	devices map[string]domain.ClientDevice
	vless   []domain.VLESSClient
	// legacy names the WGClient IDs that have never belonged to a device — their
	// own /c/{id} link is still live (see ResolveDevice's fallback path).
	legacy map[string]bool
	// aliases names additional master IDs that answer with the same node/spec as
	// s.node/s.spec — a second master sharing the fixture's fleet state, needed to
	// test a device with credentials on more than one master.
	aliases map[string]bool
	// lifelineMaster overrides the master the reserve interfaces carry; empty means
	// the fixture's own master, so the one-master tests need not set it.
	lifelineMaster string
}

func (s stubSource) LifelineMaster(context.Context) (string, error) {
	if s.lifelineMaster != "" {
		return s.lifelineMaster, nil
	}
	return s.node.ID, nil
}

func (s stubSource) NodeChecks(_ context.Context, id string) ([]domain.HealthCheck, error) {
	return s.checks[id], nil
}

func (s stubSource) GetNode(_ context.Context, id string) (domain.Node, error) {
	if id == s.node.ID || s.aliases[id] {
		n := s.node
		n.ID = id
		return n, nil
	}
	if n, ok := s.exitNodes[id]; ok {
		return n, nil
	}
	return domain.Node{}, store.ErrNotFound
}

func (s stubSource) RenderNodeSpec(_ context.Context, id string) (domain.NodeSpec, error) {
	if sp, ok := s.exitSpecs[id]; ok {
		return sp, nil
	}
	if id == s.node.ID || s.aliases[id] {
		return s.spec, nil
	}
	return domain.NodeSpec{}, store.ErrNotFound
}

func (s stubSource) ListWGClients(context.Context, string) ([]domain.WGClient, error) {
	return s.clients, nil
}

func (s stubSource) LifelineExits(context.Context) ([]string, error) { return s.exits, nil }

func (s stubSource) ExitEndpointHost(_ context.Context, exitID string) (string, error) {
	return s.hosts[exitID], nil
}

func (s stubSource) GetDeviceByToken(_ context.Context, tok string) (domain.ClientDevice, error) {
	if d, ok := s.devices[tok]; ok {
		return d, nil
	}
	return domain.ClientDevice{}, store.ErrNotFound
}

func (s stubSource) FindUnattachedWGClient(_ context.Context, id string) (string, domain.WGClient, error) {
	if !s.legacy[id] {
		return "", domain.WGClient{}, store.ErrNotFound
	}
	for _, c := range s.clients {
		if c.ID == id {
			return s.node.ID, c, nil
		}
	}
	return "", domain.WGClient{}, store.ErrNotFound
}

func (s stubSource) ListVLESSClients(context.Context, string) ([]domain.VLESSClient, error) {
	return s.vless, nil
}

func (s stubSource) ClientMasterMeta(context.Context, string) (domain.ClientMasterMeta, error) {
	return domain.ClientMasterMeta{Resolvers: []string{"10.80.0.1"}, ClientPool: "10.80.0.0/24",
		MgmtCIDRs: []string{"10.20.0.0/16"}}, nil
}

// lifelineSpec is an exit's reserve client-facing interface: its own port and its
// own pool, deliberately unlike the master's, so a config rendered from the wrong
// spec cannot pass as the right one.
func lifelineSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleExit,
		Lifeline: &domain.LifelineSpec{
			ClientWGSpec: domain.ClientWGSpec{
				ListenPort: 41827, AddressPool: "10.98.77.0/24", ServerAddress: "10.98.77.1",
				MTU: 1360, DNS: []string{"10.98.77.1"},
				AllowedIPs: []string{"0.0.0.0/1", "128.0.0.0/1"},
			},
			Egress: domain.EgressDirect,
		},
	}
}

func testPortal(t *testing.T) *Handler {
	t.Helper()
	src := stubSource{
		node: domain.Node{
			ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
			PublicIP: "203.0.113.1", ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
		},
		spec: domain.NodeSpec{
			Role: domain.RoleMaster,
			Master: &domain.MasterSpec{ClientWG: &domain.ClientWGSpec{
				ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1",
				MTU: 1360, DNS: []string{"10.80.0.1"}, AllowedIPs: []string{"0.0.0.0/0"},
			}},
		},
		clients: []domain.WGClient{
			{ID: "aaaabbbbccccdddd", Name: "laptop", Address: "10.80.0.2/32",
				PublicKey: "pub-a", PrivateKey: "Y2xpZW50LXByaXZhdGUta2V5LTAwMDAwMDAwMDA=", Enabled: true},
			{ID: "1111222233334444", Name: "phone", Address: "10.80.0.3/32",
				PublicKey: "pub-b", PrivateKey: "cGhvbmUtcHJpdmF0ZS1rZXktMDAwMDAwMDAwMA==", Enabled: false},
		},
		exits: []string{"exit-ready", "exit-waiting"},
		exitNodes: map[string]domain.Node{
			// The name deliberately differs from the ID: the URL is built from one and
			// the label from the other, and a fixture where they matched would let a
			// page that shows the ID pass as one that shows the name.
			"exit-ready": {ID: "exit-ready", Name: "spare-door", Role: domain.RoleExit,
				PublicIP: "198.51.100.9", LifelinePublicKey: "ZXhpdC1saWZlbGluZS1rZXktMDAwMDAwMDAwMDAwMDA="},
			// No published lifeline key: the door exists in the manifest and is not
			// open yet.
			"exit-waiting": {ID: "exit-waiting", Name: "exit-waiting", Role: domain.RoleExit,
				PublicIP: "198.51.100.10"},
		},
		exitSpecs: map[string]domain.NodeSpec{
			"exit-ready":   lifelineSpec(),
			"exit-waiting": lifelineSpec(),
		},
		hosts: map[string]string{"exit-ready": "198.51.100.9", "exit-waiting": "198.51.100.10"},
		devices: map[string]domain.ClientDevice{
			// laptop's AWG credential (aaaabbbbccccdddd) is attached here, so its own
			// /c/aaaabbbbccccdddd link is retired — see TestPortalDeletedDeviceLinkStaysDead.
			devTok: {ID: "d0", Token: devTok, Name: "laptop", Credentials: []domain.DeviceCredential{
				{Kind: domain.CredentialAWG, MasterID: "master-xa-1", Ref: "aaaabbbbccccdddd"},
			}},
		},
		// phone (1111222233334444) has never been attached to a device: its own
		// legacy link is still live.
		legacy: map[string]bool{"1111222233334444": true},
	}
	h, err := New(src, func() []string { return []string{"master-xa-1"} }, Options{Bind: "10.20.0.10:9001"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func fetch(t *testing.T, h http.Handler, path string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "10.80.0.2:51820"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func TestPortalShowsOwnProfile(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	// The app is named, and Download leads: the stated audience is a person on a
	// phone, which cannot scan its own screen.
	for _, want := range []string{"laptop", "10.80.0.2/32", "203.0.113.1:443", "AmneziaWG", "Download profile"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
	// The page must not be a copy of the credential, nor mention anyone else.
	if strings.Contains(body, "Y2xpZW50LXByaXZhdGUta2V5") {
		t.Fatal("the portal page embedded the private key")
	}
	if strings.Contains(body, "phone") {
		t.Fatal("the portal page listed another client")
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestPortalServesConfigAndQR(t *testing.T) {
	h := testPortal(t)

	res, cfg := fetch(t, h, "/c/"+devTok+"/config")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("config status = %d", res.StatusCode)
	}
	for _, want := range []string{"[Interface]", "PrivateKey = Y2xpZW50", "Endpoint = 203.0.113.1:443"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if got := res.Header.Get("Content-Disposition"); !strings.Contains(got, `"laptop.conf"`) {
		t.Errorf("Content-Disposition = %q", got)
	}

	res, png := fetch(t, h, "/c/"+devTok+"/qr")
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(png, "\x89PNG") {
		t.Fatalf("QR status = %d, prefix = %q", res.StatusCode, png[:4])
	}
}

// A muted credential still resolves — the person should see WHY they are
// disconnected rather than a dead link — but the portal does not hand out the
// config, so a paused profile cannot be re-imported to work around the pause.
func TestPortalMutedProfile(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/1111222233334444")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "paused") {
		t.Errorf("muted profile does not explain itself:\n%s", body)
	}
	if strings.Contains(body, "Download profile") {
		t.Error("a paused profile still offers its config")
	}
}

func TestPortalRejectsUnknownAndMalformedTokens(t *testing.T) {
	h := testPortal(t)
	for _, path := range []string{
		"/c/ffffffffffffffff",    // well-formed, not ours
		"/c/short",               // too short
		"/c/../../etc/passwd",    // traversal
		"/c/aaaabbbbccccdddd%00", // NUL
		"/c/notthetoken!!!!",     // out of alphabet
	} {
		res, _ := fetch(t, h, path)
		if res.StatusCode == http.StatusOK {
			t.Errorf("%s returned 200", path)
		}
	}
}

// The portal must expose nothing but the three client routes. This is the whole
// reason it is a separate listener, so it is worth asserting rather than assuming.
func TestPortalHasNoFleetSurface(t *testing.T) {
	h := testPortal(t)
	for _, path := range []string{
		"/", "/nodes", "/nodes/master-xa-1", "/login", "/backup",
		"/nodes/master-xa-1/wg-clients", "/rollout/start", "/static/app.css",
		// The reserve doors added two routes UNDER a token. Neither the console's
		// own lifeline URLs nor a truncated portal one may answer here: the reserve
		// path is a leaf on a credential, not a way into the fleet.
		"/nodes/master-xa-1/wg-clients/aaaabbbbccccdddd/lifeline/exit-ready/config",
		"/nodes/master-xa-1/wg-clients/aaaabbbbccccdddd/lifeline/exit-ready/qr",
		"/c/aaaabbbbccccdddd/l", "/c/aaaabbbbccccdddd/l/exit-ready",
	} {
		res, _ := fetch(t, h, path)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404 (the portal must expose no fleet surface)", path, res.StatusCode)
		}
	}
}

// Mutating verbs have no route at all: even the client's own profile is read-only
// from here.
func TestPortalIsReadOnly(t *testing.T) {
	h := testPortal(t)
	// Every route the portal has, including the two reserve ones: a door handed out
	// for the day the master is gone must be no more writable than the main one.
	paths := []string{
		"/c/aaaabbbbccccdddd",
		"/c/aaaabbbbccccdddd/l/exit-ready/config",
		"/c/aaaabbbbccccdddd/l/exit-ready/qr",
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range paths {
			req := httptest.NewRequest(method, path, nil)
			req.RemoteAddr = "10.80.0.2:51820"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				t.Errorf("%s %s succeeded", method, path)
			}
		}
	}
}

// Repeated bad tokens from one source lock that source out for a while; the
// token is unguessable, but a portal facing the client pool should still not be
// a free oracle.
func TestPortalRateLimitsBadTokens(t *testing.T) {
	h := testPortal(t)
	var locked bool
	for i := range 20 {
		res, _ := fetch(t, h, "/c/ffffffffffffffff")
		if res.StatusCode == http.StatusTooManyRequests {
			locked = true
			break
		}
		if i > 15 && res.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("still answering after %d bad tokens", i)
		}
	}
	if !locked {
		t.Fatal("the portal never rate-limited a grinding source")
	}
	// A good token from the same source is locked out too — that is the point of a
	// per-source lock — but it must recover, which the limiter's window handles.
	res, _ := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("lock did not apply to the grinding source: %d", res.StatusCode)
	}
}

// A person whose credential was revoked reopens the only link they have. They
// should meet a sentence, not the string "not found" on a white page.
func TestPortalFailurePageIsHuman(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/ffffffffffffffff")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type = %q, want an HTML page", got)
	}
	for _, want := range []string{"no longer working", "keeps using the profile it already has"} {
		if !strings.Contains(body, want) {
			t.Errorf("failure page missing %q:\n%s", want, body)
		}
	}
	// It still must not say WHICH check failed.
	for _, leak := range []string{"master", "not managed", "endpoint", "token"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("failure page discloses %q", leak)
		}
	}
}

// The page's only heading must describe the PAGE, not the credential.
//
// It used to be the credential's name, so a screen reader announced the page as
// "alice-iphone" and the purpose was demoted to a sub-line — on the one page in
// this system written for somebody who does not know what any of this is.
func TestPortalHeadingNamesThePageNotTheCredential(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "<h1>Your VPN profile</h1>") {
		t.Errorf("the heading does not name the page:\n%s", body)
	}
	// The name still has to be on the page — it is how a person tells two of their
	// own devices apart.
	if !strings.Contains(body, "laptop") {
		t.Error("the credential name is not shown anywhere")
	}
}

// failingSource makes ListWGClients fail the way a busy SQLite store does.
type failingSource struct {
	stubSource
	err error
}

func (f failingSource) ListWGClients(context.Context, string) ([]domain.WGClient, error) {
	return nil, f.err
}

// A store hiccup must not be reported to the person as "your profile was
// revoked", and must not count against their rate limit.
//
// Both halves were wrong together: FindByID skipped a master it could not read
// and fell through to ErrNotFound, and resolve charged a failure for any error at
// all. The result during a hiccup was every legitimate user being told their
// access was gone, and the ones who reloaded locking themselves out.
func TestPortalDistinguishesAStoreFailureFromABadToken(t *testing.T) {
	h := testPortal(t)
	h.src = failingSource{stubSource: h.src.(stubSource), err: errors.New("database is locked")}

	res, body := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body:\n%s", res.StatusCode, body)
	}
	if strings.Contains(body, "no longer working") || strings.Contains(body, "switched off") {
		t.Errorf("a server failure was reported as a revoked profile:\n%s", body)
	}
	if !strings.Contains(body, "not a problem with your profile") {
		t.Errorf("the page does not reassure the person their profile is fine:\n%s", body)
	}

	// And it must not have burned the rate limit: repeated reloads during an
	// outage must keep working once the store recovers.
	for range 10 {
		if _, _ = fetch(t, h, "/c/"+devTok); false {
			return
		}
	}
	h.src = h.src.(failingSource).stubSource
	if res, _ := fetch(t, h, "/c/"+devTok); res.StatusCode != http.StatusOK {
		t.Errorf("after the store recovered the caller was still locked out: status = %d", res.StatusCode)
	}
}

// The warning that prevents this product's most common support failure must not
// be a list item behind a tooltip.
//
// Installing the ordinary WireGuard app is the way this goes wrong for a person,
// and a title= attribute is unopenable on the phone they are holding.
func TestPortalWarnsAboutTheWrongAppInTheOpen(t *testing.T) {
	h := testPortal(t)
	_, body := fetch(t, h, "/c/"+devTok)

	// The warning now lives inside the "AmneziaWG app instead" details block — the
	// subscription is the main path (ADR-0035) — so this only checks presence, not
	// location.
	if !strings.Contains(body, "not the ordinary WireGuard app") {
		t.Errorf("the wrong-app warning is missing:\n%s", body)
	}
	if strings.Contains(body, "title=\"This profile uses") {
		t.Error("the explanation is still hidden in a tooltip")
	}
	// The QR belongs on the page, not in a tab showing a bare image of a key.
	if !strings.Contains(body, `<img class="qr-img"`) {
		t.Error("the QR is not rendered in the page")
	}
	if strings.Contains(body, `href="/c/`+devTok+`/qr" target="_blank"`) {
		t.Error("the QR still opens as a bare image in a new tab")
	}
}

// Both portal pages are the same card and must not drift apart again.
func TestPortalPagesShareOneStylesheet(t *testing.T) {
	h := testPortal(t)
	_, ok := fetch(t, h, "/c/"+devTok)
	_, bad := fetch(t, h, "/c/ffffffffffffffff")
	for _, marker := range []string{"align-items:start", ".card { box-sizing:border-box; width:min(420px, calc(100vw - 32px))"} {
		if !strings.Contains(ok, marker) || !strings.Contains(bad, marker) {
			t.Errorf("the two portal pages do not share %q", marker)
		}
	}
}

// The page hiding the button was never the same thing as the file being refused:
// handleConfig and handleQR ignored Enabled entirely, so anyone who reloaded the
// link out of their history — or simply kept the /config URL — was handed a full
// config with a live private key for a peer the server had already removed. The
// claim in TestPortalMutedProfile's comment was true of the PAGE and false of the
// two endpoints behind it.
func TestPortalPausedProfileServesNoConfigOrQR(t *testing.T) {
	h := testPortal(t)
	for _, path := range []string{"/c/1111222233334444/config", "/c/1111222233334444/qr"} {
		res, body := fetch(t, h, path)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, res.StatusCode)
		}
		if strings.Contains(body, "PrivateKey") {
			t.Errorf("GET %s handed out a private key for a paused credential", path)
		}
		if !strings.Contains(body, "paused") {
			t.Errorf("GET %s does not say the profile is paused:\n%s", path, body)
		}
	}
}

// The reserve doors are handed out WITH the main profile, not after the master
// has already gone: a person who has to be told a URL on the day the master is
// unreachable has no way of being told.
func TestPortalOffersReserveProfiles(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	for _, want := range []string{
		"If the main server stops working",
		"Add these profiles now, while everything works.",
		`href="/c/` + devTok + `/l/exit-ready/config"`,
		`src="/c/` + devTok + `/l/exit-ready/qr"`,
		"Download reserve profile",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
	// The URL is built from the exit's ID and the label is the exit's NAME. They
	// are different strings in this fixture on purpose: a person told over the
	// phone which reserve to switch to is told the name.
	if !strings.Contains(body, `<p class="reserve-name">spare-door <span>198.51.100.9:41827</span></p>`) {
		t.Errorf("the reserve door is not labelled by the exit's name:\n%s", body)
	}
	// The QR is lazy: several reserve doors mean several full-size images, and the
	// person on a phone came here to tap Download.
	if !strings.Contains(body, `src="/c/`+devTok+`/l/exit-ready/qr" alt="QR code for the spare-door reserve profile" loading="lazy"`) {
		t.Errorf("the reserve QR is not lazily loaded or not named:\n%s", body)
	}
	// An exit that cannot hand out a config is not on this page at all, and neither
	// is our reason for it: the person can do nothing with either, and the operator
	// sees both in the console.
	for _, leak := range []string{"exit-waiting", "has not published"} {
		if strings.Contains(body, leak) {
			t.Errorf("the page shows the not-ready exit (%q):\n%s", leak, body)
		}
	}
}

// The reserve config is the same credential pointed at an exit: the person's own
// private key, the exit's endpoint, the shifted address, and a filename that
// cannot be confused with the main one in a Downloads folder.
func TestPortalServesReserveConfigAndQR(t *testing.T) {
	h := testPortal(t)

	res, cfg := fetch(t, h, "/c/"+devTok+"/l/exit-ready/config")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reserve config status = %d, body:\n%s", res.StatusCode, cfg)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = Y2xpZW50",
		"Endpoint = 198.51.100.9:41827",
		"10.98.77.2/32",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("reserve config missing %q:\n%s", want, cfg)
		}
	}
	// It must be the EXIT's door, never the master's.
	if strings.Contains(cfg, "203.0.113.1:443") {
		t.Errorf("the reserve config points at the master:\n%s", cfg)
	}
	if got := res.Header.Get("Content-Disposition"); !strings.Contains(got, `"laptop-exit-ready.conf"`) {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	res, png := fetch(t, h, "/c/"+devTok+"/l/exit-ready/qr")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reserve QR status = %d", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "image/png" {
		t.Errorf("reserve QR Content-Type = %q", got)
	}
	if !strings.HasPrefix(png, "\x89PNG") {
		t.Errorf("reserve QR is not a PNG: %q", png[:4])
	}
}

// An exit whose door is not open answers exactly as an exit that does not exist:
// the person holding a stale link learns nothing about the fleet, and gets the
// page that tells them their own profile is unaffected.
func TestPortalReserveNotReadyExitIsNotFound(t *testing.T) {
	h := testPortal(t)
	for _, path := range []string{
		"/c/" + devTok + "/l/exit-waiting/config",
		"/c/" + devTok + "/l/exit-waiting/qr",
		"/c/" + devTok + "/l/exit-gone/config",
	} {
		res, body := fetch(t, h, path)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404; body:\n%s", path, res.StatusCode, body)
		}
		if strings.Contains(body, "PrivateKey") {
			t.Errorf("GET %s handed out a config", path)
		}
		if !strings.Contains(body, "no longer working") {
			t.Errorf("GET %s does not answer with the stale-link page:\n%s", path, body)
		}
	}
}

// A door that is not open yet is OUR state, not the caller's, so asking for it
// must not count against them. A person who bookmarked a reserve link would
// otherwise lock themselves out of their own working profile by reloading it.
func TestPortalReserveNotReadyExitIsNotChargedToTheCaller(t *testing.T) {
	h := testPortal(t)
	for range 20 {
		fetch(t, h, "/c/"+devTok+"/l/exit-waiting/config")
	}
	if res, _ := fetch(t, h, "/c/"+devTok); res.StatusCode != http.StatusOK {
		t.Errorf("the caller was locked out by our own unready exit: status = %d", res.StatusCode)
	}
}

// The portal's own rule, and it differs from the console's on purpose: a paused
// credential hands out no config here, main or reserve. The reserve route is the
// one somebody keeps in their history and reloads, which is exactly how a peer
// the server has already dropped gets re-imported.
func TestPortalPausedProfileServesNoReserveConfigOrQR(t *testing.T) {
	h := testPortal(t)
	// The page agrees with the two routes: a paused profile is offered no reserve
	// door either, which is also why the listing behind it is never run.
	if _, page := fetch(t, h, "/c/1111222233334444"); strings.Contains(page, "If the main server stops working") {
		t.Errorf("a paused profile is still offered reserve doors:\n%s", page)
	}
	for _, path := range []string{
		"/c/1111222233334444/l/exit-ready/config",
		"/c/1111222233334444/l/exit-ready/qr",
	} {
		res, body := fetch(t, h, path)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, res.StatusCode)
		}
		if strings.Contains(body, "PrivateKey") {
			t.Errorf("GET %s handed out a private key for a paused credential", path)
		}
		if !strings.Contains(body, "paused") {
			t.Errorf("GET %s does not say the profile is paused:\n%s", path, body)
		}
	}
}

// A made-up exit name is caller-supplied input like a made-up token, and is
// charged the same. The shape is checked before the store is touched, so a
// grinder cannot use the reserve route as a cheaper oracle than the main one.
func TestPortalRateLimitsBadExitNames(t *testing.T) {
	// devTok, not the dead aaaabbbbccccdddd: "exit-nope" is a well-shaped exit
	// name that simply does not exist, so it only gets charged if the request
	// actually reaches the exit-existence check — which requires a token that
	// resolves. A dead token would lock the source out on the TOKEN alone, before
	// the exit name was ever looked at, and the test would pass without having
	// tested exit-name grinding at all.
	for _, exit := range []string{"not!an!exit", "exit-nope"} {
		h := testPortal(t)
		var locked bool
		for i := range 20 {
			res, _ := fetch(t, h, "/c/"+devTok+"/l/"+exit+"/config")
			if res.StatusCode == http.StatusTooManyRequests {
				locked = true
				break
			}
			if i > 15 {
				t.Fatalf("still answering after %d bad exits (%s)", i, exit)
			}
		}
		if !locked {
			t.Errorf("the portal never rate-limited a source grinding exit names (%s)", exit)
		}
	}
}

// A device on a non-base master asking for a reserve config is not guessing URLs:
// the fleet simply has none for it. It gets a 404 and is not charged. Modelled on
// TestPortalRateLimitsBadExitNames, with the opposite expectation: there a made-up
// exit name locks the source out, here a real, ready exit must not.
func TestReserveConfigForANonBaseMasterIsNotCharged(t *testing.T) {
	h := testPortal(t)
	src := h.src.(stubSource)
	src.lifelineMaster = "master-other"
	h.src = src

	for i := range 20 {
		res, _ := fetch(t, h, "/c/"+devTok+"/l/exit-ready/config")
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("reserve config #%d for a non-base master's device = %d, want 404", i, res.StatusCode)
		}
	}
	if res, _ := fetch(t, h, "/c/"+devTok+"/config"); res.StatusCode == http.StatusTooManyRequests {
		t.Error("asking for a reserve the fleet has none of locked the source out")
	}
	_, body := fetch(t, h, "/c/"+devTok)
	if strings.Contains(body, "If the main server stops working") {
		t.Errorf("the page offers a reserve section to a non-base master's device:\n%s", body)
	}
}

// With nothing to offer, the section is absent entirely rather than present and
// empty: a heading promising a fallback that is not there is worse than silence.
func TestPortalHidesTheReserveSectionWithNoReadyExits(t *testing.T) {
	h := testPortal(t)
	src := h.src.(stubSource)
	src.exits = []string{"exit-waiting"}
	h.src = src

	_, body := fetch(t, h, "/c/"+devTok)
	for _, leak := range []string{"If the main server stops working", "Download reserve profile"} {
		if strings.Contains(body, leak) {
			t.Errorf("the reserve section is rendered with no ready exit (%q):\n%s", leak, body)
		}
	}
	if !strings.Contains(body, "Download profile") {
		t.Error("the main profile disappeared with the reserve section")
	}
}

// A reserve listing that fails must cost the page nothing: the main profile is
// what the person came for, and it is still valid.
func TestPortalPageSurvivesAFailingReserveListing(t *testing.T) {
	h := testPortal(t)
	src := h.src.(stubSource)
	src.exits = []string{"exit-broken"}
	src.exitSpecs = map[string]domain.NodeSpec{"exit-broken": {}}
	src.exitNodes = map[string]domain.Node{}
	h.src = brokenExitSource{stubSource: src, err: errors.New("database is locked")}

	res, body := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the page anyway; body:\n%s", res.StatusCode, body)
	}
	if !strings.Contains(body, "Download profile") {
		t.Errorf("a failing reserve listing took the main profile with it:\n%s", body)
	}
	if strings.Contains(body, "If the main server stops working") {
		t.Errorf("the reserve section rendered from a failed listing:\n%s", body)
	}
}

// brokenExitSource fails the reserve listing alone; everything the main profile
// needs still answers.
type brokenExitSource struct {
	stubSource
	err error
}

func (b brokenExitSource) LifelineExits(context.Context) ([]string, error) { return nil, b.err }

// The shape of the exit name is checked BEFORE the store is consulted, and the
// falsifier is a store that cannot answer: if the order were the other way round
// a malformed exit would come back as our failure (503, uncharged) instead of the
// caller's (404, charged), and grinding the reserve route would cost nothing.
func TestPortalChecksTheExitNameBeforeTouchingTheStore(t *testing.T) {
	h := testPortal(t)
	h.src = brokenExitSource{stubSource: h.src.(stubSource), err: errors.New("database is locked")}

	res, _ := fetch(t, h, "/c/"+devTok+"/l/not!an!exit/config")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("a malformed exit against an unreadable store = %d, want 404", res.StatusCode)
	}
	// And a well-formed one does reach the store, where the failure is ours.
	if res, _ := fetch(t, h, "/c/"+devTok+"/l/exit-ready/config"); res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("a store failure on the reserve route = %d, want 503", res.StatusCode)
	}
}

// The portal's charset and the manifest's are one rule (domain.ValidLifelineExitName).
// While they disagreed, an exit named "EU-1" was LISTED on this page with a
// download and a QR that both 404'd and both charged the limiter — ten auto-loaded
// QR images and the person was locked out of their own working profile. The
// falsifier is a store that cannot answer: a name that gets past the shape check
// reaches it and comes back as our failure (503), not the caller's (404).
func TestPortalAcceptsEveryExitNameTheManifestAllows(t *testing.T) {
	for _, name := range []string{"EU-1", "de.fra.1", "eu_1"} {
		h := testPortal(t)
		h.src = brokenExitSource{stubSource: h.src.(stubSource), err: errors.New("database is locked")}
		res, _ := fetch(t, h, "/c/"+devTok+"/l/"+name+"/config")
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("exit %q against an unreadable store = %d, want 503 (it must get past the shape check)",
				name, res.StatusCode)
		}
	}
}

func TestPortalServesTheMihomoProfile(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/"+devTok+"/mihomo")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", res.StatusCode, body)
	}
	for k, want := range map[string]string{
		"Content-Type":            "text/yaml; charset=utf-8",
		"Cache-Control":           "no-store",
		"Profile-Update-Interval": "24",
		"Referrer-Policy":         "no-referrer",
		"Content-Disposition":     `attachment; filename="laptop.yaml"; filename*=UTF-8''laptop.yaml`,
	} {
		if got := res.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(body, "master-xa-1-awg") || !strings.Contains(body, "type: fallback") {
		t.Errorf("profile body:\n%s", body)
	}
}

func TestPortalProfilePausedIs403(t *testing.T) {
	h := testPortal(t)
	if res, _ := fetch(t, h, "/c/1111222233334444/mihomo"); res.StatusCode != http.StatusForbidden {
		t.Errorf("paused profile: status = %d, want 403", res.StatusCode)
	}
}

func TestPortalProfileBadTokenChargesTheLimiter(t *testing.T) {
	h := testPortal(t)
	for i := 0; i < 10; i++ {
		if res, _ := fetch(t, h, "/c/deadbeefdeadbeefdeadbeefdeadbeef/mihomo"); res.StatusCode != http.StatusNotFound {
			t.Fatalf("bad token #%d: status %d", i, res.StatusCode)
		}
	}
	if res, _ := fetch(t, h, "/c/"+devTok+"/mihomo"); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after 10 misses: status = %d, want 429", res.StatusCode)
	}
}

func TestPortalDeletedDeviceLinkStaysDead(t *testing.T) {
	h := testPortal(t)
	// aaaabbbbccccdddd is the credential behind devTok. Attached (or once
	// attached), it must never resolve through the legacy path.
	if res, _ := fetch(t, h, "/c/aaaabbbbccccdddd/mihomo"); res.StatusCode != http.StatusNotFound {
		t.Errorf("attached credential ID resolves: %d", res.StatusCode)
	}
	src := h.src.(stubSource)
	delete(src.devices, devTok) // the device is deleted; the credential stays, retired
	for _, p := range []string{"/c/" + devTok, "/c/aaaabbbbccccdddd", "/c/aaaabbbbccccdddd/config"} {
		if res, _ := fetch(t, h, p); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s after delete: %d, want 404", p, res.StatusCode)
		}
	}
}

func TestPortalPageAndConfigAgreeOnTheCredential(t *testing.T) {
	h := testPortal(t)
	src := h.src.(stubSource)
	// Two masters: the first credential paused, the second enabled. The page and
	// /config must both land on the second.
	src.aliases = map[string]bool{"master-xa-2": true}
	src.devices[devTok] = domain.ClientDevice{ID: "d1", Token: devTok, Name: "laptop", Credentials: []domain.DeviceCredential{
		{Kind: domain.CredentialAWG, MasterID: "master-xa-1", Ref: "1111222233334444"},
		{Kind: domain.CredentialAWG, MasterID: "master-xa-2", Ref: "aaaabbbbccccdddd"},
	}}
	h.src, h.masters = src, func() []string { return []string{"master-xa-1", "master-xa-2"} }
	_, page := fetch(t, h, "/c/"+devTok)
	res, conf := fetch(t, h, "/c/"+devTok+"/config")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/config: %d", res.StatusCode)
	}
	if !strings.Contains(conf, "Address = 10.80.0.2/32") || !strings.Contains(page, "10.80.0.2/32") ||
		strings.Contains(page, "10.80.0.3/32") {
		t.Errorf("page and /config disagree:\npage:%s\nconf:%s", page, conf)
	}
}

func TestSubscriptionURLIgnoresForgedHost(t *testing.T) {
	h := testPortal(t)
	page := func(host string) string {
		req := httptest.NewRequest(http.MethodGet, "/c/"+devTok, nil)
		req.RemoteAddr, req.Host = "10.80.0.2:51820", host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if body := page("evil.example"); strings.Contains(body, "evil.example") ||
		!strings.Contains(body, "http://10.20.0.10:9001/c/"+devTok+"/mihomo") {
		t.Errorf("forged Host reached the link, or the bind address did not:\n%s", body)
	}
	h.opts.PublicURL = "https://vpn.example.org/"
	if body := page("10.20.0.10:9001"); !strings.Contains(body, "https://vpn.example.org/c/"+devTok+"/mihomo") {
		t.Error("configured public URL not used")
	}
	h.opts = Options{Bind: ":9001"}
	if body := page("10.20.0.10:9001"); !strings.Contains(body, "http://10.20.0.10:9001/c/"+devTok+"/mihomo") {
		t.Error("wildcard bind: an IP-literal Host on the bound port must be accepted")
	}
	if body := page("evil.example:9001"); strings.Contains(body, "evil.example") {
		t.Error("wildcard bind: a DNS-name Host was trusted")
	}
}

// The "delete the file profile" hint says "add the link above" — nonsense, and
// actively misleading, on a page that has no subscription link to add because the
// request's Host could not be trusted (see TestSubscriptionURLIgnoresForgedHost).
func TestFileProfileHintOnlyShownWithASubscriptionLink(t *testing.T) {
	h := testPortal(t)
	h.opts = Options{Bind: ":9001"} // wildcard bind + an untrusted DNS-name Host ⇒ SubscriptionURL == ""
	req := httptest.NewRequest(http.MethodGet, "/c/"+devTok, nil)
	req.RemoteAddr, req.Host = "10.80.0.2:51820", "evil.example:9001"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "delete the file profile") {
		t.Errorf("the file-profile hint points at a link the page does not have:\n%s", body)
	}
	if !strings.Contains(body, "subscription link is not available here") {
		t.Errorf("the page did not explain the missing link:\n%s", body)
	}
}

func TestPortalDevicePageLeadsWithTheSubscription(t *testing.T) {
	h := testPortal(t)
	_, body := fetch(t, h, "/c/"+devTok)
	for _, want := range []string{
		"http://10.20.0.10:9001/c/" + devTok + "/mihomo", "/c/" + devTok + "/mihomo/qr",
		"FlClash", "ClashMetaForAndroid", "ClashX Meta", "Clash Verge Rev", "TUN", "separate link", "delete the file profile",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "Set up a second device") {
		t.Error("the page still teaches installing one key on two devices")
	}
}

// The subscription and the AmneziaWG .conf carry the same key, so running both
// apps at once makes the server answer whichever spoke last — the connection
// breaks every few seconds. And a subscription update
// replaces the profile whole, so edits made inside it are lost. The page says
// both before the person finds out.
func TestPortalDevicePageWarnsAboutTwoAppsAndLocalEdits(t *testing.T) {
	h := testPortal(t)
	_, body := fetch(t, h, "/c/"+devTok)
	for _, want := range []string{"Turn it off once the new app connects", "never alongside", "Edits made inside it are lost", "Merge"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

// The card's padding must sit inside its width: content-box made it 56px wider
// than min(420px, 92vw), and a 390px phone scrolled sideways.
func TestPortalCardFitsAPhone(t *testing.T) {
	i := strings.Index(portalCSS, ".card {")
	if i < 0 {
		t.Fatal("no .card rule")
	}
	rule := portalCSS[i : i+strings.Index(portalCSS[i:], "}")]
	if !strings.Contains(rule, "box-sizing:border-box") || !strings.Contains(rule, "calc(100vw - 32px)") {
		t.Errorf(".card must be border-box and no wider than the viewport minus body's gutters, got: %s", rule)
	}
}

func TestPortalSubscriptionQRIsTheURLNotTheConfig(t *testing.T) {
	h := testPortal(t)
	res, body := fetch(t, h, "/c/"+devTok+"/mihomo/qr")
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("qr: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if len(body) > 20000 {
		t.Errorf("QR of a URL should be small; %d bytes suggests the profile was encoded", len(body))
	}
}

// TestPortalNeverLogsThePrivateKey covers both a SUCCESSFUL fetch — where the
// response body genuinely carries the key, so there is something for a stray
// log statement to leak — and an error AFTER the key has already been read from
// the store (garbage AWG params fail only deep inside the mihomo render, well
// after findClient loaded the credential). A test that only forced the garbage
// path would hold trivially: nothing in this codebase formats a WGClient into an
// error string, so that half proves nothing on its own.
func TestPortalNeverLogsThePrivateKey(t *testing.T) {
	h := testPortal(t)
	var buf bytes.Buffer
	h.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if res, body := fetch(t, h, "/c/"+devTok+"/mihomo"); res.StatusCode != http.StatusOK ||
		!strings.Contains(body, "Y2xpZW50LXByaXZhdGUta2V5LTAwMDAwMDAwMDA=") {
		t.Fatalf("setup: expected a successful profile carrying the key, got %d:\n%s", res.StatusCode, body)
	}

	src := h.src.(stubSource)
	src.spec.Master.ClientWG.AWG = &domain.AWGParams{} // invalid ⇒ render error, after the key was already read
	h.src = src
	_, _ = fetch(t, h, "/c/"+devTok+"/mihomo")

	if strings.Contains(buf.String(), "Y2xpZW50LXByaXZhdGUta2V5LTAwMDAwMDAwMDA=") {
		t.Errorf("private key reached the log:\n%s", buf.String())
	}
}

// A VLESS-only device asking for the AWG-only routes gets ErrNoAWG, which is not
// the caller's fault — see clientcfg.ErrNoAWG's own doc — so it must never be
// charged to the rate limiter: grinding /config against such a device must never
// lock out the shared source IP.
func TestPortalConfigOnAVLESSOnlyDeviceNeverChargesTheLimiter(t *testing.T) {
	h := testPortal(t)
	const vlessTok = "abcdef0123456789abcdef0123456789"
	src := h.src.(stubSource)
	src.devices[vlessTok] = domain.ClientDevice{ID: "d2", Token: vlessTok, Name: "phone-vless",
		Credentials: []domain.DeviceCredential{{Kind: domain.CredentialVLESS, MasterID: "master-xa-1", Ref: "v1"}}}
	src.vless = []domain.VLESSClient{{Name: "v1", UUID: "11111111-1111-4111-8111-111111111111", ShortID: "abcd1234"}}
	h.src = src

	for i := 0; i < 20; i++ {
		if res, _ := fetch(t, h, "/c/"+vlessTok+"/config"); res.StatusCode != http.StatusNotFound {
			t.Fatalf("device with no AWG credential: /config #%d = %d, want 404", i, res.StatusCode)
		}
	}
	if res, _ := fetch(t, h, "/c/"+devTok+"/config"); res.StatusCode == http.StatusTooManyRequests {
		t.Error("a VLESS-only device grinding /config locked out the shared IP limiter")
	}
}

// ProfileFileName is dev.Name + ".yaml", and a device's name is not bounded here
// by domain.ValidClientName the way a WGClient's own name is — one synthesised
// from an imported credential inherits whatever that import gave it. A hostile
// name must not break the header's quoting or inject a header line of its own.
func TestPortalProfileFilenameEscapesAHostileDeviceName(t *testing.T) {
	h := testPortal(t)
	src := h.src.(stubSource)
	dev := src.devices[devTok]
	dev.Name = "laptop\" ; x=1\r\nSet-Cookie: evil"
	src.devices[devTok] = dev
	h.src = src

	res, _ := fetch(t, h, "/c/"+devTok+"/mihomo")
	cd := res.Header.Get("Content-Disposition")
	if strings.ContainsAny(cd, "\r\n") {
		t.Fatalf("Content-Disposition carries a raw CR/LF: %q", cd)
	}
	// Exactly the two quotes the "filename=" wrapper itself contributes — the
	// device name's own embedded quote must not have survived to open a third.
	if n := strings.Count(cd, `"`); n != 2 {
		t.Errorf("Content-Disposition quoting is broken by the embedded quote (found %d quote chars): %q", n, cd)
	}
	// One quoted filename, then the RFC 6266 extended form — which carries no
	// quotes at all, so the count above still holds.
	if !strings.HasPrefix(cd, `attachment; filename="`) ||
		!strings.Contains(cd, `.yaml"; filename*=UTF-8''`) || !strings.HasSuffix(cd, ".yaml") {
		t.Errorf("Content-Disposition is not a single well-formed quoted-string: %q", cd)
	}
}
