package portal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// stubSource is a fixed one-master, two-credential world.
type stubSource struct {
	node    domain.Node
	spec    domain.NodeSpec
	clients []domain.WGClient
}

func (s stubSource) GetNode(_ context.Context, id string) (domain.Node, error) {
	if id != s.node.ID {
		return domain.Node{}, store.ErrNotFound
	}
	return s.node, nil
}

func (s stubSource) RenderNodeSpec(context.Context, string) (domain.NodeSpec, error) {
	return s.spec, nil
}

func (s stubSource) ListWGClients(context.Context, string) ([]domain.WGClient, error) {
	return s.clients, nil
}

// No reserve doors in this world: the portal serves the master's own config, and
// the lifeline listing is exercised where it is built (clientcfg).
func (s stubSource) LifelineExits(context.Context) ([]string, error) { return nil, nil }

func (s stubSource) ExitEndpointHost(context.Context, string) (string, error) { return "", nil }

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
	}
	h, err := New(src, func() []string { return []string{"master-xa-1"} })
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
	res, body := fetch(t, h, "/c/aaaabbbbccccdddd")
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

	res, cfg := fetch(t, h, "/c/aaaabbbbccccdddd/config")
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

	res, png := fetch(t, h, "/c/aaaabbbbccccdddd/qr")
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
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/c/aaaabbbbccccdddd", nil)
		req.RemoteAddr = "10.80.0.2:51820"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("%s on a profile succeeded", method)
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
	res, _ := fetch(t, h, "/c/aaaabbbbccccdddd")
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
	res, body := fetch(t, h, "/c/aaaabbbbccccdddd")
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

	res, body := fetch(t, h, "/c/aaaabbbbccccdddd")
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
		if _, _ = fetch(t, h, "/c/aaaabbbbccccdddd"); false {
			return
		}
	}
	h.src = stubSource{node: h.src.(failingSource).node, spec: h.src.(failingSource).spec, clients: h.src.(failingSource).clients}
	if res, _ := fetch(t, h, "/c/aaaabbbbccccdddd"); res.StatusCode != http.StatusOK {
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
	_, body := fetch(t, h, "/c/aaaabbbbccccdddd")

	notice := body[strings.Index(body, `class="notice"`):]
	notice = notice[:strings.Index(notice, "</p>")]
	if !strings.Contains(notice, "not the ordinary WireGuard app") {
		t.Errorf("the wrong-app warning is not in the notice block:\n%s", notice)
	}
	if strings.Contains(body, "title=\"This profile uses") {
		t.Error("the explanation is still hidden in a tooltip")
	}
	// The QR belongs on the page, not in a tab showing a bare image of a key.
	if !strings.Contains(body, `<img class="qr-img"`) {
		t.Error("the QR is not rendered in the page")
	}
	if strings.Contains(body, `href="/c/aaaabbbbccccdddd/qr" target="_blank"`) {
		t.Error("the QR still opens as a bare image in a new tab")
	}
}

// Both portal pages are the same card and must not drift apart again.
func TestPortalPagesShareOneStylesheet(t *testing.T) {
	h := testPortal(t)
	_, ok := fetch(t, h, "/c/aaaabbbbccccdddd")
	_, bad := fetch(t, h, "/c/ffffffffffffffff")
	for _, marker := range []string{"align-items:start", ".card { width:min(420px, 92vw)"} {
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
