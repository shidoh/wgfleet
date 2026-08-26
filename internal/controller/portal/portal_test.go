package portal

import (
	"context"
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
	for _, want := range []string{"laptop", "10.80.0.2/32", "203.0.113.1:443", "Show QR", "Download"} {
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
	if strings.Contains(body, "Download") {
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
