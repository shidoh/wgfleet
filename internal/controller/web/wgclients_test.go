package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// managedMasterSpec is a master whose client interface the agent owns.
func managedMasterSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			ClientWG: &domain.ClientWGSpec{
				ListenPort:    443,
				AddressPool:   "10.80.0.0/24",
				ServerAddress: "10.80.0.1",
				MTU:           1360,
				DNS:           []string{"10.80.0.1"},
				AllowedIPs:    []string{"0.0.0.0/0"},
			},
		},
	}
}

func wgClientHandler(t *testing.T, spec domain.NodeSpec, clients *[]domain.WGClient) (*Handler, domain.Node) {
	t.Helper()
	h, st := newTestHandler(t, stubRenderer{spec: spec, wgClients: clients})
	node := domain.Node{
		ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
		PublicIP: "203.0.113.1", State: domain.StateReady,
		ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
	}
	seed(t, st, node)
	return h, node
}

func TestWGClientsPageListsCredentials(t *testing.T) {
	clients := []domain.WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a",
			PrivateKey: "SECRET-LAPTOP-KEY", Enabled: true, CreatedAt: time.Now().Add(-48 * time.Hour)},
		{ID: "b", Name: "phone", Address: "10.80.0.3/32", PublicKey: "pub-b",
			PrivateKey: "SECRET-PHONE-KEY", Enabled: false},
	}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	res, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	for _, want := range []string{"laptop", "10.80.0.2/32", "phone", "muted", "203.0.113.1:443", "Download .conf"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// The listing must never carry a private key: the page is cached by browsers,
	// logged by proxies and screenshotted by operators.
	for _, secret := range []string{"SECRET-LAPTOP-KEY", "SECRET-PHONE-KEY"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the client list leaked a private key (%s)", secret)
		}
	}
}

// Before the handover the page still works — that is the migration order: issue
// and import first, flip the knob second.
func TestWGClientsPageBeforeHandover(t *testing.T) {
	var clients []domain.WGClient
	h, _ := wgClientHandler(t, domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}, &clients)

	res, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "wg-easy still owns") {
		t.Errorf("page does not explain the pre-handover state:\n%s", body)
	}
	if strings.Contains(body, "Download .conf") {
		t.Error("page offers configs while the interface is not ours yet")
	}
}

func TestWGClientIssueAndRevoke(t *testing.T) {
	var clients []domain.WGClient
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	if code := postForm(t, h, "/nodes/master-xa-1/wg-clients/issue", url.Values{"name": {"laptop"}}).Code; code != http.StatusSeeOther {
		t.Fatalf("issue status = %d", code)
	}
	if len(clients) != 1 || clients[0].Name != "laptop" {
		t.Fatalf("clients after issue = %+v", clients)
	}

	if res := post(t, h, "/nodes/master-xa-1/wg-clients/id-laptop/revoke"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d", res.StatusCode)
	}
	if len(clients) != 0 {
		t.Fatalf("clients after revoke = %+v", clients)
	}
}

func TestWGClientIssueRejectsBadName(t *testing.T) {
	var clients []domain.WGClient
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	if code := postForm(t, h, "/nodes/master-xa-1/wg-clients/issue", url.Values{"name": {"bad name!"}}).Code; code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect carrying the error", code)
	}
	if len(clients) != 0 {
		t.Fatalf("a malformed name was issued anyway: %+v", clients)
	}
}

func TestWGClientMuteUnmuteAndRename(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	if res := post(t, h, "/nodes/master-xa-1/wg-clients/a/mute"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("mute status = %d", res.StatusCode)
	}
	if clients[0].Enabled {
		t.Fatal("mute did not take")
	}
	if res := post(t, h, "/nodes/master-xa-1/wg-clients/a/unmute"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("unmute status = %d", res.StatusCode)
	}
	if !clients[0].Enabled {
		t.Fatal("unmute did not take")
	}
	if code := postForm(t, h, "/nodes/master-xa-1/wg-clients/a/rename", url.Values{"name": {"work-laptop"}}).Code; code != http.StatusSeeOther {
		t.Fatalf("rename status = %d", code)
	}
	if clients[0].Name != "work-laptop" || clients[0].ID != "a" || clients[0].PublicKey != "pub-a" {
		t.Fatalf("rename altered more than the label: %+v", clients[0])
	}
}

// Mutating endpoints must be POST-only and CSRF-guarded like every other action.
func TestWGClientActionsAreGuarded(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	req := httptest.NewRequest(http.MethodPost, "/nodes/master-xa-1/wg-clients/a/revoke", nil)
	req.AddCookie(sessionCookieFor(t, h))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode == http.StatusSeeOther {
		t.Fatal("a request without the CSRF token was accepted")
	}
	if len(clients) != 1 {
		t.Fatal("the unguarded request revoked a credential")
	}
}

func TestWGClientConfigDownload(t *testing.T) {
	clients := []domain.WGClient{{
		ID: "a", Name: "laptop", Address: "10.80.0.2/32",
		PublicKey: "pub-a", PrivateKey: "Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=", Enabled: true,
	}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	res, body := get(t, h, "/nodes/master-xa-1/wg-clients/a/config")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", res.StatusCode, body)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=",
		"Address = 10.80.0.2/32",
		"Endpoint = 203.0.113.1:443",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("config missing %q:\n%s", want, body)
		}
	}
	if got := res.Header.Get("Content-Disposition"); !strings.Contains(got, `"laptop.conf"`) {
		t.Errorf("Content-Disposition = %q", got)
	}
	// A config is a credential: it must not be cacheable.
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestWGClientQR(t *testing.T) {
	clients := []domain.WGClient{{
		ID: "a", Name: "laptop", Address: "10.80.0.2/32",
		PublicKey: "pub-a", PrivateKey: "Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=", Enabled: true,
	}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	res, body := get(t, h, "/nodes/master-xa-1/wg-clients/a/qr")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", res.StatusCode, body)
	}
	if got := res.Header.Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type = %q", got)
	}
	if !strings.HasPrefix(body, "\x89PNG") {
		t.Fatal("QR endpoint did not return a PNG")
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// The live columns come from the node's own status report, so a page rendered
// before the first report must degrade rather than fail.
func TestWGClientsPageShowsReportedPeers(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, st := newTestHandler(t, stubRenderer{spec: managedMasterSpec(), wgClients: &clients})
	seed(t, st, domain.Node{
		ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
		PublicIP: "203.0.113.1", State: domain.StateReady,
		ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
	})

	_, before := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(before, "not reported yet") {
		t.Errorf("page before the first status report:\n%s", before)
	}

	if err := st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: "master-xa-1", State: domain.StateReady,
		ClientPeers: []domain.ClientPeerStatus{{
			PublicKey: "pub-a", LastHandshake: time.Now().Add(-30 * time.Second),
			ReceivedBytes: 5 << 20, SentBytes: 2 << 20,
		}},
	}); err != nil {
		t.Fatalf("record status: %v", err)
	}
	_, after := get(t, h, "/nodes/master-xa-1/wg-clients")
	for _, want := range []string{"30s ago", "online", "5.0 MiB", "2.0 MiB"} {
		if !strings.Contains(after, want) {
			t.Errorf("page missing %q after the status report:\n%s", want, after)
		}
	}
}

// The portal is only reachable if the operator can see the link. Without it the
// whole self-service surface is dead on arrival, however well it works.
func TestWGClientsPageShowsThePortalLink(t *testing.T) {
	clients := []domain.WGClient{{ID: "abc123", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)
	h.SetPortalBase("http://10.80.0.1:8080/")

	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(body, "http://10.80.0.1:8080/c/abc123") {
		t.Fatalf("page does not show the client's self-service link:\n%s", body)
	}
}

// With no portal URL configured the page must show nothing rather than a guessed
// address the operator would hand out and that would not work.
func TestWGClientsPageHidesTheLinkWithoutAPortal(t *testing.T) {
	clients := []domain.WGClient{{ID: "abc123", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if strings.Contains(body, "/c/abc123") {
		t.Fatalf("page invented a portal link with no portal configured:\n%s", body)
	}
}

// A duplicate name is the mistake an operator actually makes; it must not
// surface as a SQLite constraint string.
func TestWGClientIssueReportsADuplicateNamePlainly(t *testing.T) {
	err := clientActionError(errors.New(`add wg client "laptop": constraint failed: UNIQUE constraint failed: client_wg_credentials.name (2067)`), "laptop")
	if !strings.Contains(err.Error(), "already exists on this master") {
		t.Fatalf("duplicate-name error = %q, want a sentence an operator can act on", err)
	}
	if strings.Contains(err.Error(), "constraint") {
		t.Fatalf("the SQLite constraint text reached the operator: %q", err)
	}
}

// A full pool must say what to do about it.
func TestWGClientIssueReportsAFullPool(t *testing.T) {
	err := clientActionError(fmt.Errorf("issue: %w", domain.ErrPoolExhausted), "laptop")
	for _, want := range []string{"pool is full", "revoke", "address_pool"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("pool-exhausted error = %q, want it to mention %q", err, want)
		}
	}
}
