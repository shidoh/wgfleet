package web

import (
	"context"
	"encoding/base64"
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

	// Before the first report the page must say so in the head chip AND in the
	// detail row, and must NOT claim the client never connected — that is a
	// different fault with a different fix (see peerState).
	_, before := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(before, "not reported") {
		t.Errorf("page before the first status report:\n%s", before)
	}
	if strings.Contains(before, "never connected") {
		t.Errorf("page conflated an unreported peer with one that never connected:\n%s", before)
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

// The page shows handshake ages and an "online" badge, which mean nothing on a
// frozen page: a stale green badge reads as "connected" minutes after the person
// dropped. It must refresh itself like every other live surface in the UI.
func TestWGClientsPageRefreshesItself(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(body, "hx-trigger=") {
		t.Fatalf("the credentials panel never refreshes:\n%s", body)
	}
	if !strings.Contains(body, "visibilityState") {
		t.Error("a backgrounded tab would keep polling")
	}
}

// An address collision needs the opposite advice from a name collision:
// renaming does not free an address.
func TestClientActionErrorTellsCollisionsApart(t *testing.T) {
	nameErr := clientActionError(errors.New("add wg client: constraint failed: UNIQUE constraint failed: client_wg_credentials.name (2067)"), "laptop")
	if !strings.Contains(nameErr.Error(), "pick a different name") {
		t.Errorf("name collision = %q", nameErr)
	}
	addrErr := clientActionError(errors.New("add wg client: constraint failed: UNIQUE constraint failed: client_wg_credentials.address (2067)"), "laptop")
	if strings.Contains(addrErr.Error(), "pick a different name") {
		t.Errorf("an address collision was blamed on the name: %q", addrErr)
	}
	if !strings.Contains(addrErr.Error(), "address is already taken") {
		t.Errorf("address collision = %q", addrErr)
	}
}

// Revoke destroys a person's access permanently and used to sit 10px from the
// reversible action, guarded only by a confirm() whose default button is OK.
// It is now gated behind Mute the way node.html gates Delete behind Decommission.
func TestWGClientRevokeIsGatedBehindMute(t *testing.T) {
	clients := []domain.WGClient{
		{ID: "a", Name: "live-one", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true},
		{ID: "b", Name: "muted-one", Address: "10.80.0.3/32", PublicKey: "pub-b", Enabled: false},
	}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)
	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")

	// Sliced per card rather than anchored on an aria-label: that label duplicated
	// the button's own visible text and has been removed.
	live := card(body, "a")
	if !strings.Contains(live, "disabled") {
		t.Errorf("Revoke is offered on an enabled client without muting it first:\n%s", live)
	}
	muted := card(body, "b")
	if strings.Contains(muted, "disabled") {
		t.Errorf("Revoke is refused on a muted client, so there is no way to revoke at all:\n%s", muted)
	}
}

// Every client always carries exactly one state chip. Absence used to carry
// meaning: an enabled client that was simply offline rendered no badge at all
// and looked identical to a card nobody had parsed yet.
func TestWGClientsAlwaysShowAState(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)
	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(body, "subbadge state-") {
		t.Errorf("no state chip rendered for a client:\n%s", body)
	}
}

// A node that is not a master is a dead end, not a failure. Rendering it in the
// red alert treatment reserved for real breakage tells the operator something
// broke when nothing did — and leaves them with no way onward.
func TestWGClientsPageOnANonMasterIsNotAnError(t *testing.T) {
	clients := []domain.WGClient{}
	h, _ := wgClientHandler(t, domain.NodeSpec{Role: domain.RoleExit}, &clients)
	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")

	if strings.Contains(body, "error-note") {
		t.Errorf("a non-master node is shown as a failure:\n%s", body)
	}
	if !strings.Contains(body, "section-link") {
		t.Errorf("a non-master node is a dead end with no way back:\n%s", body)
	}
	for _, unwanted := range []string{"issue-form", "panel-credentials"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("a non-master node still renders %q:\n%s", unwanted, body)
		}
	}
}

// Nothing is being polled for while wg-easy owns the leg, so a pulsing LIVE chip
// over the list is a lie — and Mute/handshake rows describe an interface these
// credentials are not on yet.
func TestWGClientsPageBeforeHandoverIsNotLive(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}, &clients)
	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")

	if strings.Contains(body, ">LIVE") {
		t.Errorf("the list claims to be live before the handover:\n%s", body)
	}
	if !strings.Contains(body, "Not in force yet") {
		t.Errorf("the list does not say the credentials are not in force yet:\n%s", body)
	}
}

// section returns the fragment of body around the first occurrence of marker,
// so an assertion about one card's button cannot accidentally pass on another's.
func section(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	start := i - 400
	if start < 0 {
		start = 0
	}
	end := i + 200
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// The 10-second poll must never be able to delete the thing it is refreshing.
//
// It used to re-fetch the whole page with hx-select=".panel-credentials". Two of
// this page's three branches — the failure one and the not-a-master one — render
// no such element, so a transient store error made the selector match nothing;
// htmx swapped in the empty string and outerHTML removed the panel, the LIVE chip
// and the poll itself. HTTP 200, no error on screen (its text was in the body
// hx-select discarded), and the client list simply gone until a manual reload.
func TestWGClientsPanelAnswers204RatherThanAnEmptyBody(t *testing.T) {
	clients := []domain.WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true},
	}
	// The healthy poll returns the panel, and only the panel.
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)
	res, body := get(t, h, "/nodes/master-xa-1/wg-clients/panel")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "panel-credentials") || !strings.Contains(body, "laptop") {
		t.Fatalf("the fragment is not the credentials panel:\n%s", body)
	}
	if strings.Contains(body, "<html") || strings.Contains(body, "ISSUE CLIENT") {
		t.Errorf("the fragment endpoint rendered the whole page:\n%s", body)
	}

	// Every branch that has no panel to give must answer 204, never a 200 with
	// nothing in it.
	for name, broken := range map[string]stubRenderer{
		"spec render fails": {spec: managedMasterSpec(), err: errors.New("database is locked")},
		"not a master":      {spec: domain.NodeSpec{Role: domain.RoleExit}},
	} {
		t.Run(name, func(t *testing.T) {
			hb, st := newTestHandler(t, broken)
			seed(t, st, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady})
			res, body := get(t, hb, "/nodes/master-xa-1/wg-clients/panel")
			if res.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (htmx leaves the panel alone); body:\n%s", res.StatusCode, body)
			}
			if strings.TrimSpace(body) != "" {
				t.Errorf("204 carried a body:\n%s", body)
			}
		})
	}
}

// A client link that cannot work yet must not be offered.
//
// The portal renders a config on demand from the live spec, so before the
// handover the link resolves to its "this link is no longer working — ask whoever
// sent it for a new one" page. Offering it under the label "send this to the
// person" hands somebody advice that is wrong in a way that makes things worse:
// the natural response is to reissue, which changes nothing.
func TestWGClientLinkIsWithheldUntilItWorks(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}

	// Before the handover: no portal link anywhere on the page.
	h, st := newTestHandler(t, stubRenderer{
		spec:      domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}},
		wgClients: &clients,
	})
	h.portalBase = "http://10.80.0.1:8080"
	seed(t, st, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
		PublicIP: "203.0.113.1", State: domain.StateReady})
	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if strings.Contains(body, "/c/a") {
		t.Error("a client link was offered before the agent owns the interface")
	}
	if !strings.Contains(body, "goes live once") {
		t.Errorf("nothing explains why there is no link yet:\n%s", body)
	}

	// After it: the link is there.
	h2, _ := wgClientHandler(t, managedMasterSpec(), &clients)
	h2.portalBase = "http://10.80.0.1:8080"
	_, body = get(t, h2, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(body, "/c/a") {
		t.Errorf("a working client link was withheld:\n%s", body)
	}
}

// card returns the markup of one client card, from its anchor to the start of the
// next one. The generic section() helper reads BACKWARDS from its marker, which is
// wrong here: a card's controls come after its id, not before it.
func card(body, id string) string {
	start := strings.Index(body, `id="client-`+id+`"`)
	if start < 0 {
		return ""
	}
	rest := body[start+1:]
	if next := strings.Index(rest, `id="client-`); next >= 0 {
		return rest[:next]
	}
	return rest
}

// Issuing a credential must land the operator ON it and say so.
//
// The page's headline action used to end in a bare redirect: the new card is
// inserted alphabetically among all the others, unhighlighted, with its hand-out
// collapsed, so the only evidence anything happened was the counter in the panel
// heading incrementing by one.
func TestIssueLandsOnTheNewCredential(t *testing.T) {
	var clients []domain.WGClient
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	rec := postForm(t, h, "/nodes/master-xa-1/wg-clients/issue", url.Values{
		"csrf_token": {h.csrf}, "name": {"laptop"},
	})
	res := rec.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "#client-") {
		t.Errorf("redirect %q does not anchor the new credential", loc)
	}
	if len(clients) != 1 {
		t.Fatalf("issued %d credentials, want 1", len(clients))
	}
	if !strings.HasSuffix(loc, "#client-"+clients[0].ID) {
		t.Errorf("redirect %q does not point at the credential just issued (%s)", loc, clients[0].ID)
	}

	// And the success is reported, not merely performed.
	var flash *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == flashOKCookie {
			flash = c
		}
	}
	if flash == nil || flash.Value == "" {
		t.Fatal("no success flash was set; the operator gets no confirmation")
	}
	raw, err := base64.RawURLEncoding.DecodeString(flash.Value)
	if err != nil {
		t.Fatalf("flash is not decodable: %v", err)
	}
	if !strings.Contains(string(raw), "laptop") {
		t.Errorf("flash %q does not name what was issued", raw)
	}
}

// Forty "not reported" chips under a pulsing LIVE badge is the page's most
// misleading state: each chip is individually a fact rather than a fault, and in
// aggregate they are one fault nobody names.
func TestWGClientsPageNamesADownInterfaceOnce(t *testing.T) {
	clients := []domain.WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true},
		{ID: "b", Name: "phone", Address: "10.80.0.3/32", PublicKey: "pub-b", Enabled: true},
	}
	h, node := wgClientHandler(t, managedMasterSpec(), &clients)
	if err := h.store.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: node.ID,
		State:  domain.StateDegraded,
		Checks: []domain.HealthCheck{
			{Name: "client-wg-owned", OK: false, Detail: "wg0 is not up"},
		},
	}); err != nil {
		t.Fatalf("put status: %v", err)
	}

	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(body, "client interface is not up") {
		t.Errorf("a down interface is not named anywhere:\n%s", body)
	}
	if !strings.Contains(body, "wg0 is not up") {
		t.Error("the agent's own detail is not passed through")
	}

	// And a healthy interface must not raise it.
	if err := h.store.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: node.ID,
		State:  domain.StateReady,
		Checks: []domain.HealthCheck{{Name: "client-wg-owned", OK: true}},
	}); err != nil {
		t.Fatalf("put status: %v", err)
	}
	if _, body := get(t, h, "/nodes/master-xa-1/wg-clients"); strings.Contains(body, "client interface is not up") {
		t.Error("the banner shows on a healthy interface")
	}
}

// The 10-second poll must not consume the one-shot flashes.
//
// They are read-and-clear and the poll shares the page's view builder, so a tick
// landing between an action's redirect and the render destroyed the message. The
// cookie path is "/", so a clients tab left open would also eat a failure flash
// raised on another page in another tab — the operator clicks Provision, it
// fails, and that page renders as though it had worked.
func TestPollDoesNotEatTheFlash(t *testing.T) {
	clients := []domain.WGClient{{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true}}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)

	req := httptest.NewRequest(http.MethodGet, "/nodes/master-xa-1/wg-clients/panel", nil)
	req.AddCookie(&http.Cookie{Name: flashOKCookie, Value: base64.RawURLEncoding.EncodeToString([]byte("Issued laptop"))})
	req.AddCookie(sessionCookieFor(t, h))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if (c.Name == flashOKCookie || c.Name == flashCookie) && c.MaxAge < 0 {
			t.Fatalf("the poll cleared %q, so the page about to render it shows nothing", c.Name)
		}
	}
}
