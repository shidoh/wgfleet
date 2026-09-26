package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/portal"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

type fakeDevices struct {
	devs    map[string]*domain.ClientDevice
	calls   []string
	attachE error
}

func newFakeDevices() *fakeDevices {
	return &fakeDevices{devs: map[string]*domain.ClientDevice{
		"d1": {ID: "d1", Token: "0123456789abcdef0123456789abcdef", Name: "alice-phone", CreatedAt: time.Now(),
			Credentials: []domain.DeviceCredential{{Kind: domain.CredentialAWG, MasterID: "master-xa-1", Ref: "a", Name: "laptop"}}},
	}}
}

func (f *fakeDevices) Masters() []string { return []string{"master-xa-1"} }
func (f *fakeDevices) ListDevices(context.Context) ([]domain.ClientDevice, error) {
	var out []domain.ClientDevice
	for _, d := range f.devs {
		out = append(out, *d)
	}
	return out, nil
}
func (f *fakeDevices) GetDevice(_ context.Context, id string) (domain.ClientDevice, error) {
	if d, ok := f.devs[id]; ok {
		return *d, nil
	}
	return domain.ClientDevice{}, store.ErrNotFound
}
func (f *fakeDevices) CreateDevice(_ context.Context, name string) (domain.ClientDevice, error) {
	f.calls = append(f.calls, "create:"+name)
	d := &domain.ClientDevice{ID: "d-" + name, Token: "ffffffffffffffffffffffffffffffff", Name: name}
	f.devs[d.ID] = d
	return *d, nil
}
func (f *fakeDevices) RenameDevice(_ context.Context, id, name string) error {
	f.calls = append(f.calls, "rename:"+id+":"+name)
	return nil
}
func (f *fakeDevices) RotateDeviceToken(_ context.Context, id string) (domain.ClientDevice, error) {
	f.calls = append(f.calls, "rotate:"+id)
	return *f.devs[id], nil
}
func (f *fakeDevices) DeleteDevice(_ context.Context, id string) error {
	f.calls = append(f.calls, "delete:"+id)
	return nil
}
func (f *fakeDevices) AttachCredential(_ context.Context, k domain.CredentialKind, m, ref, dev string) error {
	f.calls = append(f.calls, "attach:"+string(k)+":"+m+":"+ref+":"+dev)
	return f.attachE
}
func (f *fakeDevices) DetachCredential(_ context.Context, k domain.CredentialKind, m, ref string) error {
	f.calls = append(f.calls, "detach:"+string(k)+":"+m+":"+ref)
	return nil
}
func (f *fakeDevices) IssueWGClientForDevice(_ context.Context, m, dev string) (domain.WGClient, error) {
	f.calls = append(f.calls, "issue-awg:"+m+":"+dev)
	return domain.WGClient{ID: "new"}, nil
}
func (f *fakeDevices) IssueVLESSClientForDevice(_ context.Context, m, dev string) (domain.VLESSClient, error) {
	f.calls = append(f.calls, "issue-vless:"+m+":"+dev)
	return domain.VLESSClient{Name: "n"}, nil
}
func (f *fakeDevices) ClientMasterMeta(context.Context, string) (domain.ClientMasterMeta, error) {
	return domain.ClientMasterMeta{Resolvers: []string{"10.80.0.1"}, ClientPool: "10.80.0.0/24", MgmtCIDRs: []string{"10.20.0.0/16"}}, nil
}

// deviceHandler is the real WG-clients fixture from wgclients_test.go
// (wgClientHandler + managedMasterSpec, master "master-xa-1"): credential "a"
// attached to d1, "spare" unattached with a live personal link, "old" unattached
// with its link retired.
func deviceHandler(t *testing.T) (*Handler, *fakeDevices) {
	t.Helper()
	clients := []domain.WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.2/32", PublicKey: "pub-a", Enabled: true, LegacyLinkRetired: true,
			PrivateKey: "cHJpdi1hLTAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="},
		{ID: "paused", Name: "paused", Address: "10.80.0.5/32", PublicKey: "pub-p", Enabled: false, LegacyLinkRetired: true,
			PrivateKey: "cHJpdi1wLTAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="},
		{ID: "spare", Name: "spare", Address: "10.80.0.3/32", PublicKey: "pub-s", Enabled: true},
		{ID: "old", Name: "old", Address: "10.80.0.4/32", PublicKey: "pub-o", Enabled: true, LegacyLinkRetired: true},
	}
	h, _ := wgClientHandler(t, managedMasterSpec(), &clients)
	f := newFakeDevices()
	h.SetDevices(f)
	h.SetPortalBase("http://10.20.0.10:9001")
	return h, f
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

// getWithCookies carries the flash cookie a POST set into the next GET.
func getWithCookies(t *testing.T, h *Handler, path string, cookies []*http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(sessionCookieFor(t, h))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestDevicesListShowsSubscriptionLinks(t *testing.T) {
	h, _ := deviceHandler(t)
	res, body := get(t, h, "/devices")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if !strings.Contains(body, "alice-phone") ||
		!strings.Contains(body, "http://10.20.0.10:9001/c/0123456789abcdef0123456789abcdef/mihomo") {
		t.Errorf("list page:\n%s", body)
	}
}

func TestDeviceCreateIssuesAndAttaches(t *testing.T) {
	h, f := deviceHandler(t)
	res := postWith(t, h, "/devices/create", url.Values{"name": {"bob-laptop"},
		"awg_master-xa-1": {"new"}, "vless_master-xa-1": {"new"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d", res.StatusCode)
	}
	want := "create:bob-laptop,issue-awg:master-xa-1:d-bob-laptop,issue-vless:master-xa-1:d-bob-laptop"
	if got := strings.Join(f.calls, ","); got != want {
		t.Errorf("calls = %s, want %s", got, want)
	}
	if loc := res.Header.Get("Location"); loc != "/devices/d-bob-laptop" {
		t.Errorf("redirect = %s", loc)
	}
}

func TestAttachingACredentialWithALiveLinkAsksFirst(t *testing.T) {
	h, f := deviceHandler(t)
	form := url.Values{"name": {"x"}, "awg_master-xa-1": {"spare"}}
	res := postWith(t, h, "/devices/create", form)
	if res.StatusCode != http.StatusOK || len(f.calls) != 0 {
		t.Fatalf("no confirmation: status %d calls %v", res.StatusCode, f.calls)
	}
	body := readBody(t, res)
	if !strings.Contains(body, "personal link") || !strings.Contains(body, `name="awg_master-xa-1" value="spare"`) {
		t.Errorf("confirmation page does not warn or does not carry the form:\n%s", body)
	}
	form.Set("confirm", "1")
	postWith(t, h, "/devices/create", form)
	if got := strings.Join(f.calls, ","); got != "create:x,attach:awg:master-xa-1:spare:d-x" {
		t.Errorf("calls after confirm = %s", got)
	}
}

func TestDevicePageOffersOnlyUnattachedCredentials(t *testing.T) {
	h, _ := deviceHandler(t)
	_, body := get(t, h, "/devices/d1")
	if !strings.Contains(body, `value="spare"`) || !strings.Contains(body, `value="old"`) {
		t.Error("unattached credentials are not offered")
	}
	if strings.Contains(body, `<option value="a"`) {
		t.Error("an attached credential is offered for attaching")
	}
}

func TestDeviceAttachRefusalIsReadable(t *testing.T) {
	h, f := deviceHandler(t)
	f.attachE = store.ErrDeviceSlotTaken
	res := postWith(t, h, "/devices/d1/attach", url.Values{"kind": {"awg"}, "master": {"master-xa-1"}, "ref": {"old"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d", res.StatusCode)
	}
	if body := getWithCookies(t, h, "/devices/d1", res.Cookies()); !strings.Contains(body, "already has an AmneziaWG credential on master-xa-1") {
		t.Errorf("no readable flash:\n%s", body)
	}
}

func TestDeviceDestructiveActionsConfirmFirst(t *testing.T) {
	h, f := deviceHandler(t)
	for _, action := range []string{"rotate", "delete"} {
		if res := postWith(t, h, "/devices/d1/"+action, url.Values{}); res.StatusCode != http.StatusOK {
			t.Errorf("%s without confirm: status %d, want the confirmation page", action, res.StatusCode)
		}
	}
	res := postWith(t, h, "/devices/d1/detach", url.Values{"kind": {"awg"}, "master": {"master-xa-1"}, "ref": {"a"}})
	if res.StatusCode != http.StatusOK {
		t.Errorf("detach without confirm: status %d", res.StatusCode)
	}
	if len(f.calls) != 0 {
		t.Errorf("acted without confirmation: %v", f.calls)
	}
	postWith(t, h, "/devices/d1/rotate", url.Values{"confirm": {"1"}})
	if len(f.calls) != 1 || f.calls[0] != "rotate:d1" {
		t.Errorf("calls = %v", f.calls)
	}
}

func TestDeviceDeleteConfirmationTellsTheTruth(t *testing.T) {
	h, _ := deviceHandler(t)
	body := readBody(t, postWith(t, h, "/devices/d1/delete", url.Values{}))
	for _, want := range []string{"not revoked", "do not come back"} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation missing %q", want)
		}
	}
}

func TestDevicePOSTsRequireCSRFAndSession(t *testing.T) {
	h, f := deviceHandler(t)
	for _, path := range []string{"/devices/create", "/devices/d1/rename", "/devices/d1/rotate",
		"/devices/d1/delete", "/devices/d1/attach", "/devices/d1/detach"} {
		// A session, no CSRF token: the handler's own guard refuses.
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("name=evil&confirm=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(sessionCookieFor(t, h))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without CSRF: %d", path, rec.Code)
		}
		// A CSRF token, no session: ServeHTTP sends it to /login first.
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader("name=evil&confirm=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-CSRF-Token", h.csrf)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Errorf("%s without a session: %d → %s", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("acted on a forged request: %v", f.calls)
	}
}

func TestDevicesHiddenWithoutManager(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	if res, _ := get(t, h, "/devices"); res.StatusCode != http.StatusNotFound {
		t.Errorf("status %d", res.StatusCode)
	}
}

func TestWGCredentialPageNamesItsDevice(t *testing.T) {
	h, _ := deviceHandler(t)
	_, body := get(t, h, "/nodes/master-xa-1/wg-clients")
	if !strings.Contains(body, `href="/devices/d1"`) {
		t.Error("credential card does not link its device")
	}
	for _, retired := range []string{"http://10.20.0.10:9001/c/a\"", "http://10.20.0.10:9001/c/old"} {
		if strings.Contains(body, retired) {
			t.Errorf("a retired personal link is still shown: %s", retired)
		}
	}
	if !strings.Contains(body, "http://10.20.0.10:9001/c/spare") {
		t.Error("a live personal link disappeared")
	}
}

// portalOverPanel is the portal fed from the panel's own profile source plus the
// fake registry's token lookup — so the comparison below runs both routes over
// ONE set of facts.
type portalOverPanel struct {
	deviceProfileSource
	f *fakeDevices
}

func (p portalOverPanel) GetDeviceByToken(_ context.Context, tok string) (domain.ClientDevice, error) {
	for _, d := range p.f.devs {
		if d.Token == tok {
			return *d, nil
		}
	}
	return domain.ClientDevice{}, store.ErrNotFound
}

func (p portalOverPanel) FindUnattachedWGClient(context.Context, string) (string, domain.WGClient, error) {
	return "", domain.WGClient{}, store.ErrNotFound
}

func TestDeviceProfileDownloadIsThePortalProfile(t *testing.T) {
	h, f := deviceHandler(t)
	res, file := get(t, h, "/devices/d1/profile.yaml")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, file)
	}
	if res.Header.Get("Cache-Control") != "no-store" ||
		res.Header.Get("Content-Disposition") != `attachment; filename="alice-phone.yaml"` ||
		res.Header.Get("Content-Type") != "text/yaml; charset=utf-8" {
		t.Errorf("headers = %v", res.Header)
	}
	ph, err := portal.New(portalOverPanel{deviceProfileSource{clientSource{h}}, f}, f.Masters, portal.Options{Bind: "10.20.0.10:9001"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/c/0123456789abcdef0123456789abcdef/mihomo", nil)
	req.RemoteAddr = "10.80.0.2:51820"
	rec := httptest.NewRecorder()
	ph.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != file {
		t.Errorf("the file and the subscription differ (%d):\nfile:\n%s\nsubscription:\n%s", rec.Code, file, rec.Body.String())
	}
}

func TestDeviceProfileDownloadRefusesADeviceWithNothingActive(t *testing.T) {
	h, f := deviceHandler(t)
	f.devs["d2"] = &domain.ClientDevice{ID: "d2", Token: "22222222222222222222222222222222", Name: "old",
		Credentials: []domain.DeviceCredential{{Kind: domain.CredentialAWG, MasterID: "master-xa-1", Ref: "paused"}}}
	f.devs["d3"] = &domain.ClientDevice{ID: "d3", Token: "33333333333333333333333333333333", Name: "empty"}
	for _, id := range []string{"d2", "d3"} {
		res, body := get(t, h, "/devices/"+id+"/profile.yaml")
		if res.StatusCode != http.StatusForbidden || strings.Contains(body, "private-key") {
			t.Errorf("%s: status %d, body %q", id, res.StatusCode, body)
		}
	}
}

func TestDeviceProfileDownloadNeedsASession(t *testing.T) {
	h, _ := deviceHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/devices/d1/profile.yaml", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" || strings.Contains(rec.Body.String(), "private-key") {
		t.Errorf("without a session: %d → %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDevicePageOffersTheProfileFile(t *testing.T) {
	h, _ := deviceHandler(t)
	if _, body := get(t, h, "/devices/d1"); !strings.Contains(body, `href="/devices/d1/profile.yaml"`) {
		t.Error("no Download profile (.yaml) button")
	}
}
