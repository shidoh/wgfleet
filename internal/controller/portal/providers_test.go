package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// withVLESS gives the test device a VLESS credential beside its AmneziaWG one:
// the provider form needs a path to fetch the provider over.
func withVLESS(t *testing.T, h *Handler) {
	t.Helper()
	src := h.src.(stubSource)
	d := src.devices[devTok]
	d.Credentials = append(d.Credentials, domain.DeviceCredential{Kind: domain.CredentialVLESS, MasterID: "master-xa-1", Ref: "v1"})
	src.devices[devTok] = d
	src.vless = []domain.VLESSClient{{Name: "v1", UUID: "11111111-1111-4111-8111-111111111111", ShortID: "abcd1234"}}
	src.node.ClientVLESSPublicKey = "pbk1"
	master := *src.spec.Master
	master.ClientVLESS = &domain.ClientVLESSServerSpec{ListenPort: 49443, ServerName: "www.example.org", AllowEmptySNI: true}
	src.spec.Master = &master
	h.src = src
}

func TestPortalProfilePointsAtItsProviderWhenEnabled(t *testing.T) {
	h := testPortal(t)
	withVLESS(t, h)
	h.opts.Providers = true
	res, body := fetch(t, h, "/c/"+devTok+"/mihomo")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", res.StatusCode, body)
	}
	want := "url: http://10.20.0.10:9001/c/" + devTok + "/mihomo/proxies"
	if !strings.Contains(body, "proxy-providers:") || !strings.Contains(body, want) {
		t.Errorf("profile does not point at its provider (%s):\n%s", want, body)
	}
}

func TestPortalProfileStaysInlineByDefault(t *testing.T) {
	h := testPortal(t)
	withVLESS(t, h)
	if _, body := fetch(t, h, "/c/"+devTok+"/mihomo"); strings.Contains(body, "proxy-providers:") {
		t.Errorf("provider form without controller.client_profile_providers:\n%s", body)
	}
}

func TestPortalServesTheAWGProviderAndRecordsIt(t *testing.T) {
	h, rec, _ := fetchPortal(t)
	res, body := fetch(t, h, "/c/"+devTok+"/mihomo/proxies")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", res.StatusCode, body)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q: the body carries a private key", res.Header.Get("Cache-Control"))
	}
	if !strings.HasPrefix(body, "proxies:") || !strings.Contains(body, "master-xa-1-awg") || strings.Contains(body, "proxy-groups") {
		t.Errorf("provider body:\n%s", body)
	}
	if rec.count() != 1 || rec.got[0].Kind != domain.FetchProvider {
		t.Errorf("recorded %+v, want one provider fetch", rec.got)
	}
}

func TestPortalProviderBadTokenIs404(t *testing.T) {
	h := testPortal(t)
	if res, _ := fetch(t, h, "/c/deadbeefdeadbeefdeadbeefdeadbeef/mihomo/proxies"); res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
}

// A core that fetches the profile URL itself uses it as a proxy provider and
// reads only the top-level proxies list; the provider form has none. It gets the
// inline form, apps keep the provider form.
func TestPortalBareCoreGetsTheInlineProfile(t *testing.T) {
	h := testPortal(t)
	withVLESS(t, h)
	h.opts.Providers = true
	for ua, wantProviders := range map[string]bool{
		"clash.meta/v1.19.33":                false,
		"mihomo/1.19.40":                     false,
		"clash-verge/v2.5.10":                true,
		"ClashMetaForAndroid/2.11.36.Meta":   true,
		"FlClash/v0.9.2 clash.meta/v1.19.33": true,
		"":                                   true,
	} {
		req := httptest.NewRequest(http.MethodGet, "/c/"+devTok+"/mihomo", nil)
		req.RemoteAddr = "10.80.0.2:51820"
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if got := strings.Contains(body, "proxy-providers:"); got != wantProviders {
			t.Errorf("UA %q: provider form = %v, want %v", ua, got, wantProviders)
		}
		if !wantProviders && !strings.Contains(body, "\nproxies:") {
			t.Errorf("UA %q: inline form without a top-level proxies list:\n%s", ua, body)
		}
	}
}
