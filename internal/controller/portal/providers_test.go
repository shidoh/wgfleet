package portal

import (
	"net/http"
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
