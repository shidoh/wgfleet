package portal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// withRealAWG gives the fixture's master and its ready reserve door the AWG
// params the fleet actually derives, header protection included. The plain
// fixture has no AWG at all, so its configs are a few hundred bytes and fit any
// QR — which is how a profile too large for one went unnoticed.
func withRealAWG(t *testing.T, h *Handler) {
	t.Helper()
	src := h.src.(stubSource)
	p := wg.WithAWG3(wg.DeriveAWGParamsForEnd("master-xa-1/clients", "server", true), "master-xa-1/clients", "fleet-secret")

	master := *src.spec.Master
	cw := *master.ClientWG
	cw.AWG = &p
	master.ClientWG = &cw
	src.spec.Master = &master

	exitSpecs := map[string]domain.NodeSpec{}
	for id, sp := range src.exitSpecs {
		lifeline := *sp.Lifeline
		lifeline.ClientWGSpec.AWG = &p
		sp.Lifeline = &lifeline
		exitSpecs[id] = sp
	}
	src.exitSpecs = exitSpecs
	h.src = src
}

func TestPortalProfileTooLargeForQROffersTheFileOnly(t *testing.T) {
	h := testPortal(t)
	withRealAWG(t, h)

	res, body := fetch(t, h, "/c/"+devTok)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("page status = %d", res.StatusCode)
	}
	for _, src := range []string{`src="/c/` + devTok + `/qr"`, `src="/c/` + devTok + `/l/exit-ready/qr"`} {
		if strings.Contains(body, src) {
			t.Errorf("the page offers a QR image that cannot be encoded: %s", src)
		}
	}
	if !strings.Contains(body, "too large for a QR code") {
		t.Errorf("the page does not say why there is no QR:\n%s", body)
	}
	for _, want := range []string{`href="/c/` + devTok + `/config"`, `href="/c/` + devTok + `/l/exit-ready/config"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the download is gone along with the QR: missing %s", want)
		}
	}

	// A bookmarked QR link says what happened, not that the profile is dead.
	for _, path := range []string{"/c/" + devTok + "/qr", "/c/" + devTok + "/l/exit-ready/qr"} {
		res, body := fetch(t, h, path)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", path, res.StatusCode)
		}
		if !strings.Contains(body, "too large for a QR code") || strings.Contains(body, "no longer working") {
			t.Errorf("%s does not explain the missing QR:\n%s", path, body)
		}
	}

	// The file itself is unaffected.
	if res, cfg := fetch(t, h, "/c/"+devTok+"/config"); res.StatusCode != http.StatusOK || !strings.Contains(cfg, "HeaderProtectionKey") {
		t.Fatalf("config status = %d:\n%s", res.StatusCode, cfg)
	}
}

func TestPortalSmallProfileStillShowsItsQR(t *testing.T) {
	h := testPortal(t)
	_, body := fetch(t, h, "/c/"+devTok)
	for _, src := range []string{`src="/c/` + devTok + `/qr"`, `src="/c/` + devTok + `/l/exit-ready/qr"`} {
		if !strings.Contains(body, src) {
			t.Errorf("a profile that fits lost its QR: missing %s", src)
		}
	}
	if strings.Contains(body, "too large for a QR code") {
		t.Error("a profile that fits is said to be too large")
	}
}
