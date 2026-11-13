package web

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestSpecViewShowsTheCamouflageSiteAndItsDNSRecord(t *testing.T) {
	s := domain.NodeSpec{Role: domain.RoleExit, Camouflage: &domain.CamouflageSpec{
		Domain: "e1.example.net", PublicIP: "198.51.100.20", PublicHTTPS: true,
	}}
	text := renderedText(buildSpecView(s))
	for _, want := range []string{"Camouflage site", "e1.example.net A 198.51.100.20", "80/tcp, 443/tcp", "127.0.0.1:8444", "Let's Encrypt"} {
		if !strings.Contains(text, want) {
			t.Errorf("camouflage detail %q missing:\n%s", want, text)
		}
	}
	if text := renderedText(buildSpecView(domain.NodeSpec{Role: domain.RoleExit})); strings.Contains(text, "Camouflage site") {
		t.Error("a node without camouflage shows the group")
	}
}
