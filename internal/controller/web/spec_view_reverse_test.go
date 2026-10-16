package web

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

const (
	bridgeUUIDMarker = "b71d9e00-0000-4000-8000-00000000b71d"
	portalUUIDMarker = "a0c7a100-0000-4000-8000-0000000a0c7a"
)

func reverseExitSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role:              domain.RoleExit,
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		Reality: &domain.RealityServerSpec{Image: "img", Bridge: &domain.RealityBridgeSpec{Portals: []domain.RealityPortalPeer{
			{Master: "master-xa-1", Address: "203.0.113.1:48123", PublicKey: "pk", UUID: bridgeUUIDMarker, ShortID: "5e0b5e0b5e0b5e0b", ServerName: "www.python.org"},
		}}},
	}
}

func reverseMasterSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			ExitTunnels: []domain.ExitTunnel{{
				Name: "vn0-reality", Transport: domain.TransportRealityXHTTP, Reality: &domain.RealityTunnel{Reverse: true},
			}},
			RealityPortal: &domain.RealityPortalSpec{
				ListenPort: 48123, SocksPort: 10808, ServerName: "www.python.org", Dest: "www.python.org:443",
				Clients: []domain.RealityPortalClient{{Exit: "vn0", UUID: portalUUIDMarker, ShortID: "5e0b5e0b5e0b5e0b"}},
			},
		},
	}
}

// The bridge and portal UUIDs are credentials like every other VLESS id: the
// page — tables and raw JSON alike — must never carry them.
func TestSpecViewLeaksNoBridgeOrPortalUUIDs(t *testing.T) {
	for name, s := range map[string]domain.NodeSpec{"exit": reverseExitSpec(), "master": reverseMasterSpec()} {
		text := renderedText(buildSpecView(s))
		for _, marker := range []string{bridgeUUIDMarker, portalUUIDMarker, "5e0b5e0b5e0b5e0b"} {
			if strings.Contains(text, marker) {
				t.Errorf("%s: UUID %s reached the page", name, marker)
			}
		}
	}
}

func TestSpecViewShowsTheBridge(t *testing.T) {
	text := renderedText(buildSpecView(reverseExitSpec()))
	for _, want := range []string{"exit dials", "master-xa-1", "203.0.113.1:48123"} {
		if !strings.Contains(text, want) {
			t.Errorf("bridge detail %q missing:\n%s", want, text)
		}
	}
	if strings.Contains(text, "0/tcp") {
		t.Error("a bridge shows a listen port of 0")
	}
}

func TestSpecViewShowsThePortalAndReverseTunnels(t *testing.T) {
	text := renderedText(buildSpecView(reverseMasterSpec()))
	for _, want := range []string{"REALITY portal", "48123/tcp", "vn0", "via portal"} {
		if !strings.Contains(text, want) {
			t.Errorf("portal detail %q missing:\n%s", want, text)
		}
	}
}

// The node page's REALITY block showed "Listen port 0 / tcp" for a bridge — a
// closed port read as a misconfiguration. In the mode it says what is true.
func TestNodePageShowsTheBridgeInsteadOfAListenPort(t *testing.T) {
	spec := reverseExitSpec()
	spec.ActiveTransport = domain.TransportRealityXHTTP
	h, st := newTestHandler(t, stubRenderer{spec: spec})
	seed(t, st, domain.Node{ID: "vn0", Name: "vn0", Role: domain.RoleExit, State: domain.StateReady})
	_, page := get(t, h, "/nodes/vn0")
	if !strings.Contains(page, "exit dials, no open port") || !strings.Contains(page, "Dials master-xa-1") {
		t.Errorf("node page does not show the bridge")
	}
	if strings.Contains(page, "0 / tcp") {
		t.Error("node page shows listen port 0 for a bridge")
	}
	if strings.Contains(page, bridgeUUIDMarker) {
		t.Error("node page carries the bridge UUID")
	}
}
