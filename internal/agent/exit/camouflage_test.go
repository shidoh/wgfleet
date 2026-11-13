package exit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/camouflage"
	"github.com/shidoh/wgfleet/internal/domain"
)

// The inbound renders the gate's verdict of the pass: the domain is accepted in
// both states, the target moves only while the gate is open.
func TestXrayPlannerFollowsTheCamouflageGate(t *testing.T) {
	dir := t.TempDir()
	spec := domain.NodeSpec{
		EnabledTransports: []domain.MasterTransport{domain.TransportRealityXHTTP},
		Reality: &domain.RealityServerSpec{
			ListenPort: 443, UUID: "11111111-2222-3333-4444-555555555555",
			ShortID: "0badc0de", ServerName: "www.example.org", Dest: "www.example.org:443",
		},
		Camouflage: &domain.CamouflageSpec{Domain: "e1.example.net", PublicIP: "198.51.100.20"},
	}
	gate := camouflage.NewGate("")
	p := xrayPlanner{configPath: filepath.Join(dir, "config.json"), composePath: filepath.Join(dir, "docker-compose.yml"),
		privateKey: "PRIV", up: func(string) bool { return false }, gate: gate}
	config := func() string {
		t.Helper()
		acts, err := p.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range acts {
			if a.Target == p.configPath {
				return a.Display
			}
		}
		t.Fatal("no config action")
		return ""
	}
	closed := config()
	if !strings.Contains(closed, `"target": "www.example.org:443"`) || !strings.Contains(closed, `"e1.example.net"`) {
		t.Errorf("closed gate: want the default target and the domain accepted:\n%s", closed)
	}
	if _, err := gate.Observe(spec.Camouflage, camouflage.Result{TLSOK: true, DNSOK: true}); err != nil {
		t.Fatal(err)
	}
	if open := config(); !strings.Contains(open, `"target": "127.0.0.1:8444"`) {
		t.Errorf("open gate: want the local site as target:\n%s", open)
	}
}
