package camoplan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/camouflage"
	"github.com/shidoh/wgfleet/internal/domain"
)

func camoSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role:       domain.RoleExit,
		Reality:    &domain.RealityServerSpec{ListenPort: 443},
		Camouflage: &domain.CamouflageSpec{Domain: "e1.example.net", PublicIP: "198.51.100.20"},
	}
}

type fakes struct {
	up        bool
	inspect   [3]any // configFile, dataDir, found
	result    camouflage.Result
	holder    string
	probeSeen int
}

func (f *fakes) planner(t *testing.T, g *camouflage.Gate) Planner {
	t.Helper()
	return Planner{
		Paths: PathsUnder(t.TempDir()),
		Gate:  g,
		Up:    func(context.Context, string) bool { return f.up },
		Inspect: func(context.Context) (string, string, bool) {
			if f.inspect[2] == nil {
				return "", "", false
			}
			return f.inspect[0].(string), f.inspect[1].(string), f.inspect[2].(bool)
		},
		Probe: func(context.Context, domain.CamouflageSpec) camouflage.Result {
			f.probeSeen++
			return f.result
		},
		PortHolder: func(context.Context, int) string { return f.holder },
	}
}

func apply(t *testing.T, p Planner, spec domain.NodeSpec) []reconcile.Action {
	t.Helper()
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return acts
}

func summaries(acts []reconcile.Action) string {
	var b strings.Builder
	for _, a := range acts {
		b.WriteString(a.Summary + " | " + a.Display + "\n")
	}
	return b.String()
}

func TestPlanRendersTheSiteAndBringsItUp(t *testing.T) {
	f := &fakes{result: camouflage.Result{Reason: "connection refused"}}
	p := f.planner(t, camouflage.NewGate(""))
	acts := apply(t, p, camoSpec())
	got := summaries(acts)
	for _, want := range []string{"bring camouflage site up", "create camouflage directories", "target: the fleet default"} {
		if !strings.Contains(got, want) {
			t.Errorf("plan lacks %q:\n%s", want, got)
		}
	}
	var caddyfile string
	for _, a := range acts {
		if a.Target == p.Paths.caddyfile() {
			caddyfile = a.Display
		}
	}
	// The inbound on 443 shows the site, so port 80 redirects there.
	if !strings.Contains(caddyfile, "redir https://e1.example.net{uri} 308") {
		t.Errorf("Caddyfile display:\n%s", caddyfile)
	}
	if f.probeSeen != 1 {
		t.Errorf("probed %d times, want once per pass", f.probeSeen)
	}
}

func TestPlanOpensTheGateOnAPassingProbe(t *testing.T) {
	f := &fakes{up: true, result: camouflage.Result{TLSOK: true, DNSOK: true, NotAfter: time.Now().Add(time.Hour * 24 * 80)}}
	g := camouflage.NewGate("")
	acts := apply(t, f.planner(t, g), camoSpec())
	if g.ActiveDomain() != "e1.example.net" {
		t.Fatalf("gate closed after a passing probe:\n%s", summaries(acts))
	}
	if !strings.Contains(summaries(acts), "switched — target: the own site 127.0.0.1:8444") {
		t.Errorf("plan does not show the switch:\n%s", summaries(acts))
	}
	x := XrayCamouflage(g, camoSpec().Camouflage)
	if x == nil || x.Domain != "e1.example.net" || x.Target != "127.0.0.1:8444" {
		t.Errorf("XrayCamouflage = %+v", x)
	}
}

func TestPlanNamesWhatHoldsPort80(t *testing.T) {
	f := &fakes{result: camouflage.Result{Reason: "connection refused"}, holder: `(("nginx",pid=7,fd=6))`}
	acts := apply(t, f.planner(t, camouflage.NewGate("")), camoSpec())
	if !strings.Contains(summaries(acts), `TCP/80 is held by (("nginx"`) {
		t.Errorf("holder not named:\n%s", summaries(acts))
	}
	f.holder = `(("caddy",pid=8,fd=3))`
	acts = apply(t, f.planner(t, camouflage.NewGate("")), camoSpec())
	if strings.Contains(summaries(acts), "held by") {
		t.Errorf("our own Caddy named as a foreign holder:\n%s", summaries(acts))
	}
}

func TestPlanAdoptsAHandBuiltContainer(t *testing.T) {
	old := t.TempDir()
	f := &fakes{inspect: [3]any{"/opt/site/docker-compose.yml", old, true}}
	p := f.planner(t, camouflage.NewGate(""))
	got := summaries(apply(t, p, camoSpec()))
	if !strings.Contains(got, "adopt the hand-built camouflage container") ||
		!strings.Contains(got, "cp -a "+old+"/. "+p.Paths.Data+"/ && docker rm -f camouflage") {
		t.Errorf("no adoption with a certificate copy:\n%s", got)
	}
	// Storage already filled: the certificates stay ours, only the container goes.
	if err := os.MkdirAll(filepath.Join(p.Paths.Data, "caddy"), 0o700); err != nil {
		t.Fatal(err)
	}
	got = summaries(apply(t, p, camoSpec()))
	if strings.Contains(got, "cp -a") || !strings.Contains(got, "docker rm -f camouflage") {
		t.Errorf("filled storage overwritten or container kept:\n%s", got)
	}
	// Our own container is not adopted.
	f.inspect = [3]any{p.Paths.compose(), p.Paths.Data, true}
	if got = summaries(apply(t, p, camoSpec())); strings.Contains(got, "adopt") {
		t.Errorf("adopted our own container:\n%s", got)
	}
}

func TestPlanStopsTheSiteWhenCamouflageGoes(t *testing.T) {
	f := &fakes{up: true, result: camouflage.Result{TLSOK: true, DNSOK: true}}
	g := camouflage.NewGate("")
	p := f.planner(t, g)
	apply(t, p, camoSpec())
	if err := os.MkdirAll(p.Paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Paths.compose(), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	off := camoSpec()
	off.Camouflage = nil
	got := summaries(apply(t, p, off))
	if !strings.Contains(got, "stop camouflage site") || !strings.Contains(got, "down") {
		t.Errorf("site not stopped:\n%s", got)
	}
	if g.ActiveDomain() != "" {
		t.Error("gate still open with camouflage off")
	}
	if x := XrayCamouflage(g, nil); x != nil {
		t.Errorf("XrayCamouflage(nil) = %+v", x)
	}
}

func TestPlanRefusesABadSpecAndKeepsTheSite(t *testing.T) {
	f := &fakes{}
	spec := camoSpec()
	spec.Camouflage.PublicIP = "not-an-ip"
	got := summaries(apply(t, f.planner(t, nil), spec))
	if !strings.Contains(got, "spec rejected, keeping the last-good site") {
		t.Errorf("bad spec not refused:\n%s", got)
	}
}

func TestPlanWithoutPathsDoesNothing(t *testing.T) {
	acts, err := Planner{}.Plan(context.Background(), camoSpec())
	if err != nil || len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("Plan with no paths = %v, %v", acts, err)
	}
}

func TestRealityOn443(t *testing.T) {
	cases := map[string]struct {
		spec domain.NodeSpec
		want bool
	}{
		"exit inbound on 443":    {domain.NodeSpec{Reality: &domain.RealityServerSpec{ListenPort: 443}}, true},
		"exit inbound elsewhere": {domain.NodeSpec{Reality: &domain.RealityServerSpec{ListenPort: 8443}}, false},
		"exit dials out": {domain.NodeSpec{Reality: &domain.RealityServerSpec{
			Bridge: &domain.RealityBridgeSpec{}}}, false},
		"master client inbound on 443": {domain.NodeSpec{Master: &domain.MasterSpec{
			ClientVLESS: &domain.ClientVLESSServerSpec{ListenPort: 443}}}, true},
		"master portal on 443": {domain.NodeSpec{Master: &domain.MasterSpec{
			RealityPortal: &domain.RealityPortalSpec{ListenPort: 443}}}, true},
		"nothing": {domain.NodeSpec{}, false},
	}
	for name, c := range cases {
		if got := realityOn443(c.spec); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestTeardownRemovesTheSite(t *testing.T) {
	p := PathsUnder(t.TempDir())
	acts, _ := Teardown(p).Plan(context.Background(), domain.NodeSpec{})
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("teardown without a site: %v", acts)
	}
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.compose(), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	acts, _ = Teardown(p).Plan(context.Background(), domain.NodeSpec{})
	got := summaries(acts)
	if !strings.Contains(got, "compose -f "+p.compose()+" down") || !strings.Contains(got, "rm -rf "+p.Dir+" "+p.Data) {
		t.Errorf("teardown:\n%s", got)
	}
}

func TestXrayCamouflageIgnoresARejectedSpec(t *testing.T) {
	g := camouflage.NewGate("")
	bad := &domain.CamouflageSpec{Domain: `e1.example.net"`, PublicIP: "198.51.100.20"}
	if x := XrayCamouflage(g, bad); x != nil {
		t.Errorf("a rejected spec reached the inbounds: %+v", x)
	}
}

func TestPlanDoesNotAdoptOurContainerListedWithOthers(t *testing.T) {
	f := &fakes{}
	p := f.planner(t, camouflage.NewGate(""))
	f.inspect = [3]any{"/x/override.yml," + p.Paths.compose(), p.Paths.Data, true}
	if got := summaries(apply(t, p, camoSpec())); strings.Contains(got, "adopt") {
		t.Errorf("adopted our own container:\n%s", got)
	}
}
