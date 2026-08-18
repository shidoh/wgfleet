package exit

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func awg3Spec() domain.NodeSpec {
	p := domain.AWGParams{
		Shared: domain.AWGShared{
			H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
			H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
			H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
			H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
			S1: 102, S2: 67, S3: 143, S4: 38,
			HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			RekeyAfterTime:      "120-150",
		},
		Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900},
	}
	return domain.NodeSpec{
		Role: domain.RoleExit,
		WGServer: domain.WGServerSpec{
			ListenPort: 51820, AddressPool: "10.81.0.0/24", Address: "10.81.0.1", MTU: 1420, AWG: &p,
		},
	}
}

func awg2Spec() domain.NodeSpec {
	s := awg3Spec()
	awg := *s.WGServer.AWG
	awg.Shared.HeaderProtectionKey = ""
	awg.Shared.RekeyAfterTime = ""
	s.WGServer.AWG = &awg
	return s
}

func plannerWithGen(t *testing.T, gen int, err error) wgPlanner {
	t.Helper()
	kp, kerr := wg.GenerateKeyPair()
	if kerr != nil {
		t.Fatal(kerr)
	}
	return wgPlanner{
		path:       filepath.Join(t.TempDir(), "awg0.conf"),
		privateKey: kp.PrivateKey,
		up:         func(string) bool { return true },
		awgGen:     func() (int, error) { return gen, err },
	}
}

// TestAWG3RefusedOnLegacyModule is the node-local half of the AWG 3.0 gate. The
// controller checks what it can see (operator intent, agent wire version), but
// only the node knows its kernel module generation — and AmneziaWG 3.0 changed the
// netlink attribute layout, so `awg setconf` on a 1.x module fails outright with
// "attribute type 14 has an invalid length" and the interface never comes up.
//
// Writing the config and running awg-quick anyway would take a live exit DOWN. The
// planner must refuse before touching anything, leaving the previous good config
// in place and surfacing the reason.
func TestAWG3RefusedOnLegacyModule(t *testing.T) {
	p := plannerWithGen(t, 1, nil)
	_, err := p.Plan(context.Background(), awg3Spec())
	if err == nil {
		t.Fatal("expected the planner to refuse an AWG 3.0 config on a 1.x module")
	}
	for _, want := range []string{"3.0", "module"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
	if _, statErr := os.Stat(p.path); statErr == nil {
		t.Error("the planner must not have written a config it knows cannot be applied")
	}
}

// TestAWG3AppliedOnModernModule — the happy path stays a normal render.
func TestAWG3AppliedOnModernModule(t *testing.T) {
	p := plannerWithGen(t, 3, nil)
	acts, err := p.Plan(context.Background(), awg3Spec())
	if err != nil {
		t.Fatalf("AWG 3.0 on a 3.x module must render: %v", err)
	}
	if len(acts) == 0 || !acts[0].Changes() {
		t.Fatalf("expected a config write, got %+v", acts)
	}
}

// TestAWG2UnaffectedByModuleGeneration — the probe must not gate 2.0 configs. A
// 3.x module still speaks 2.0 params, and more importantly a node whose generation
// we cannot read must keep converging exactly as it did before this gate existed.
func TestAWG2UnaffectedByModuleGeneration(t *testing.T) {
	for _, gen := range []int{1, 3, 0} {
		p := plannerWithGen(t, gen, nil)
		if _, err := p.Plan(context.Background(), awg2Spec()); err != nil {
			t.Errorf("AWG 2.0 must render on module generation %d: %v", gen, err)
		}
	}
}

// TestAWG3RefusedWhenGenerationUnknown — an unreadable module generation with a
// 3.0 config is the one case where refusing is right: applying could take the exit
// down, refusing only leaves it on its previous config.
func TestAWG3RefusedWhenGenerationUnknown(t *testing.T) {
	p := plannerWithGen(t, 0, errAWGGenUnknown)
	if _, err := p.Plan(context.Background(), awg3Spec()); err == nil {
		t.Fatal("expected a refusal when the module generation cannot be determined")
	}
}
