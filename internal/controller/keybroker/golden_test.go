package keybroker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Fixed key material: a generated key would make every run a different file.
const (
	goldenMasterPriv = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA="
	goldenExitPub    = "kXr4jF0G0mYB0kQ0s2Yz8mJ1o8m0Qd0l5nJ8Zc1vS2I="
	goldenRealityPub = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE="
	// goldenMaster names the master in the snapshots. AmneziaWG parameters are
	// derived from node names, so it is fixed here rather than inherited.
	goldenMaster = "master-gold"
)

// goldenFleet is one master and two exits that between them take the branches the
// multi-master work rewrites: both transports, the exit-initiated flow with its
// gate armed, AmneziaWG 3.0 opted in, a reserve tier, a direct-egress exit. The
// lifeline is not here — its one-master behaviour is pinned by lifeline_test.go.
func goldenFleet(phase domain.PerTunnelKeyPhase) config.FleetSection {
	on := true
	f := testFleet()
	f.Masters[0].Name = goldenMaster
	f.AWG3 = &on
	f.Masters[0].PublicIP = "203.0.113.1"
	f.Masters[0].Routing.ReserveExits = []string{"exit-nl-1"}
	// The goldens froze the default image of their day. The image pin is bumped on
	// its own schedule, and that bump is not the regression these files guard.
	f.Masters[0].Compose.MihomoImage = "metacubex/mihomo"
	f.Masters[0].Compose.MihomoTag = "v1.19.30"
	f.Exits[0].PublicIP = "198.51.100.1"
	f.Exits[0].PerTunnelKey = string(phase)
	f.Exits[0].Transports.AWG.Enabled = true
	f.Exits[0].Transports.AWG.ExitInitiated = true
	f.Exits[0].Transports.Reality.Enabled = true
	f.Exits = append(f.Exits, config.ExitConfig{
		Name: "exit-nl-1", Region: "nl", Egress: "direct",
		AddressPool: "10.82.0.0/24", PublicIP: "198.51.100.2",
		PerTunnelKey: string(phase),
	})
	return f
}

func seedGolden(t *testing.T, st store.Store, fleet config.FleetSection, clock time.Time) {
	t.Helper()
	ctx := context.Background()
	masterPub, err := wg.PublicKeyOf(goldenMasterPriv)
	if err != nil {
		t.Fatal(err)
	}
	m := fleet.Masters[0]
	seedNode(t, st, m.Name, m.MgmtAddr, m.PublicIP, masterPub, domain.RoleMaster)
	setWireVersion(t, st, m.Name, api.WireAWG3TrackB)
	for i, e := range fleet.Exits {
		seedNode(t, st, e.Name, fmt.Sprintf("10.20.25.%d", i+1), e.PublicIP, goldenExitPub, domain.RoleExit)
		setWireVersion(t, st, e.Name, api.WireAWG3TrackB)
		seedTunnelKey(t, st, m.Name, e.Name, goldenMasterPriv)
		if err := st.SetNodeRealityKey(ctx, e.Name, goldenRealityPub); err != nil {
			t.Fatal(err)
		}
	}
	// The exit confirms the pinned address, so the master's gate renders ARMED:
	// without this every snapshot would carry an empty MasterAddr and say nothing
	// about the path the exit-initiated rework changes.
	pinned := fmt.Sprintf("%s:%d", m.PublicIP, wg.MasterPortFor(m.Name, fleet.Exits[0].Name))
	if err := st.RecordStatus(ctx, domain.NodeStatus{
		NodeID: fleet.Exits[0].Name, State: domain.StateReady, ReportedAt: clock, AWGMasterEndpoint: pinned,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSingleMasterRenderIsUnchanged(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0).UTC()
	for _, phase := range []domain.PerTunnelKeyPhase{
		domain.PerTunnelKeyOff, domain.PerTunnelKeyDual, domain.PerTunnelKeySwitch, domain.PerTunnelKeyOn,
	} {
		t.Run(string(phase), func(t *testing.T) {
			fleet := goldenFleet(phase)
			st, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			b := New(st, fleet, slog.New(slog.NewTextHandler(io.Discard, nil)),
				WithClock(func() time.Time { return clock }), WithAWG3Key("golden-awg3-key"))
			seedGolden(t, st, fleet, clock)
			// The master first: its render is what records the exit's confirmation.
			for _, id := range []string{goldenMaster, "exit-de-1", "exit-nl-1"} {
				spec, err := b.RenderNodeSpec(context.Background(), id)
				if err != nil {
					t.Fatalf("render %s: %v", id, err)
				}
				assertGolden(t, string(phase)+"-"+id, spec)
			}
		})
	}
}

func assertGolden(t *testing.T, name string, spec domain.NodeSpec) {
	t.Helper()
	got, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "single_master", name+".json")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s: rendered spec differs from the single-master golden.\nA one-master fleet must render exactly as before — fix the code, never the file.", name)
	}
}

// goldenSums freezes the snapshot. The files are the definition of "a one-master
// fleet renders as it always has"; a test that could be regenerated would let the
// definition drift to whatever the code does today.
var goldenSums = map[string]string{
	"dual-exit-de-1.json":     "5aa758252fbb0d05990e8a512b20213aa7b2fb78cc02e0aead33dd7f194a73ac",
	"dual-exit-nl-1.json":     "dab88c693698943748ca5777e754b40672b56aad11bb6356c762db61649c1155",
	"dual-master-gold.json":   "754b45ae0094161fd849692284ff1ab77b17cdc8ce35b75fe7e8f6c8a327ccf3",
	"off-exit-de-1.json":      "d91d9e9391c30f87c579c3cfce6a1c5b73400541da0a02f60d3a021517d25d6d",
	"off-exit-nl-1.json":      "c91bf699058eaf61beed624cdf3a806ff22062d0fedb6dcaac09aefa20ae0642",
	"off-master-gold.json":    "754b45ae0094161fd849692284ff1ab77b17cdc8ce35b75fe7e8f6c8a327ccf3",
	"on-exit-de-1.json":       "cb54749edcb2a15f423b555174ab28510780d844734c6ab6290dac4f2923298a",
	"on-exit-nl-1.json":       "724f842a6d4b09f02af45f1aab252b5982519506cb2667d2b587b9732e7e36bb",
	"on-master-gold.json":     "0fd9074d94cdc3433a52cd0c6b9ef826ae97955c47ec8259b183a02073f14b2b",
	"switch-exit-de-1.json":   "a24d1224973f47ebe3bea24c7274e02f3790cc120fa8b69d420e4686afa0175d",
	"switch-exit-nl-1.json":   "dab88c693698943748ca5777e754b40672b56aad11bb6356c762db61649c1155",
	"switch-master-gold.json": "0fd9074d94cdc3433a52cd0c6b9ef826ae97955c47ec8259b183a02073f14b2b",
}

func TestGoldenFilesAreFrozen(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "single_master"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(goldenSums) {
		t.Fatalf("%d golden files, %d recorded sums", len(entries), len(goldenSums))
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("testdata", "single_master", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != goldenSums[e.Name()] {
			t.Errorf("%s was modified (sha256 %s). Golden files are never regenerated.", e.Name(), got)
		}
	}
}
