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
)

// goldenFleet is one master and two exits that between them take the branches the
// multi-master work rewrites: both transports, the exit-initiated flow with its
// gate armed, AmneziaWG 3.0 opted in, a reserve tier, a direct-egress exit. The
// lifeline is not here — its one-master behaviour is pinned by lifeline_test.go.
func goldenFleet(phase domain.PerTunnelKeyPhase) config.FleetSection {
	on := true
	f := testFleet()
	f.AWG3 = &on
	f.Masters[0].PublicIP = "203.0.113.1"
	f.Masters[0].Routing.ReserveExits = []string{"exit-nl-1"}
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
	setWireVersion(t, st, m.Name, api.WireAWGExitInitiated)
	for i, e := range fleet.Exits {
		seedNode(t, st, e.Name, fmt.Sprintf("10.20.25.%d", i+1), e.PublicIP, goldenExitPub, domain.RoleExit)
		setWireVersion(t, st, e.Name, api.WireAWGExitInitiated)
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
			for _, id := range []string{"master-xa-1", "exit-de-1", "exit-nl-1"} {
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
	"dual-exit-de-1.json":     "47da8f329eef08f86f4e0597403215679be6698041d341b8081a192d10fd629f",
	"dual-exit-nl-1.json":     "d4389b9b243453698f60ef55b3952a6b61f950e720ca27e26386ad76de9675b5",
	"dual-master-xa-1.json":   "797d3015bdc13c0b5071c288365922e9aeaeac18c4c1dc569d330417485fc6ae",
	"off-exit-de-1.json":      "7721255e45b48475b4ef432d342b928738b8b00a75d0809ce5e90b6ef9bdf2fc",
	"off-exit-nl-1.json":      "b770852022322d6eb038ac7aa3e762dc6489c4b71ccbbc692d2264d36f8bff90",
	"off-master-xa-1.json":    "797d3015bdc13c0b5071c288365922e9aeaeac18c4c1dc569d330417485fc6ae",
	"on-exit-de-1.json":       "101ef6af560d2e2f9d8c45817b987f5ed622f38924a942f13271d7d9722d017a",
	"on-exit-nl-1.json":       "2aba44f0e06c1d12f48d7c4b9fce9a28a5169192457b8a0c77e8adbd70985cfa",
	"on-master-xa-1.json":     "dbc3c6e74d01179414cfa871e43b507e58d8b2ce79654843c5a97da432b8c586",
	"switch-exit-de-1.json":   "6a60e594c5c7b891ccfaa9811c4f9ce9042214e57f8c6a74167418a02c9e2f86",
	"switch-exit-nl-1.json":   "d4389b9b243453698f60ef55b3952a6b61f950e720ca27e26386ad76de9675b5",
	"switch-master-xa-1.json": "dbc3c6e74d01179414cfa871e43b507e58d8b2ce79654843c5a97da432b8c586",
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
