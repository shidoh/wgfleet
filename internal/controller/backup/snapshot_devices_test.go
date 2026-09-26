package backup

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// The backup is a whole-database VACUUM INTO, so devices ride along without a
// line of backup code — this pins that, and that the one-shot marker travels
// too (a restored controller must not re-run the adoption).
func TestSnapshotCarriesDevicesAndAdoptionMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "controller.db")
	st, err := store.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	if err := st.UpsertNode(ctx, domain.Node{ID: "m1", Name: "m1", Role: domain.RoleMaster, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddWGClient(ctx, "m1", domain.WGClient{ID: "c1", Name: "laptop", Address: "10.80.0.2/32",
		PublicKey: "p", PrivateKey: "k", Enabled: true, CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AdoptWGCredentialsAsDevices(ctx, t0); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	snap := filepath.Join(dir, "snap.db")
	if err := SnapshotDB(ctx, src, snap); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(snap)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if d, err := restored.GetDeviceByToken(ctx, "c1"); err != nil || d.Name != "laptop" || len(d.Credentials) != 1 {
		t.Fatalf("restored device = %+v, %v", d, err)
	}
	if n, err := restored.AdoptWGCredentialsAsDevices(ctx, t0); err != nil || n != 0 {
		t.Errorf("adoption re-ran after restore: n=%d err=%v", n, err)
	}
}
