package backup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGatherItemsControllerOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	src := Sources{
		ControllerYAML: write("controller.yaml", "controller: {}"),
		StateDB:        filepath.Join(dir, "real-state.db"), // not captured directly; snapshot is
		CACert:         write("ca.crt", "CERT"),
		CAKey:          write("ca.key", "KEY"),
	}
	snap := write("snap.db", "SNAPSHOT")

	items, layers, err := GatherItems(src, snap, os.Stat)
	if err != nil {
		t.Fatalf("GatherItems: %v", err)
	}
	if len(layers) != 1 || layers[0] != LayerController {
		t.Fatalf("want controller-only, got %v", layers)
	}
	names := map[string]bool{}
	for _, it := range items {
		names[it.Name] = true
	}
	for _, want := range []string{"controller/controller.yaml", "controller/state.db", "controller/ca.crt", "controller/ca.key"} {
		if !names[want] {
			t.Fatalf("missing item %q in %v", want, names)
		}
	}
	if names["master/wg-easy.db"] {
		t.Fatal("master items must be absent when files do not exist")
	}
}

func TestGatherItemsIncludesMasterWhenPresent(t *testing.T) {
	dir := t.TempDir()
	w := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	src := Sources{
		ControllerYAML: w("controller.yaml"), CACert: w("ca.crt"), CAKey: w("ca.key"),
		WGEasyDB: w("wg-easy.db"), WGEasyAdmin: w("admin"), NodeCert: w("node.crt"),
		NodeKey: w("node.key"), AgentYAML: w("agent.yaml"),
	}
	_, layers, err := GatherItems(src, w("snap.db"), os.Stat)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 2 {
		t.Fatalf("want both layers, got %v", layers)
	}
}

func TestGatherItemsMissingRequiredFails(t *testing.T) {
	src := Sources{ControllerYAML: "/nonexistent/controller.yaml"}
	if _, _, err := GatherItems(src, "/nonexistent/snap.db", os.Stat); err == nil {
		t.Fatal("expected error for missing required controller item")
	}
}

// The master's wg.key is the ROOT of every master↔exit tunnel identity: since
// ADR-0030 each per-tunnel key is derived from it, so losing it invalidates every
// tunnel at once rather than possibly none. It must be in the master layer.
func TestGatherItemsCapturesMasterWGKey(t *testing.T) {
	dir := t.TempDir()
	wgKey := filepath.Join(dir, "wg.key")
	if err := os.WriteFile(wgKey, []byte("QK9uYm90aGluZ3Rvc2VlaGVyZW5vdGhpbmdhdGFsbA=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "snap.db")
	ca := filepath.Join(dir, "ca.crt")
	cfg := filepath.Join(dir, "controller.yaml")
	for _, p := range []string{db, ca, cfg} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	items, layers, err := GatherItems(
		Sources{ControllerYAML: cfg, StateDB: db, CACert: ca, WGKey: wgKey},
		db, os.Stat)
	if err != nil {
		t.Fatal(err)
	}

	var found *Item
	for i := range items {
		if items[i].Name == "master/wg.key" {
			found = &items[i]
		}
	}
	if found == nil {
		t.Fatal("master/wg.key missing from the backup — a restore would mint a new " +
			"master identity and break every exit tunnel until the fleet reconverges")
	}
	if found.Layer != LayerMaster {
		t.Errorf("wg.key layer = %v, want the master layer", found.Layer)
	}
	if found.Dest != "/etc/wgfleet/wg.key" {
		t.Errorf("wg.key restore dest = %q", found.Dest)
	}
	if found.Mode.Perm() != 0o600 {
		t.Errorf("wg.key mode = %o, want 0600 — it is a private key", found.Mode.Perm())
	}
	if !slices.Contains(layers, LayerMaster) {
		t.Error("master layer must be reported when wg.key is present")
	}
}
