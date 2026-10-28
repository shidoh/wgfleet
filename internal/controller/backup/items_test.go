package backup

import (
	"github.com/shidoh/wgfleet/internal/config"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	if names["master/node.crt"] {
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
		ClientWGKey: w("client-wg.key"), NodeCert: w("node.crt"),
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

// The archive must carry the two secrets that cannot be regenerated without
// invalidating every client profile in the fleet.
//
// Neither was in it. A fresh awg3_key derives a different chacha20 header-protection
// key on every 3.x tunnel at once; a fresh client-vless key invalidates every
// profile's pinned pbk=. And the controller refuses to START without the first when
// header protection is on, so a restore onto a clean host did not come back
// degraded — it did not come back.
func TestGatherItemsCarriesTheIrreplaceableSecrets(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("secret-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	src := Sources{
		ControllerYAML: write("controller.yaml"),
		CACert:         write("ca.crt"),
		CAKey:          write("ca.key"),
		AWG3Key:        write("awg3.key"),
		ClientVLESSKey: write("client-vless.key"),
	}
	snap := write("state.db")

	items, _, err := GatherItems(src, snap, os.Stat)
	if err != nil {
		t.Fatalf("GatherItems: %v", err)
	}
	names := map[string]bool{}
	for _, it := range items {
		names[it.Name] = true
	}
	for _, want := range []string{"controller/awg3.key", "master/client-vless.key"} {
		if !names[want] {
			t.Errorf("the archive does not carry %q; a restore onto a clean host cannot come back", want)
		}
	}
}

// What cannot be carried must be said out loud, before the archive is written.
func TestSourcesWarnAboutSecretsThatCannotTravel(t *testing.T) {
	cfg := &config.ControllerConfig{}
	cfg.Fleet.AWG3Key = "env://WGFLEET_AWG3_KEY"

	// Neither secret resolves to a file on this host. Assert on WHAT is named, not
	// how many lines it takes: the list grows as more unbackupable things are found,
	// and a count assertion turns each addition into a spurious failure.
	got := Sources{}.Warnings(cfg)
	joined := strings.Join(got, "\n")
	for _, want := range []string{"CA private key", "awg3_key", "ZeroTier identity"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, joined)
		}
	}
	// With both in files this host can actually read, there is nothing to warn about.
	dir := t.TempDir()
	caKey, awg3 := filepath.Join(dir, "ca.key"), filepath.Join(dir, "awg3.key")
	for _, p := range []string{caKey, awg3} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Readable secrets must not be warned about. The ZeroTier line is unconditional —
	// it is never in the archive — so exclude it rather than assert an empty list.
	for _, w := range (Sources{CAKey: caKey, AWG3Key: awg3}).Warnings(cfg) {
		if strings.Contains(w, "ZeroTier") {
			continue
		}
		t.Errorf("warned about a secret that IS in the archive: %v", w)
	}

	// A path that is CONFIGURED but unreadable is the case the first version missed:
	// Warnings read the Sources ("is a path set") while GatherItems skips what it
	// cannot stat, so a ca_key that had been moved produced a non-empty string, no
	// warning, and an archive with no CA in it.
	moved := filepath.Join(dir, "gone.key")
	got = (Sources{CAKey: moved, AWG3Key: awg3}).Warnings(cfg)
	joined = strings.Join(got, "\n")
	if !strings.Contains(joined, "cannot read it") || !strings.Contains(joined, moved) {
		t.Errorf("the warning does not say which file or why:\n%s", joined)
	}
	if strings.Contains(joined, "awg3_key") {
		t.Errorf("a readable awg3_key was still warned about:\n%s", joined)
	}
}
