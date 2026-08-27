package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
)

func writeManifest(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// The shipped example is the manifest every new operator starts from, so using it
// here checks two things at once: that --check-config accepts a good file, and
// that the example we ship is still one.
func exampleManifest(t *testing.T, mode os.FileMode) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "examples", "controller.yaml"))
	if err != nil {
		t.Fatalf("read the shipped example: %v", err)
	}
	return writeManifest(t, string(raw), mode)
}

// The whole point of the flag: a manifest the controller would refuse must be
// reported here instead of at startup, where the unit's Restart=on-failure turns
// the refusal into a crash loop of the control plane.
func TestCheckManifestRejectsWhatTheControllerWouldRefuse(t *testing.T) {
	p := writeManifest(t, "controller:\n  listen: [oops\n", 0o600)
	err := checkManifest(p)
	if err == nil {
		t.Fatal("a manifest that cannot be parsed was reported as valid")
	}
	if !errors.Is(err, errCheckFailed) {
		t.Fatalf("err = %v, want errCheckFailed so main does not log the report twice", err)
	}
}

func TestCheckManifestAcceptsAValidOne(t *testing.T) {
	// The MANIFEST verdict. The host verdict is deliberately separate — it needs a
	// CA and a store on this machine, which a unit test has no business planting.
	if _, err := checkManifestOnly(exampleManifest(t, 0o600)); err != nil {
		t.Fatalf("the shipped example manifest was rejected: %v", err)
	}
}

// A check that modifies the thing it checks is not a check. The startup path
// tightens the manifest to 0600; this one must not, or `--check-config` becomes a
// command with a side effect nobody expects.
func TestCheckManifestDoesNotTouchTheFile(t *testing.T) {
	p := exampleManifest(t, 0o644)
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkManifestOnly(p); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Errorf("the check changed the file mode: %v -> %v", before.Mode(), after.Mode())
	}
}

func TestCheckManifestReportsAMissingFile(t *testing.T) {
	if err := checkManifest(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("a missing manifest was reported as valid")
	}
}

// The store check must not create or migrate anything: --check-config promises
// to change nothing, and opening the store does both.
func TestCheckStoreOpenableTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "state.db")

	// Absent is a first start, not a failure — and must stay absent.
	if err := checkStoreOpenable(missing); err != nil {
		t.Fatalf("an absent store was reported as a problem: %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("the check created the database it was asked to inspect")
	}

	// A store from a NEWER build is the failure that otherwise surfaces as a
	// crash loop, so it must be caught here.
	st, err := store.Open(missing)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := checkStoreOpenable(missing); err != nil {
		t.Fatalf("a current store was rejected: %v", err)
	}

	db, err := sql.Open("sqlite", "file:"+missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", store.MigrationCount()+1)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err = checkStoreOpenable(missing)
	if err == nil {
		t.Fatal("a store from a newer build was accepted")
	}
	if !strings.Contains(err.Error(), "newer wgfleet-controller") {
		t.Errorf("error = %v, want the cause named", err)
	}
}

// A good manifest on a machine that is not the controller must be reported as a
// GOOD manifest that this host cannot run — not as a bad manifest.
//
// The two verdicts were folded together at first, and the cost showed up
// immediately: validating the live manifest from a laptop said "NOT valid" about
// a file that was fine, which is exactly the wrong thing for a command whose job
// is to be trusted before a restart.
func TestCheckHostReadinessDoesNotCondemnTheManifest(t *testing.T) {
	p := exampleManifest(t, 0o600)
	cfg, err := checkManifestOnly(p)
	if err != nil {
		t.Fatalf("the manifest verdict failed: %v", err)
	}
	// The example points at /etc/wgfleet paths that do not exist here.
	if err := checkHostReadiness(cfg); !errors.Is(err, errCheckFailed) {
		t.Fatalf("host readiness = %v, want errCheckFailed", err)
	}
}

// A reference that resolves to nothing must be refused, not silently accepted.
//
// Config validation checks the reference string; this is the value. An env var
// set to the empty string — a one-character slip in a systemd Environment= line —
// passes validation and then keys the header-protection HMAC on "", which anyone
// holding this source can recompute. --check-config must catch it, because the
// alternative is finding out from `Restart=on-failure`.
func TestAWG3KeyMustResolveToSomethingUsable(t *testing.T) {
	on := true
	cfg := &config.ControllerConfig{}
	cfg.Fleet.AWG3 = &on
	cfg.Fleet.AWG3Key = "env://WGFLEET_TEST_AWG3_KEY"

	t.Setenv("WGFLEET_TEST_AWG3_KEY", "")
	if _, err := resolveAWG3Key(cfg, config.EnvSecretProvider{}); err == nil {
		t.Error("an empty resolved secret was accepted while header protection is on")
	}

	t.Setenv("WGFLEET_TEST_AWG3_KEY", "short")
	err := resolveAWG3Key2(t, cfg)
	if err == nil {
		t.Error("a 5-byte secret was accepted")
	} else if !strings.Contains(err.Error(), "at least") {
		t.Errorf("the refusal does not say what is needed: %v", err)
	}

	t.Setenv("WGFLEET_TEST_AWG3_KEY", strings.Repeat("k", config.MinAWG3KeyLen))
	if _, err := resolveAWG3Key(cfg, config.EnvSecretProvider{}); err != nil {
		t.Errorf("a usable secret was refused: %v", err)
	}

	// With header protection off, an empty value is the ordinary state and must
	// not block startup.
	off := config.ControllerConfig{}
	t.Setenv("WGFLEET_TEST_AWG3_KEY", "")
	off.Fleet.AWG3Key = "env://WGFLEET_TEST_AWG3_KEY"
	if _, err := resolveAWG3Key(&off, config.EnvSecretProvider{}); err != nil {
		t.Errorf("an unused secret was refused: %v", err)
	}
}

func resolveAWG3Key2(t *testing.T, cfg *config.ControllerConfig) error {
	t.Helper()
	_, err := resolveAWG3Key(cfg, config.EnvSecretProvider{})
	return err
}
