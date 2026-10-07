package main

import (
	"bytes"
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
	err := checkManifest(p, "")
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
	if err := checkManifest(filepath.Join(t.TempDir(), "absent.yaml"), ""); err == nil {
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

// --check-config exists to answer, without restarting, the question a restart
// answers destructively. A store path the controller cannot open is precisely the
// crash loop it was written to catch — and a manifest naming a directory that does
// not exist passed with rc=0, then failed at startup with
// `unable to open database file (14)`.
func TestCheckConfigRefusesAStoreItCannotOpen(t *testing.T) {
	if err := checkStoreOpenable(filepath.Join(t.TempDir(), "no-such-dir", "state.db")); err == nil {
		t.Error("a store under a directory that does not exist was accepted as a first start")
	}
	// A file that simply does not exist yet, in a directory that does, IS a first
	// start and must stay acceptable.
	if err := checkStoreOpenable(filepath.Join(t.TempDir(), "state.db")); err != nil {
		t.Errorf("a genuine first start was refused: %v", err)
	}
}

// --store overrides controller.store everywhere else in this binary, so it has to
// override it here too. It used to be applied after the check had already run,
// which made the flag accepted, documented, and silently ignored.
func TestCheckConfigHonoursTheStoreOverride(t *testing.T) {
	p := exampleManifest(t, 0o600)
	missing := filepath.Join(t.TempDir(), "no-such-dir", "state.db")
	if err := checkManifest(p, missing); err == nil {
		t.Error("--store was accepted and then ignored")
	}
}

// The anchor label and the slots decide every address and every key derivation
// on the exits, and nothing detects one that changed between restarts. The check
// prints them, so the operator can compare by eye before applying.
func TestCheckConfigPrintsTheMasterModel(t *testing.T) {
	two := config.FleetSection{
		InterfaceAnchor: "master-xa-1",
		MgmtSubnet:      "10.20.0.0/16",
		Masters: []config.MasterConfig{
			{Name: "master-xa-1", Slot: 0},
			{Name: "master-xa-2", Slot: 3},
		},
	}
	cases := []struct {
		name    string
		mutate  func(*config.FleetSection)
		want    []string
		wantNot []string
	}{
		{"two masters", func(*config.FleetSection) {},
			[]string{"anchor   master-xa-1", "base     master-xa-1", "master   master-xa-1  slot 0", "master   master-xa-2  slot 3"},
			[]string{"warning"}},
		{"the base master is gone", func(f *config.FleetSection) { f.Masters = f.Masters[1:] },
			[]string{"anchor   master-xa-1", "base     none", "master   master-xa-2  slot 3"},
			[]string{"master   master-xa-1", "warning"}},
		{"one master, nothing declared", func(f *config.FleetSection) {
			f.Masters, f.InterfaceAnchor, f.MgmtSubnet = f.Masters[:1], "", ""
		},
			[]string{"anchor   master-xa-1", "base     master-xa-1", "master   master-xa-1  slot 0"},
			[]string{"warning"}},
		{"several masters without a mgmt subnet", func(f *config.FleetSection) { f.MgmtSubnet = "" },
			[]string{"warning: fleet.mgmt_subnet is not set", "every exit"}, nil},
		{"no masters", func(f *config.FleetSection) { f.Masters, f.InterfaceAnchor = nil, "" },
			[]string{"anchor   none", "base     none"}, []string{"master   "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := two
			f.Masters = append([]config.MasterConfig(nil), two.Masters...)
			c.mutate(&f)
			var out bytes.Buffer
			printMasterModel(&out, f)
			for _, w := range c.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(out.String(), w) {
					t.Errorf("output has %q:\n%s", w, out.String())
				}
			}
		})
	}
}

// More direct rules than an exit can hold is said by the check and by the
// startup log, from one list — and is not a reason to refuse the manifest.
func TestManifestWarningsCarryTheDirectRuleCount(t *testing.T) {
	cidrs := make([]string, 80)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	cfg := config.ControllerConfig{Fleet: config.FleetSection{
		MgmtSubnet: "10.200.0.0/24",
		Masters:    []config.MasterConfig{{Name: "master-xa-1", Routing: config.MasterRouting{DirectCIDRs: cidrs}}},
		Exits:      []config.ExitConfig{{Name: "exit-de-1", AddressPool: "10.81.0.0/24", Egress: "warp"}},
	}}
	warns := manifestWarnings(cfg)
	if len(warns) != 1 || !strings.Contains(warns[0], "81 direct rules") {
		t.Fatalf("warnings = %q, want the one about 81 direct rules", warns)
	}
	cfg.Fleet.Masters[0].Routing.DirectCIDRs = cidrs[:10]
	if warns := manifestWarnings(cfg); len(warns) != 0 {
		t.Errorf("a manifest under the cap was warned about: %q", warns)
	}
}
