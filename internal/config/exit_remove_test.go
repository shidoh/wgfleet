package config

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

// removeSample carries the two shapes a reserve_exits list is written in (inline
// flow on one master, block form on the other) plus comments inside and around the
// exit blocks, so one fixture exercises every branch the removal has to survive.
const removeSample = `controller:
  listen: "10.20.25.254:8443"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
      routing:
        # second tier
        reserve_exits: [anz3, fn7, pn8]
    - name: master-xa-2
      mgmt_addr: 10.20.25.253
      routing:
        reserve_exits:
          - fn7
          - anz3
  exits:
    - name: anz3
      region: sw
      firewall:
        as_blacklist: true
    # the dead node
    - name: fn7
      region: bl
      mgmt_addr: "172.29.3.23"
      transports:
        awg:
          enabled: true
      firewall:
        as_blacklist: true
    - name: pn8
      region: de
      firewall:
        as_blacklist: true
`

func TestRemoveExitDropsBlockAndKeepsSiblings(t *testing.T) {
	p := writeManifest(t, removeSample)

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	got := readManifest(t, p)
	if strings.Contains(got, "fn7") {
		t.Errorf("fn7 still referenced after removal:\n%s", got)
	}
	// The neighbours — and their bodies — must survive untouched.
	for _, want := range []string{"- name: anz3", "- name: pn8", "region: sw", "region: de"} {
		if !strings.Contains(got, want) {
			t.Errorf("removal ate %q:\n%s", want, got)
		}
	}
	// Only fn7's own lines go; the mgmt_addr that belonged to it must not survive.
	if strings.Contains(got, "172.29.3.23") {
		t.Errorf("fn7's body outlived its block:\n%s", got)
	}
}

func TestRemoveExitPrunesReserveExitsInBothListForms(t *testing.T) {
	p := writeManifest(t, removeSample)

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	got := readManifest(t, p)
	if !strings.Contains(got, "reserve_exits: [anz3, pn8]") {
		t.Errorf("inline reserve_exits not pruned to the survivors:\n%s", got)
	}
	// Block form: the fn7 item goes, anz3 stays.
	if strings.Contains(got, "- fn7") {
		t.Errorf("block-form reserve_exits still lists fn7:\n%s", got)
	}
	if !strings.Contains(got, "- anz3") {
		t.Errorf("block-form reserve_exits lost anz3:\n%s", got)
	}
}

// The landmine this whole change exists to avoid: validateReserveExits rejects a
// reserve_exits entry naming no declared exit, so removing the block WITHOUT
// pruning the references leaves a manifest the controller refuses to start on.
// Deleting a node from the console must never produce a config that will not load.
func TestRemoveExitLeavesAValidLoadableManifest(t *testing.T) {
	// A complete, genuinely loadable manifest — the point of this test is that the
	// file still passes the FULL Validate() the controller runs at startup, so a
	// fixture that could not load to begin with would prove nothing.
	const live = `
controller:
  listen: "0.0.0.0:8443"
  store: "/var/lib/wgfleet/state.db"
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key: "secret://ca-key"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
      client_awg:
        listen_port: 443
        address_pool: 10.80.0.0/24
      routing:
        balance: consistent-hashing
        reserve_exits: [anz3, fn7]
  exits:
    - name: anz3
      region: sw
      egress: warp
      address_pool: 10.81.0.0/24
    - name: fn7
      region: bl
      egress: warp
      address_pool: 10.77.0.0/24
`
	p := writeManifest(t, live)
	if _, err := Load(p, &ControllerConfig{}); err != nil {
		t.Fatalf("fixture does not load before removal: %v", err)
	}

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	cfg, err := Load(p, &ControllerConfig{})
	if err != nil {
		t.Fatalf("manifest no longer loads after removing an exit: %v\n%s", err, readManifest(t, p))
	}
	if err := cfg.validateReserveExits(); err != nil {
		t.Fatalf("dangling reserve_exits reference left behind: %v", err)
	}
	for _, e := range cfg.Fleet.Exits {
		if e.Name == "fn7" {
			t.Fatal("fn7 still declared after removal")
		}
	}
	if len(cfg.Fleet.Exits) != 1 {
		t.Errorf("exits = %d, want 1 survivor", len(cfg.Fleet.Exits))
	}
}

// An unknown exit is an error, not a silent no-op: the console reports "deleted"
// off the back of this, and a no-op would report success while the ghost stayed.
func TestRemoveExitUnknownIsAnError(t *testing.T) {
	p := writeManifest(t, removeSample)

	if err := RemoveExit(p, "nosuch"); err == nil {
		t.Fatal("removing an undeclared exit succeeded; want an error")
	}

	// A failed removal must not have touched the file.
	if got := readManifest(t, p); got != removeSample {
		t.Errorf("manifest modified despite the error:\n%s", got)
	}
}

// The manifest carries private keys; a rewrite must not widen its mode.
func TestRemoveExitKeepsManifestOwnerOnly(t *testing.T) {
	p := writeManifest(t, removeSample)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("manifest mode = %o, want 600", perm)
	}
}

func readManifest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	return string(b)
}

// A manifest has several lists of `- name:` items and fleet.masters has exactly the
// same shape as fleet.exits. An unscoped search finds the MASTER's block and removes
// it — and the resulting master-less manifest still LOADS, so there is no crash to
// notice: the controller comes up and brokers a fleet with no hub. Removal must be
// confined to fleet.exits.
func TestRemoveExitWillNotReachIntoFleetMasters(t *testing.T) {
	const withMaster = `controller:
  listen: "0.0.0.0:8443"
  store: "/var/lib/wgfleet/state.db"
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key: "secret://ca-key"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
      client_awg:
        listen_port: 443
        address_pool: 10.80.0.0/24
  exits:
    - name: anz3
      region: sw
      egress: warp
      address_pool: 10.81.0.0/24
`
	p := writeManifest(t, withMaster)

	if err := RemoveExit(p, "master-xa-1"); err == nil {
		t.Fatalf("removing a MASTER by name succeeded; the fleet lost its hub:\n%s", readManifest(t, p))
	}

	got := readManifest(t, p)
	if !strings.Contains(got, "- name: master-xa-1") {
		t.Errorf("the master block was removed anyway:\n%s", got)
	}
	if got != withMaster {
		t.Errorf("a refused removal still modified the manifest:\n%s", got)
	}
}

// An exit name that is a prefix of another must not take the longer one with it.
func TestRemoveExitDoesNotMatchANameByPrefix(t *testing.T) {
	const pair = `fleet:
  exits:
    - name: fn7
      region: bl
    - name: fb01
      region: bl
`
	p := writeManifest(t, pair)

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	got := readManifest(t, p)
	if !strings.Contains(got, "- name: fb01") {
		t.Errorf("removing fn7 also removed fb01:\n%s", got)
	}
	if strings.Contains(got, "- name: fn7\n") {
		t.Errorf("fn7 survived:\n%s", got)
	}
}

// Both manifest writers (RemoveExit and SetExitActiveTransport) read the whole
// file, mutate in memory and write it back. Two of them running at once — two
// browser tabs, or a delete racing a transport switch — each start from the same
// snapshot, and the second write reinstates whatever the first removed. The
// resurrected node then looks exactly like the ghost this feature exists to clear,
// days later and with no obvious cause.
func TestConcurrentRemoveExitDoesNotLoseUpdates(t *testing.T) {
	const many = `fleet:
  exits:
    - name: e1
      region: a
    - name: e2
      region: b
    - name: e3
      region: c
    - name: e4
      region: d
    - name: keep
      region: z
`
	p := writeManifest(t, many)

	var wg sync.WaitGroup
	for _, name := range []string{"e1", "e2", "e3", "e4"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := RemoveExit(p, name); err != nil {
				t.Errorf("RemoveExit(%s): %v", name, err)
			}
		}()
	}
	wg.Wait()

	got := readManifest(t, p)
	for _, name := range []string{"e1", "e2", "e3", "e4"} {
		if strings.Contains(got, "name: "+name) {
			t.Errorf("%s came back — a concurrent write reinstated it:\n%s", name, got)
		}
	}
	if !strings.Contains(got, "name: keep") {
		t.Errorf("an untouched exit was lost:\n%s", got)
	}
}

// `name: exit-a`, `name: "exit-a"` and `name: 'exit-a'` are the same exit to the parser, so
// they must be the same exit here — matching raw text missed the single-quoted
// spelling and reported "not found" for an exit the manifest plainly declares.
func TestRemoveExitMatchesEveryQuotingOfTheName(t *testing.T) {
	for _, spelling := range []string{"fn7", `"fn7"`, `'fn7'`} {
		manifest := "fleet:\n  exits:\n    - name: " + spelling + "\n      region: bl\n    - name: keep\n      region: z\n"
		p := writeManifest(t, manifest)

		if err := RemoveExit(p, "fn7"); err != nil {
			t.Errorf("RemoveExit with name spelled %s: %v", spelling, err)
			continue
		}
		got := readManifest(t, p)
		if strings.Contains(got, "fn7") {
			t.Errorf("name spelled %s survived removal:\n%s", spelling, got)
		}
		if !strings.Contains(got, "- name: keep") {
			t.Errorf("name spelled %s: removal ate the sibling:\n%s", spelling, got)
		}
	}
}

// A CRLF manifest must stay CRLF. pruneInlineList rewrites its line from scratch,
// so it is the one place a lone LF could be introduced mid-file.
func TestRemoveExitPreservesCRLFLineEndings(t *testing.T) {
	manifest := "fleet:\r\n  masters:\r\n    - name: m\r\n      routing:\r\n        reserve_exits: [fn7, keep]\r\n  exits:\r\n    - name: fn7\r\n      region: bl\r\n    - name: keep\r\n      region: z\r\n"
	p := writeManifest(t, manifest)

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	got := readManifest(t, p)
	if strings.Contains(got, "fn7") {
		t.Errorf("fn7 survived:\n%q", got)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\r\n"), "\r\n") {
		if strings.Contains(line, "\n") {
			t.Errorf("a bare LF was introduced into a CRLF file: %q", got)
			break
		}
	}
}

// The dangerous shape: a line-matcher miss must never be reported as "not
// declared", because callers treat that as success and would report a delete that
// removed nothing. Whatever the matcher does, the answer is cross-checked against
// the YAML parser.
func TestRemoveExitNeverReportsNotDeclaredForAnExitThatIs(t *testing.T) {
	// `exits:` nested inside a master, BEFORE the real fleet.exits list. A section
	// scan that matches the key anywhere inside the fleet block locks onto this one.
	const nested = `fleet:
  masters:
    - name: m
      routing:
        exits: something-else
  exits:
    - name: fn7
      region: bl
`
	p := writeManifest(t, nested)

	err := RemoveExit(p, "fn7")

	if errors.Is(err, ErrExitNotDeclared) {
		t.Fatalf("reported ErrExitNotDeclared for an exit the manifest declares — callers treat that as a successful delete: %v", err)
	}
	if err != nil {
		// A loud error is acceptable; silence is not. But this shape should just work.
		t.Errorf("RemoveExit: %v", err)
	}
	if got := readManifest(t, p); strings.Contains(got, "- name: fn7") {
		t.Errorf("fn7 survived:\n%s", got)
	}
}

// This manifest annotates values heavily, so a trailing comment on the name line is
// an ordinary thing to find.
func TestRemoveExitHandlesATrailingCommentOnTheNameLine(t *testing.T) {
	const commented = `fleet:
  masters:
    - name: m
      routing:
        reserve_exits:
          - fn7   # replaced 2026-08
          - keep
  exits:
    - name: fn7   # dead server, decommissioned
      region: bl
    - name: keep
      region: z
`
	p := writeManifest(t, commented)

	if err := RemoveExit(p, "fn7"); err != nil {
		t.Fatalf("RemoveExit: %v", err)
	}

	got := readManifest(t, p)
	if strings.Contains(got, "fn7") {
		t.Errorf("fn7 survived a name line carrying a comment:\n%s", got)
	}
	if !strings.Contains(got, "- name: keep") || !strings.Contains(got, "- keep") {
		t.Errorf("the surviving exit or its reserve_exits entry was lost:\n%s", got)
	}
}

// A genuinely absent exit still gets the sentinel — the tolerance callers rely on
// for a repeat delete must keep working.
func TestRemoveExitStillReportsNotDeclaredWhenItTrulyIsNot(t *testing.T) {
	p := writeManifest(t, "fleet:\n  exits:\n    - name: keep\n      region: z\n")

	err := RemoveExit(p, "fn7")

	if !errors.Is(err, ErrExitNotDeclared) {
		t.Fatalf("err = %v, want ErrExitNotDeclared", err)
	}
}
