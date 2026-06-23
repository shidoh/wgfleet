package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestFileActionCreateUpdateNoChange(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "config.conf")

	// First: create.
	a1, err := FileAction(target, []byte("alpha\n"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a1.Kind != ActionCreate || !a1.Changes() {
		t.Fatalf("expected create, got %s", a1.Kind)
	}
	if err := a1.run(context.Background()); err != nil {
		t.Fatalf("apply create: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "alpha\n" {
		t.Fatalf("content = %q", got)
	}

	// Second: same content ⇒ no change.
	a2, _ := FileAction(target, []byte("alpha\n"), 0o600, nil)
	if a2.Kind != ActionNoChange || a2.Changes() {
		t.Fatalf("expected no-change, got %s", a2.Kind)
	}

	// Third: different content ⇒ update.
	a3, _ := FileAction(target, []byte("beta\n"), 0o600, nil)
	if a3.Kind != ActionUpdate {
		t.Fatalf("expected update, got %s", a3.Kind)
	}
	if err := a3.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(target)
	if string(got) != "beta\n" {
		t.Fatalf("content after update = %q", got)
	}
}

func TestFileActionAtomicPerm(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.key")
	a, _ := FileAction(target, []byte("k"), 0o600, nil)
	if err := a.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", info.Mode().Perm())
	}
}

func TestFileActionRedaction(t *testing.T) {
	redact := func(s string) string {
		return strings.ReplaceAll(s, "TOPSECRET", "<redacted>")
	}
	a, _ := FileAction(filepath.Join(t.TempDir(), "x.conf"), []byte("PrivateKey = TOPSECRET\n"), 0o600, redact)
	if strings.Contains(a.Display, "TOPSECRET") {
		t.Errorf("display leaked secret: %q", a.Display)
	}
	if !strings.Contains(a.Display, "<redacted>") {
		t.Errorf("display missing redaction marker: %q", a.Display)
	}
}

// stubPlanner returns a fixed set of actions and records whether Plan ran.
type stubPlanner struct {
	name    string
	actions []Action
	planned *bool
}

func (s stubPlanner) Component() string { return s.name }
func (s stubPlanner) Plan(context.Context, domain.NodeSpec) ([]Action, error) {
	if s.planned != nil {
		*s.planned = true
	}
	return s.actions, nil
}

func TestEnginePlanModeAppliesNothing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "should-not-exist.conf")
	create, _ := FileAction(target, []byte("data"), 0o600, nil)

	eng := NewEngine(nil, stubPlanner{name: "wg", actions: []Action{create}})
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModePlan)
	if err != nil {
		t.Fatal(err)
	}
	if report.ChangeCount() != 1 {
		t.Errorf("change count = %d, want 1", report.ChangeCount())
	}
	// The defining property: plan mode must not have written the file.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("plan mode wrote the file; dry-run must not mutate: %v", err)
	}
	if !strings.Contains(report.String(), "wg") {
		t.Errorf("report missing component:\n%s", report.String())
	}
}

func TestEngineApplyModeApplies(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "applied.conf")
	create, _ := FileAction(target, []byte("data"), 0o600, nil)

	eng := NewEngine(nil, stubPlanner{name: "wg", actions: []Action{create}})
	if _, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("apply mode did not write the file: %v", err)
	}
}

func TestReportStringShowsArtifacts(t *testing.T) {
	a, _ := FileAction(filepath.Join(t.TempDir(), "wg0.conf"), []byte("[Interface]\nListenPort = 51820\n"), 0o600, nil)
	r := Report{Mode: ModePlan, Plans: []Plan{{Component: "wireguard", Actions: []Action{a}}}}
	out := r.String()
	for _, want := range []string{"wireguard", "create", "ListenPort = 51820", "1 change"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestRemoveFileAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wipe-me.conf")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// File present ⇒ delete action; applying it removes the file.
	del, err := RemoveFileAction(path, "wipe config")
	if err != nil {
		t.Fatal(err)
	}
	if del.Kind != ActionDelete {
		t.Errorf("kind = %s, want delete", del.Kind)
	}
	eng := NewEngine(nil, stubPlanner{name: "wipe", actions: []Action{del}})
	if _, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file not removed: %v", err)
	}

	// Already-absent ⇒ no-change, never an error (idempotent wipe).
	noop, err := RemoveFileAction(path, "wipe config")
	if err != nil {
		t.Fatal(err)
	}
	if noop.Kind != ActionNoChange {
		t.Errorf("absent file kind = %s, want no-change", noop.Kind)
	}
}

func TestReportChangedComponents(t *testing.T) {
	changed, _ := FileAction(filepath.Join(t.TempDir(), "a.conf"), []byte("new\n"), 0o600, nil)
	noop := NoChangeAction("dns", "already current")
	r := Report{Mode: ModeApply, Plans: []Plan{
		{Component: "firewall", Actions: []Action{changed}},
		{Component: "dns", Actions: []Action{noop}},
		{Component: "routing", Actions: []Action{ExecAction("flush", "true")}},
	}}

	got := r.ChangedComponents()
	want := []string{"firewall", "routing"} // dns had only a no-change action
	if len(got) != len(want) {
		t.Fatalf("ChangedComponents = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ChangedComponents[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// scheduledStubPlanner is a stubPlanner that declares its changes out-of-band.
type scheduledStubPlanner struct{ stubPlanner }

func (scheduledStubPlanner) Scheduled() bool { return true }

func TestReportDriftComponentsExcludesScheduled(t *testing.T) {
	changed, _ := FileAction(filepath.Join(t.TempDir(), "a.conf"), []byte("new\n"), 0o600, nil)
	feed, _ := FileAction(filepath.Join(t.TempDir(), "feed.lst"), []byte("feed\n"), 0o600, nil)
	r := Report{Mode: ModeApply, Plans: []Plan{
		{Component: "firewall", Actions: []Action{changed}},
		{Component: "AS-blacklist feed", Scheduled: true, Actions: []Action{feed}},
	}}

	// ChangedComponents still lists every mutating plan...
	if got := r.ChangedComponents(); len(got) != 2 {
		t.Fatalf("ChangedComponents = %v, want both", got)
	}
	// ...but DriftComponents drops the scheduled one, so a daily feed refresh is
	// not misreported as config drift.
	got := r.DriftComponents()
	want := []string{"firewall"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("DriftComponents = %v, want %v", got, want)
	}
}

func TestEngineFlagsScheduledPlanner(t *testing.T) {
	changed, _ := FileAction(filepath.Join(t.TempDir(), "feed.lst"), []byte("feed\n"), 0o600, nil)
	eng := NewEngine(nil,
		scheduledStubPlanner{stubPlanner{name: "AS-blacklist feed", actions: []Action{changed}}},
		stubPlanner{name: "firewall", actions: []Action{NoChangeAction("fw", "current")}},
	)
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModePlan)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Plans[0].Scheduled {
		t.Error("engine did not flag the ScheduledPlanner's plan as scheduled")
	}
	if report.Plans[1].Scheduled {
		t.Error("non-scheduled planner's plan was flagged scheduled")
	}
	if got := report.DriftComponents(); len(got) != 0 {
		t.Errorf("DriftComponents = %v, want empty (only a scheduled change occurred)", got)
	}
}

func TestBestEffortExecSwallowsError(t *testing.T) {
	// A best-effort exec of a non-existent command must NOT return an error from
	// the engine apply (teardown tolerates already-down steps).
	a := BestEffortExecAction("teardown step", "this-command-does-not-exist-xyz")
	if a.Kind != ActionExec {
		t.Fatalf("kind = %s", a.Kind)
	}
	eng := NewEngine(nil, stubPlanner{name: "teardown", actions: []Action{a}})
	if _, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply); err != nil {
		t.Errorf("best-effort exec failure must not abort the pass: %v", err)
	}
}
