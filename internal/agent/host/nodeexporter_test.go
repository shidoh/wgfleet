package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
)

func nodeExporterFor(t *testing.T, installed bool, mgmt string, active bool) (nodeExporterPlanner, string, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "prometheus-node-exporter")
	if installed {
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	defaults := filepath.Join(dir, "default")
	dropIn := filepath.Join(dir, "wgfleet.conf")
	p := nodeExporterPlanner{
		defaultsPath: defaults, dropInPath: dropIn, binary: bin, mgmtAddr: mgmt,
		active: func() bool { return active },
	}
	return p, defaults, dropIn
}

func execSummaries(acts []reconcile.Action) string {
	var out []string
	for _, a := range acts {
		if a.Kind == reconcile.ActionExec {
			out = append(out, a.Summary)
		}
	}
	return strings.Join(out, "; ")
}

// A node the bootstrap never gave an exporter (every node provisioned before this
// existed) must be left alone, loudly: the planner cannot install packages, and a
// config file for a service that is not there would be drift nobody asked for.
func TestNodeExporterPlanner_NotInstalledIsANoop(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, false, "10.20.0.5", false)
	acts := plan(t, p)
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want a single no-change action, got %+v", acts)
	}
	if !strings.Contains(acts[0].Summary, "not installed") {
		t.Errorf("the no-op must say the exporter is missing, got %q", acts[0].Summary)
	}
	for _, f := range []string{defaults, dropIn} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s written for an absent exporter", f)
		}
	}
}

// Fresh node: both files are written and the service is (re)started so the new
// bind takes effect.
func TestNodeExporterPlanner_FreshWriteRestarts(t *testing.T) {
	p, defaults, _ := nodeExporterFor(t, true, "10.20.0.5", false)
	acts := plan(t, p)
	if !hasExec(acts) {
		t.Fatalf("fresh write must restart the exporter, got %+v", acts)
	}
	if !strings.Contains(execSummaries(acts), "restart") {
		t.Errorf("want a restart, got %q", execSummaries(acts))
	}
	var creates int
	for _, a := range acts {
		if a.Kind == reconcile.ActionCreate {
			creates++
		}
	}
	if creates != 2 {
		t.Errorf("fresh node must create both files, got %d creates in %+v", creates, acts)
	}
	if _, err := os.Stat(defaults); err == nil {
		t.Errorf("planning must not write; %s exists", defaults)
	}
}

// Converged and running: nothing to do, and in particular no restart — the
// exporter would otherwise be bounced every thirty seconds.
func TestNodeExporterPlanner_ConvergedDoesNotRestart(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, true, "10.20.0.5", true)
	if err := os.WriteFile(defaults, []byte(nodeexporter.RenderDefaults("10.20.0.5")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, []byte(nodeexporter.DropIn), 0o644); err != nil {
		t.Fatal(err)
	}
	if acts := plan(t, p); hasExec(acts) {
		t.Fatalf("converged node must not restart the exporter: %q", execSummaries(acts))
	}
}

// Converged on disk but not running (stopped by hand, or bind failed before the
// overlay came up and the unit hit its limit): start it, do not rewrite anything.
func TestNodeExporterPlanner_StoppedIsStarted(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, true, "10.20.0.5", false)
	if err := os.WriteFile(defaults, []byte(nodeexporter.RenderDefaults("10.20.0.5")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, []byte(nodeexporter.DropIn), 0o644); err != nil {
		t.Fatal(err)
	}
	acts := plan(t, p)
	if !hasExec(acts) {
		t.Fatalf("stopped exporter must be started, got %+v", acts)
	}
	if s := execSummaries(acts); !strings.Contains(s, "start") || strings.Contains(s, "restart") {
		t.Errorf("want a plain start, got %q", s)
	}
}

// The mgmt address moved (re-provision, overlay change): the file changes and the
// exporter is restarted onto the new bind — a stale bind is a silent hole in the
// host metrics, exactly the kind that took two weeks to notice on the tunnels.
func TestNodeExporterPlanner_MgmtChangeRebinds(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, true, "10.20.0.6", true)
	if err := os.WriteFile(defaults, []byte(nodeexporter.RenderDefaults("10.20.0.5")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, []byte(nodeexporter.DropIn), 0o644); err != nil {
		t.Fatal(err)
	}
	acts := plan(t, p)
	if !strings.Contains(execSummaries(acts), "restart") {
		t.Fatalf("changed bind must restart, got %q", execSummaries(acts))
	}
}
