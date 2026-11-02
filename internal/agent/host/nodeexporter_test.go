package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
)

const testMgmt = "10.20.0.5"

// nodeExporterFor builds a planner over a temp dir. installed says whether the
// DISTRO package is there (the only exporter the planner can repair); listening
// is what the kernel reports on the metrics port, which is what it actually acts
// on.
func nodeExporterFor(t *testing.T, installed bool, mgmt string, listening ...string) (nodeExporterPlanner, string, string) {
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
		listenAddrs: func() []string { return listening },
	}
	return p, defaults, dropIn
}

func writeConverged(t *testing.T, defaults, dropIn, mgmt string) {
	t.Helper()
	if err := os.WriteFile(defaults, []byte(nodeexporter.RenderDefaults(mgmt)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, []byte(nodeexporter.DropIn), 0o644); err != nil {
		t.Fatal(err)
	}
}

// execDisplays is the command line each exec action would run — what the planner
// DOES, as opposed to how it words it.
func execDisplays(acts []reconcile.Action) string {
	var out []string
	for _, a := range acts {
		if a.Kind == reconcile.ActionExec {
			out = append(out, a.Display)
		}
	}
	return strings.Join(out, "; ")
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

// The reason this planner exists in this shape.
//
// An operator may replace the distro package with a newer upstream node_exporter
// and mask the package's unit so the two do not fight over the port. Host metrics
// never stop flowing. An agent that recognised only the package would try to start
// the masked unit every thirty seconds and hold those nodes in Error indefinitely —
// and an Error pass skips every self-check and, on an exit, the egress failover
// with them.
//
// An optional component the operator may upgrade on their own schedule is adopted
// by WHAT IT DOES. Something is serving host metrics on the overlay ⇒ nothing to do,
// whoever is serving them.
func TestNodeExporterPlanner_AdoptsAnExporterItDoesNotOwn(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, false, testMgmt, testMgmt)
	acts := plan(t, p)
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("an exporter already serving the overlay must be left alone, got %+v", acts)
	}
	if strings.Contains(acts[0].Summary, "not installed") {
		t.Errorf("host metrics ARE being served; the summary must not read as absence: %q", acts[0].Summary)
	}
	for _, f := range []string{defaults, dropIn} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s written for an exporter wgfleet does not manage", f)
		}
	}
}

// Same, with our package still installed alongside: a serving overlay bind is the
// goal state, so the planner does not rewrite files or bounce anything to put its
// own implementation back in charge.
func TestNodeExporterPlanner_ServingBindIsNotDrift(t *testing.T) {
	p, _, _ := nodeExporterFor(t, true, testMgmt, testMgmt)
	acts := plan(t, p)
	if hasExec(acts) {
		t.Fatalf("a served overlay bind must not be touched: %q", execSummaries(acts))
	}
}

// Nothing is listening and the package is there: this IS ours to repair.
func TestNodeExporterPlanner_StoppedIsStarted(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, true, testMgmt)
	writeConverged(t, defaults, dropIn, testMgmt)
	acts := plan(t, p)
	if !hasExec(acts) {
		t.Fatalf("a down exporter we installed must be started, got %+v", acts)
	}
	if s := execSummaries(acts); !strings.Contains(s, "start") || strings.Contains(s, "restart") {
		t.Errorf("want a plain start, got %q", s)
	}
}

// Fresh node: both files are written and the service is (re)started so the bind
// takes effect.
func TestNodeExporterPlanner_FreshWriteRestarts(t *testing.T) {
	p, defaults, _ := nodeExporterFor(t, true, testMgmt)
	acts := plan(t, p)
	if !strings.Contains(execDisplays(acts), "systemctl restart") {
		t.Fatalf("fresh write must restart the exporter, got %q", execDisplays(acts))
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

// Nothing listening and no package: there is nothing to install and nothing to
// repair. Say so — silence here reads exactly like a healthy node.
func TestNodeExporterPlanner_NotInstalledIsANoop(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, false, testMgmt)
	acts := plan(t, p)
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want a single no-change action, got %+v", acts)
	}
	if !strings.Contains(acts[0].Summary, "no host metrics") {
		t.Errorf("the no-op must say this node has no host metrics, got %q", acts[0].Summary)
	}
	for _, f := range []string{defaults, dropIn} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s written for an absent exporter", f)
		}
	}
}

// A wildcard bind serves the overlay address too, so it would pass any "can I
// reach <mgmt>:9100" probe — while publishing every listening socket, mount and
// interface on the box to anyone who can reach the port (DESIGN §9). Ours to fix.
func TestNodeExporterPlanner_ExposedBindIsRebound(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, true, testMgmt, "0.0.0.0")
	writeConverged(t, defaults, dropIn, testMgmt)
	acts := plan(t, p)
	if !strings.Contains(execDisplays(acts), "systemctl restart") {
		t.Fatalf("an exposed exporter must be rebound onto the overlay, got %q", execDisplays(acts))
	}
}

// Exposed, but by a unit we did not install: we cannot fix it and must not
// pretend otherwise. It still has to be the loudest thing the component says.
func TestNodeExporterPlanner_ExposedButNotOursIsReported(t *testing.T) {
	p, _, _ := nodeExporterFor(t, false, testMgmt, "0.0.0.0")
	acts := plan(t, p)
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want a single no-change action, got %+v", acts)
	}
	if !strings.Contains(acts[0].Summary, "beyond the management overlay") {
		t.Errorf("the summary must name the exposure, got %q", acts[0].Summary)
	}
}

// The mgmt address moved (re-provision, overlay change): the old bind is a silent
// hole in the host metrics, so the file changes and the exporter is restarted.
func TestNodeExporterPlanner_MgmtChangeRebinds(t *testing.T) {
	p, defaults, dropIn := nodeExporterFor(t, true, "10.20.0.6", "10.20.0.5")
	writeConverged(t, defaults, dropIn, "10.20.0.5")
	acts := plan(t, p)
	if !strings.Contains(execDisplays(acts), "systemctl restart") {
		t.Fatalf("changed bind must restart, got %q", execDisplays(acts))
	}
}

// Host metrics are observability, and observability must never decide whether a
// node is healthy. A masked unit, a package half-removed, an exporter somebody is
// mid-upgrade — none of it may fail the pass, because a failed pass costs the node
// its self-checks and an exit its egress failover. The absence of host metrics has
// its own alarm (WgfleetHostMetricsMissing, on the scrape target), which is the one
// that can see a node this agent cannot reach at all.
func TestNodeExporterPlanner_NeverFailsThePass(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed bool
		listening []string
	}{
		{"fresh install", true, nil},
		{"stopped exporter", true, nil},
		{"exposed bind", true, []string{"0.0.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := nodeExporterFor(t, tc.installed, testMgmt, tc.listening...)
			for _, a := range plan(t, p) {
				if a.Kind == reconcile.ActionExec && !a.NonFatal {
					t.Errorf("exec action %q is fatal; host metrics must not decide node state", a.Summary)
				}
			}
		})
	}
}
