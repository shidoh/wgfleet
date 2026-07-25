package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/hardening"
)

// plannersFor builds the host planners writing under a temp dir and returns the
// sshd and fail2ban planners plus their target paths.
func plannersFor(t *testing.T, cidrs []string) (sshd, f2b reconcile.Planner, sshdPath, jailPath string) {
	t.Helper()
	dir := t.TempDir()
	sshdPath = filepath.Join(dir, "10-wgfleet-hardening.conf")
	jailPath = filepath.Join(dir, "wgfleet.conf")
	ps := Planners(Input{SSHDConfigPath: sshdPath, Fail2banJailPath: jailPath, MgmtIgnoreCIDRs: cidrs})
	if len(ps) != 2 {
		t.Fatalf("want 2 host planners, got %d", len(ps))
	}
	return ps[0], ps[1], sshdPath, jailPath
}

func plan(t *testing.T, p reconcile.Planner) []reconcile.Action {
	t.Helper()
	acts, err := p.Plan(context.Background(), domain.NodeSpec{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return acts
}

func hasExec(acts []reconcile.Action) bool {
	for _, a := range acts {
		if a.Kind == reconcile.ActionExec {
			return true
		}
	}
	return false
}

func TestSSHDHardeningPlanner_FreshWriteReloads(t *testing.T) {
	sshd, _, _, _ := plannersFor(t, nil)
	if sshd.Component() != "sshd hardening" {
		t.Fatalf("unexpected component %q", sshd.Component())
	}
	acts := plan(t, sshd)
	if acts[0].Kind != reconcile.ActionCreate {
		t.Errorf("first pass: want file create, got %q", acts[0].Kind)
	}
	if acts[0].Display != hardening.SSHDConfig {
		t.Errorf("planned content is not the canonical sshd drop-in:\n%s", acts[0].Display)
	}
	if !hasExec(acts) {
		t.Errorf("a fresh write must reload sshd")
	}
}

func TestSSHDHardeningPlanner_ConvergedNoReload(t *testing.T) {
	sshd, _, sshdPath, _ := plannersFor(t, nil)
	if err := os.WriteFile(sshdPath, []byte(hardening.SSHDConfig), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	acts := plan(t, sshd)
	if acts[0].Kind != reconcile.ActionNoChange {
		t.Errorf("converged: want no-change, got %q", acts[0].Kind)
	}
	if hasExec(acts) {
		t.Errorf("converged: must not reload sshd")
	}
}

func TestSSHDHardeningPlanner_DriftRepaired(t *testing.T) {
	// A partial overwrite (the 2026-07-25 incident: only X11Forwarding survived) must be
	// repaired: the full hardening returns and sshd is reloaded.
	sshd, _, sshdPath, _ := plannersFor(t, nil)
	if err := os.WriteFile(sshdPath, []byte("X11Forwarding no\n"), 0o644); err != nil {
		t.Fatalf("seed drift: %v", err)
	}
	acts := plan(t, sshd)
	if acts[0].Kind != reconcile.ActionUpdate {
		t.Errorf("drift: want update, got %q", acts[0].Kind)
	}
	if acts[0].Display != hardening.SSHDConfig {
		t.Errorf("drift repair must restore full hardening:\n%s", acts[0].Display)
	}
	if !hasExec(acts) {
		t.Errorf("drift repair must reload sshd")
	}
}

func TestSSHDHardeningPlanner_ModeOnlyDriftDoesNotReload(t *testing.T) {
	// Content already correct but the file mode drifted (a stray chmod). FileAction
	// repairs the mode, but the reload gate is content-only, so sshd is NOT bounced.
	sshd, _, sshdPath, _ := plannersFor(t, nil)
	if err := os.WriteFile(sshdPath, []byte(hardening.SSHDConfig), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	acts := plan(t, sshd)
	if acts[0].Kind != reconcile.ActionUpdate {
		t.Errorf("mode drift: want update (mode repair), got %q", acts[0].Kind)
	}
	if hasExec(acts) {
		t.Errorf("mode-only repair must NOT reload sshd")
	}
}

func TestFail2banPlanner_WritesWhenCIDRsConfigured(t *testing.T) {
	_, f2b, _, _ := plannersFor(t, []string{"172.29.0.0/16"})
	acts := plan(t, f2b)
	if acts[0].Kind != reconcile.ActionCreate {
		t.Errorf("want jail create, got %q", acts[0].Kind)
	}
	if want := "ignoreip = 127.0.0.1/8 ::1 172.29.0.0/16"; !strings.Contains(acts[0].Display, want) {
		t.Errorf("jail ignoreip missing %q:\n%s", want, acts[0].Display)
	}
	if !hasExec(acts) {
		t.Errorf("a fresh jail write must reload fail2ban")
	}
}

func TestFail2banPlanner_NoopWhenNoCIDRs(t *testing.T) {
	// Without mgmt CIDRs the planner must not touch the jail — an un-reprovisioned node
	// keeps whatever bootstrap installed, never regressed to a narrower ignoreip.
	_, f2b, _, jailPath := plannersFor(t, nil)
	acts := plan(t, f2b)
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want a single no-change action, got %+v", acts)
	}
	if hasExec(acts) {
		t.Errorf("no-op planner must not reload fail2ban")
	}
	if _, err := os.Stat(jailPath); !os.IsNotExist(err) {
		t.Errorf("no-op planner must not create the jail file")
	}
}
