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
	if len(ps) != 3 {
		t.Fatalf("want 3 host planners, got %d", len(ps))
	}
	return ps[0], ps[1], sshdPath, jailPath
}

// plan renders against a bare spec — no hardening policy, which every planner must
// read as "both enabled" (the pre-wire-v6 default).
func plan(t *testing.T, p reconcile.Planner) []reconcile.Action {
	t.Helper()
	return planSpec(t, p, domain.NodeSpec{})
}

func planSpec(t *testing.T, p reconcile.Planner, spec domain.NodeSpec) []reconcile.Action {
	t.Helper()
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return acts
}

// offSpec is the spec of a fleet that has switched both hardening subsystems off.
func offSpec() domain.NodeSpec {
	return domain.NodeSpec{Hardening: &domain.HardeningSpec{SSHD: false, Fail2ban: false}}
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

// --- fleet.hardening opt-out (wire v6) ---

func TestHardeningDefaultsToEnabledWhenSpecUnset(t *testing.T) {
	// The whole safety argument for the knob rests on this: a spec that says nothing
	// about hardening — a bare struct, or one from a controller predating v6 — must
	// leave the node hardened, never silently un-harden it.
	var spec domain.NodeSpec
	if !spec.SSHDHardeningEnabled() || !spec.Fail2banEnabled() {
		t.Fatalf("an unset hardening policy must read as enabled, got sshd=%v fail2ban=%v",
			spec.SSHDHardeningEnabled(), spec.Fail2banEnabled())
	}
}

func TestSSHDHardeningPlanner_DisabledRemovesDropInAndReloads(t *testing.T) {
	// Switching the knob off must actually take effect: a drop-in nothing reconciles
	// would keep overriding the operator's own sshd_config forever.
	sshd, _, sshdPath, _ := plannersFor(t, nil)
	if err := os.WriteFile(sshdPath, []byte(hardening.SSHDConfig), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	acts := planSpec(t, sshd, offSpec())
	if acts[0].Kind != reconcile.ActionDelete {
		t.Fatalf("disabled: want the drop-in deleted, got %q", acts[0].Kind)
	}
	if !hasExec(acts) {
		t.Errorf("removing the drop-in must reload sshd, else the old config stays live")
	}
}

func TestSSHDHardeningPlanner_DisabledIsQuietOnceRemoved(t *testing.T) {
	// Converged on "unmanaged": no file, so no delete and — critically — no sshd
	// reload every 30 seconds for the rest of the node's life.
	sshd, _, _, _ := plannersFor(t, nil)
	acts := planSpec(t, sshd, offSpec())
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want a single no-change action, got %+v", acts)
	}
	if hasExec(acts) {
		t.Errorf("an already-unmanaged node must not reload sshd")
	}
}

func TestFail2banPlanner_DisabledRemovesJailAndReloads(t *testing.T) {
	_, p, _, jailPath := plannersFor(t, []string{"172.29.0.0/16"})
	if err := os.WriteFile(jailPath, []byte(hardening.RenderFail2banJail([]string{"172.29.0.0/16"})), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	acts := planSpec(t, p, offSpec())
	if acts[0].Kind != reconcile.ActionDelete {
		t.Fatalf("disabled: want the jail deleted, got %q", acts[0].Kind)
	}
	if !hasExec(acts) {
		t.Errorf("removing the jail must reload fail2ban")
	}
}

func TestHardeningKnobsAreIndependent(t *testing.T) {
	// The two subsystems are separate knobs: an operator who only wants their own
	// sshd_config back must not lose brute-force protection as a side effect.
	sshd, f2b, sshdPath, jailPath := plannersFor(t, []string{"172.29.0.0/16"})
	for _, path := range []string{sshdPath, jailPath} {
		if err := os.WriteFile(path, []byte("seeded"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	spec := domain.NodeSpec{Hardening: &domain.HardeningSpec{SSHD: false, Fail2ban: true}}
	if k := planSpec(t, sshd, spec)[0].Kind; k != reconcile.ActionDelete {
		t.Errorf("sshd off: want delete, got %q", k)
	}
	if k := planSpec(t, f2b, spec)[0].Kind; k != reconcile.ActionUpdate {
		t.Errorf("fail2ban on: want the jail still reconciled (update), got %q", k)
	}
}
