// Package host holds the role-agnostic reconcile planners that keep a node's host
// hardening converged: the sshd drop-in and the fail2ban sshd jail. They run on
// every node (master and exit) so that, unlike the one-shot bootstrap steps they
// mirror, a drifted or hand-overwritten file is repaired on the next reconcile pass.
package host

import (
	"bytes"
	"context"
	"os"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/hardening"
)

// Input configures the host planners. The path fields default to the canonical
// on-node hardening paths; tests override them to write under a temp dir.
type Input struct {
	SSHDConfigPath   string
	Fail2banJailPath string
	// MgmtIgnoreCIDRs are the management-overlay scopes fail2ban must never ban.
	// Empty leaves the fail2ban jail unmanaged (see fail2banPlanner.Plan) so an
	// un-reprovisioned node keeps the jail bootstrap installed. NB: this is an
	// agent-local value baked into agent.yaml at provisioning (like MgmtOverlayMSS);
	// the planner reconciles the jail against THIS value, not against live fleet
	// config, so a later fleet.mgmt_subnet change reaches a node only on re-provision.
	MgmtIgnoreCIDRs []string
}

// Planners returns the host-hardening reconcile planners applied on every node
// regardless of role.
func Planners(in Input) []reconcile.Planner {
	sshdPath := in.SSHDConfigPath
	if sshdPath == "" {
		sshdPath = hardening.SSHDDropInPath
	}
	jailPath := in.Fail2banJailPath
	if jailPath == "" {
		jailPath = hardening.Fail2banJailPath
	}
	return []reconcile.Planner{
		sshdHardeningPlanner{path: sshdPath},
		fail2banPlanner{path: jailPath, ignoreCIDRs: in.MgmtIgnoreCIDRs},
	}
}

// --- sshd hardening ---

type sshdHardeningPlanner struct{ path string }

func (sshdHardeningPlanner) Component() string { return "sshd hardening" }

func (p sshdHardeningPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	content := []byte(hardening.SSHDConfig)
	// Gate the reload on a real CONTENT change, not on FileAction.Changes(): that also
	// reports true for a mode-only repair (see reconcile/plan.go), and bouncing sshd
	// for a stray chmod is needless churn.
	reload := contentDiffers(p.path, content)
	file, err := reconcile.FileAction(p.path, content, 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	if reload {
		// reload (not restart): graceful, keeps live sessions. The unit is `sshd` on
		// most distros and `ssh` on Debian/Ubuntu, so try both (order matches bootstrap).
		actions = append(actions, reconcile.ExecAction(
			"reload sshd (hardening changed)", "sh", "-c",
			"systemctl reload sshd || systemctl reload ssh"))
	} else {
		actions = append(actions, reconcile.NoChangeAction("sshd hardening", "drop-in already current"))
	}
	return actions, nil
}

// --- fail2ban sshd jail ---

type fail2banPlanner struct {
	path        string
	ignoreCIDRs []string
}

func (fail2banPlanner) Component() string { return "fail2ban sshd jail" }

func (p fail2banPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	// The jail's whole purpose is to never ban the operator/control plane, which
	// reach nodes over the mgmt overlay. Without the overlay CIDRs we cannot render a
	// safe ignoreip, so we leave whatever bootstrap installed untouched rather than
	// risk narrowing it. A re-provisioned node carries the CIDRs in agent.yaml and is
	// managed here from then on.
	if len(p.ignoreCIDRs) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("fail2ban sshd jail",
			"mgmt ignore CIDRs not configured; leaving bootstrap jail in place")}, nil
	}
	content := []byte(hardening.RenderFail2banJail(p.ignoreCIDRs))
	// Reload only on a real content change (not a mode-only repair): `reload` keeps the
	// in-memory ban state that a `restart` would drop.
	reload := contentDiffers(p.path, content)
	file, err := reconcile.FileAction(p.path, content, 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	if reload {
		actions = append(actions, reconcile.ExecAction(
			"reload fail2ban (jail changed)", "sh", "-c",
			"systemctl reload fail2ban || systemctl restart fail2ban"))
	} else {
		actions = append(actions, reconcile.NoChangeAction("fail2ban sshd jail", "jail already current"))
	}
	return actions, nil
}

// contentDiffers reports whether the file at path is absent/unreadable or its bytes
// differ from want. It gates a service reload on a genuine content change, so a
// mode-only drift repair (which FileAction still writes) does not bounce the service.
func contentDiffers(path string, want []byte) bool {
	got, err := os.ReadFile(path)
	if err != nil {
		return true // absent/unreadable → FileAction will (re)write it
	}
	return !bytes.Equal(got, want)
}
