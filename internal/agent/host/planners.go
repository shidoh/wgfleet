// Package host holds the role-agnostic reconcile planners that keep a node's host
// hardening converged: the sshd drop-in, the fail2ban sshd jail, and the apt hold
// on the AmneziaWG packages. They run on every node (master and exit) so that,
// unlike the one-shot bootstrap steps they mirror, a drifted or hand-overwritten
// file — or a hold that a later-provisioned node never got — is repaired on the
// next reconcile pass.
//
// Both subsystems are individually switchable from the fleet manifest
// (fleet.hardening, wire v6). The policy arrives per-pass on the NodeSpec rather
// than in Input because it is fleet state the operator can change at any moment,
// whereas Input carries the node-local paths fixed at start-up. An unset policy
// means enabled, so a node whose controller predates the knob stays hardened.
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
	// MgmtAddr is this node's overlay address, the only thing the host-metrics
	// exporter may bind. Empty binds loopback (see nodeexporter.RenderDefaults).
	MgmtAddr string
	// NodeExporter* default to the package's canonical paths; tests override them.
	NodeExporterDefaultsPath string
	NodeExporterDropInPath   string
	NodeExporterBinary       string
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
		// Unconditional: unlike the two above it has no fleet.hardening knob, because
		// holding a package never conflicts with a deliberate operator upgrade. See
		// awgHoldPlanner's doc comment.
		awgHoldPlanner{},
		newNodeExporterPlanner(in),
	}
}

// --- sshd hardening ---

type sshdHardeningPlanner struct{ path string }

func (sshdHardeningPlanner) Component() string { return "sshd hardening" }

func (p sshdHardeningPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.SSHDHardeningEnabled() {
		return unmanage(p.path, "sshd hardening",
			"disabled by fleet.hardening.sshd; removing the managed drop-in",
			"reload sshd (hardening drop-in removed)",
			"systemctl reload sshd || systemctl reload ssh")
	}
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

func (p fail2banPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.Fail2banEnabled() {
		return unmanage(p.path, "fail2ban sshd jail",
			"disabled by fleet.hardening.fail2ban; removing the managed jail",
			"reload fail2ban (jail removed)",
			"systemctl reload fail2ban || systemctl restart fail2ban")
	}
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

// unmanage renders the "this subsystem is switched off" plan: remove the file
// wgfleet installed and, only if it was actually there, reload the service so the
// node falls back to the operator's own configuration.
//
// Removal — rather than simply ceasing to reconcile — is the point of the knob. A
// leftover drop-in that nothing manages any more would keep overriding the
// operator's sshd_config forever, so "off" would not actually turn anything off.
// It is not a silent weakening either: the delete is an ordinary plan action and
// shows up in `--plan` before it is ever applied.
func unmanage(path, component, removeSummary, reloadSummary, reloadCmd string) ([]reconcile.Action, error) {
	rm, err := reconcile.RemoveFileAction(path, removeSummary)
	if err != nil {
		return nil, err
	}
	if !rm.Changes() {
		// Already gone: converged on "unmanaged", so say so plainly instead of
		// re-reporting an absent file every 30 seconds.
		return []reconcile.Action{reconcile.NoChangeAction(component, "disabled by fleet policy; nothing to remove")}, nil
	}
	return []reconcile.Action{rm, reconcile.ExecAction(reloadSummary, "sh", "-c", reloadCmd)}, nil
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
