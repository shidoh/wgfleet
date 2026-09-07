package host

import (
	"context"
	"os"
	"os/exec"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
)

// nodeExporterPlanner keeps the host-metrics exporter bound to the management
// overlay and running. It mirrors the bootstrap step that installs the same two
// files, so a bind that drifted (the overlay address changed, a package upgrade
// rewrote /etc/default) is repaired on the next pass rather than leaving a silent
// hole in the host metrics — the kind of hole that hid three exits dropping out
// of rotation for two weeks.
//
// It never installs anything. A node provisioned before host metrics existed has
// no exporter, and the planner says so every pass instead of writing config for
// a service that is not there; re-provisioning (or the one-off apt install the
// operator does in its place) is what closes that.
type nodeExporterPlanner struct {
	defaultsPath string
	dropInPath   string
	binary       string
	mgmtAddr     string
	// active reports whether the unit is running; nil ⇒ `systemctl is-active`.
	active func() bool
}

func newNodeExporterPlanner(in Input) nodeExporterPlanner {
	p := nodeExporterPlanner{
		defaultsPath: in.NodeExporterDefaultsPath,
		dropInPath:   in.NodeExporterDropInPath,
		binary:       in.NodeExporterBinary,
		mgmtAddr:     in.MgmtAddr,
	}
	if p.defaultsPath == "" {
		p.defaultsPath = nodeexporter.DefaultsPath
	}
	if p.dropInPath == "" {
		p.dropInPath = nodeexporter.DropInPath
	}
	if p.binary == "" {
		p.binary = nodeexporter.Binary
	}
	return p
}

func (nodeExporterPlanner) Component() string { return "host metrics exporter" }

func (p nodeExporterPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	if _, err := os.Stat(p.binary); err != nil {
		return []reconcile.Action{reconcile.NoChangeAction("host metrics exporter",
			nodeexporter.Package+" not installed (bootstrap installs it; re-provision the node) — no host metrics from this node")}, nil
	}
	defaults := []byte(nodeexporter.RenderDefaults(p.mgmtAddr))
	dropIn := []byte(nodeexporter.DropIn)
	// Restart only on a CONTENT change, not on FileAction.Changes(): a mode-only
	// repair must not bounce the exporter every pass.
	changed := contentDiffers(p.defaultsPath, defaults) || contentDiffers(p.dropInPath, dropIn)
	defFile, err := reconcile.FileAction(p.defaultsPath, defaults, 0o644, nil)
	if err != nil {
		return nil, err
	}
	dropFile, err := reconcile.FileAction(p.dropInPath, dropIn, 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{defFile, dropFile}
	switch {
	case changed:
		actions = append(actions, reconcile.ExecAction(
			"restart the host metrics exporter onto the new bind", "sh", "-c",
			"systemctl daemon-reload && systemctl enable "+nodeexporter.Unit+" && systemctl restart "+nodeexporter.Unit))
	case !p.isActive():
		// Config converged but the service is down: stopped by hand, or it hit a
		// start limit before the overlay address existed (older drop-in). Start it;
		// do not rewrite anything.
		actions = append(actions, reconcile.ExecAction(
			"start the host metrics exporter (was down)", "sh", "-c",
			"systemctl enable "+nodeexporter.Unit+" && systemctl start "+nodeexporter.Unit))
	default:
		actions = append(actions, reconcile.NoChangeAction("host metrics exporter", "bound to the mgmt address and running"))
	}
	return actions, nil
}

func (p nodeExporterPlanner) isActive() bool {
	if p.active != nil {
		return p.active()
	}
	return exec.Command("systemctl", "is-active", "--quiet", nodeexporter.Unit).Run() == nil
}
