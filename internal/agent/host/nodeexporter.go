package host

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
)

// nodeExporterPlanner keeps host metrics being served on the management overlay
// — and stops there.
//
// The exporter is an OPTIONAL component: the fleet does not ship it, does not pin
// its version, and must not stand between the operator and an upgrade of it. What
// the planner asserts is therefore the outcome (something is exporting host
// metrics, and only over the overlay), not the implementation. Whatever is
// serving that bind is adopted as-is, whether it is the distro package the
// bootstrap installed or a newer binary the operator put there this morning.
//
// It repairs only what wgfleet installed — the distro package's unit, via the two
// files bootstrap laid down — and it never fails the pass while doing it. Host
// metrics are observability; a node that cannot report its CPU is not a node that
// should lose its self-checks, and on an exit a failed pass also costs the egress
// failover. The alarm for "no host metrics" lives where it belongs, on the scrape
// target (WgfleetHostMetricsMissing).
type nodeExporterPlanner struct {
	defaultsPath string
	dropInPath   string
	binary       string
	mgmtAddr     string
	// listenAddrs reports who is listening on the metrics port; nil ⇒ the kernel.
	listenAddrs func() []string
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
	addrs := p.binds()
	bind := nodeexporter.ClassifyBind(addrs, p.mgmtAddr)
	ours := p.packageInstalled()

	// Served on the overlay and nowhere else: the goal state. Who produced it, and
	// with which version, is the operator's business.
	if bind == nodeexporter.BindMgmt {
		return []reconcile.Action{reconcile.NoChangeAction("host metrics exporter",
			fmt.Sprintf("host metrics served on %s:%d", p.mgmtAddr, nodeexporter.Port))}, nil
	}

	if !ours {
		// Nothing of ours to repair. Two very different silences, and the summary is
		// the only place they are told apart.
		if bind == nodeexporter.BindExposed {
			return []reconcile.Action{reconcile.NoChangeAction("host metrics exporter",
				fmt.Sprintf("host metrics are served beyond the management overlay (%s:%d) by a unit wgfleet does not manage — bind it to %s",
					strings.Join(addrs, ", "), nodeexporter.Port, p.mgmtAddr))}, nil
		}
		return []reconcile.Action{reconcile.NoChangeAction("host metrics exporter",
			"no host metrics from this node: nothing is serving :"+fmt.Sprint(nodeexporter.Port)+
				" and "+nodeexporter.Package+" is not installed (the bootstrap installs it; re-provision the node, or install an exporter bound to "+p.mgmtAddr+")")}, nil
	}

	// Ours, and either down or bound somewhere it should not be.
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
	case changed || bind == nodeexporter.BindExposed:
		// A wrong bind is only corrected by a restart: the process has the old
		// address open, and rewriting the file under it changes nothing until then.
		summary := "restart the host metrics exporter onto the new bind"
		if bind == nodeexporter.BindExposed {
			summary = fmt.Sprintf("rebind the host metrics exporter onto %s (it is answering on %s)",
				p.mgmtAddr, strings.Join(addrs, ", "))
		}
		actions = append(actions, reconcile.BestEffortExecAction(summary, "sh", "-c",
			"systemctl daemon-reload && systemctl enable "+nodeexporter.Unit+" && systemctl restart "+nodeexporter.Unit))
	default:
		// Config converged but nothing is listening: stopped by hand, masked in favour
		// of another exporter, or it hit a start limit before the overlay address
		// existed. Try to start it; do not rewrite anything, and do not insist.
		actions = append(actions, reconcile.BestEffortExecAction(
			"start the host metrics exporter (nothing is serving the metrics port)", "sh", "-c",
			"systemctl enable "+nodeexporter.Unit+" && systemctl start "+nodeexporter.Unit))
	}
	return actions, nil
}

// packageInstalled reports whether the distro exporter — the only one this
// planner can repair — is on the box.
func (p nodeExporterPlanner) packageInstalled() bool {
	_, err := os.Stat(p.binary)
	return err == nil
}

// binds asks the kernel who holds the metrics port. An unreadable table answers
// "nobody", which costs at worst one idempotent start.
func (p nodeExporterPlanner) binds() []string {
	if p.listenAddrs != nil {
		return p.listenAddrs()
	}
	addrs, err := nodeexporter.ListenAddrs(nodeexporter.Port)
	if err != nil {
		return nil
	}
	return addrs
}
