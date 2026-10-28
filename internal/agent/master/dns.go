package master

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
)

// dnsPlanner reconciles the master-tier blocky resolver (ADR-0024): a client-facing
// filtering resolver that forwards public queries to the exit blockys and local
// zones to internal DNS. It mirrors the exit dnsPlanner but ALSO binds the client-
// pool gateway (spec.Master.BindAddress) so VPN clients can use the master as their
// DNS through the tunnel. blocky has no hot-reload for upstreams, so a change to the
// active exit set restarts the container — gated by FileAction, steady state never
// restarts (a restart is sub-second and stateless; the cache repopulates).
type dnsPlanner struct {
	configPath  string
	composePath string
	// up reports whether the blocky stack is running; nil ⇒ real `docker compose ps`.
	up func(file string) bool
	// nonlocalBind reports whether net.ipv4.ip_nonlocal_bind is already on; nil ⇒ real read.
	nonlocalBind func() bool
}

func (dnsPlanner) Component() string { return "master dns filter (blocky)" }

func (p dnsPlanner) isUp(ctx context.Context) bool {
	if p.up == nil {
		return compose.StackUp(ctx, p.composePath)
	}
	return p.up(p.composePath)
}

func (p dnsPlanner) nonlocalBindOn() bool {
	if p.nonlocalBind != nil {
		return p.nonlocalBind()
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_nonlocal_bind")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func (p dnsPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.DNS.Enabled {
		return []reconcile.Action{reconcile.NoChangeAction("master dns filter", "disabled")}, nil
	}
	if spec.Master == nil || spec.Master.BindAddress == "" {
		// The client gateway is the master's own address in the client pool; until the
		// controller resolves it, defer rather than render a resolver clients can't reach.
		return []reconcile.Action{reconcile.NoChangeAction("master dns filter",
			"pending: client gateway (master bind address) unknown")}, nil
	}

	// Bind the client-pool gateway in addition to loopback/mgmt so clients reach the
	// master as their DNS through the tunnel (agent-populated, ADR-0024).
	dns := spec.DNS
	dns.ClientBindAddr = spec.Master.BindAddress

	cfg, err := dnsfilter.RenderBlocky(dns)
	if err != nil {
		return nil, fmt.Errorf("render master dns filter: %w", err)
	}
	composeYAML, err := compose.RenderBlockyCompose(compose.BlockyInput{
		Image:      dns.Image,
		ConfigPath: p.configPath,
	})
	if err != nil {
		return nil, fmt.Errorf("render master dns compose: %w", err)
	}

	cfgFile, err := reconcile.FileAction(p.configPath, []byte(cfg), 0o644, nil)
	if err != nil {
		return nil, err
	}
	composeFile, err := reconcile.FileAction(p.composePath, []byte(composeYAML), 0o644, nil)
	if err != nil {
		return nil, err
	}

	var actions []reconcile.Action
	// blocky binds the client gateway, which only exists once the client interface
	// planner has brought wg0 up. ip_nonlocal_bind lets the host-net container claim the address even if it
	// (re)starts before wg0 — e.g. after a reboot — instead of crash-looping until
	// wg0 appears. Gated on the current value so it is not a perpetual "change".
	if p.nonlocalBindOn() {
		actions = append(actions, reconcile.NoChangeAction("ip_nonlocal_bind", "already enabled"))
	} else {
		actions = append(actions, reconcile.BestEffortExecAction(
			"allow binding the not-yet-present client gateway",
			"sysctl", "-w", "net.ipv4.ip_nonlocal_bind=1"))
	}
	actions = append(actions, composeFile, cfgFile)

	// Operator extra files (Custom.Files): include lists referenced from overrides.
	extra, err := reconcile.ManagedFileActions(dns.Custom.Files, filepath.Dir(p.configPath))
	if err != nil {
		return nil, err
	}
	configChanged := cfgFile.Changes()
	for _, fa := range extra {
		actions = append(actions, fa)
		configChanged = configChanged || fa.Changes()
	}

	switch {
	case composeFile.Changes() || !reconcile.ComposeApplied(p.composePath, []byte(composeYAML)):
		// Also a file no `up -d` ever applied (killed mid-pass, image not pulled):
		// the running containers may still be the previous definition.
		actions = append(actions, reconcile.ComposeUpAction("bring master blocky stack up", p.composePath, []byte(composeYAML)))
		if configChanged && !composeFile.Changes() && p.isUp(ctx) {
			// An unchanged definition makes `up -d` a no-op for a running container,
			// so it would not reread the config. A stopped one starts with it.
			actions = append(actions, reconcile.ExecAction("restart master resolver",
				"docker", "compose", "-f", p.composePath, "restart", "blocky"))
		}
	case configChanged:
		// Config (upstreams/conditional/blocking) changed: restart blocky to reload —
		// it has no hot-reload for the resolver config (only `/lists/refresh` for lists).
		actions = append(actions, reconcile.ExecAction("restart master resolver",
			"docker", "compose", "-f", p.composePath, "restart", "blocky"))
	case !p.isUp(ctx):
		actions = append(actions, reconcile.ComposeUpAction("bring master blocky stack up (was down)", p.composePath, []byte(composeYAML)))
	default:
		actions = append(actions, reconcile.NoChangeAction("master dns filter", "resolver already up"))
	}
	return actions, nil
}
