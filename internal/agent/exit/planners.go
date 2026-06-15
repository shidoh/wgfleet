package exit

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/routing"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Input is everything the exit planners need beyond the NodeSpec. PrivateKey is
// the node's WG key (a real persisted key in apply mode, or an ephemeral one in
// plan mode). WARP is the registered wgcf material; nil until `wgcf register`
// has run, in which case the WARP planner emits a notice instead of a config.
type Input struct {
	Paths      Paths
	PrivateKey string
	WARP       *egress.WARPConfig
	// IfaceUp reports whether a network interface currently exists/is up. It lets
	// the WG/WARP planners bring an interface up when it is down even though its
	// config file is unchanged (after a reboot, or a previously failed `up`).
	// nil ⇒ a real `ip link show` check; tests inject a stub.
	IfaceUp func(name string) bool
}

// Planners returns the ordered exit reconcilers: firewall first (so the box is
// protected before interfaces come up), then the WG interface, the WARP egress,
// routing, and the DNS filter.
func Planners(in Input) []reconcile.Planner {
	up := in.IfaceUp
	if up == nil {
		up = ipLinkUp
	}
	return []reconcile.Planner{
		firewallPlanner{path: in.Paths.NFT},
		wgPlanner{path: in.Paths.WGConf, privateKey: in.PrivateKey, up: up},
		warpPlanner{path: in.Paths.WGCF, dir: in.Paths.WARPDir, warp: in.WARP, up: up},
		routingPlanner{statePath: in.Paths.RoutingState},
		dnsPlanner{configPath: in.Paths.DNS, composePath: in.Paths.DNSCompose},
	}
}

// ipLinkUp reports whether a network interface exists (WG/AWG interfaces are
// created by *-quick up, so "exists" means "up"). Used by the WG/WARP planners
// to converge to the desired RUNNING state, not just the desired config.
func ipLinkUp(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

// ifaceName derives the interface name from a *-quick config path
// (/etc/.../awg0.conf → awg0; /etc/.../wgcf.conf → wgcf).
func ifaceName(confPath string) string {
	return strings.TrimSuffix(filepath.Base(confPath), ".conf")
}

// --- firewall ---

type firewallPlanner struct {
	path string
	// loaded reports whether the live kernel has the exit firewall table.
	// nil ⇒ a real `nft list table inet wgfleet` probe; tests inject a stub.
	loaded func() bool
}

func (firewallPlanner) Component() string { return "firewall (nftables)" }

func (p firewallPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	in := netfw.RenderInput{
		Firewall: spec.Firewall,
		Role:     spec.Role,
		DropQUIC: spec.Role == domain.RoleMaster,
	}
	// On an egress-routed exit, mark this node's WG-server reply/handshake packets
	// so the routing `ip rule fwmark` keeps them off the WARP interface (earlier findings
	// ). The mark MUST match the routing ip-rule's, so both resolve it the same
	// way. Direct egress ⇒ no egress interface ⇒ no mark needed.
	if spec.Routing.EgressInterface != "" {
		in.WGReplyMark = routing.EffectiveFwMark(spec.Routing)
	}
	ruleset, err := netfw.RenderRuleset(in)
	if err != nil {
		return nil, err
	}
	file, err := reconcile.FileAction(p.path, []byte(ruleset), 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	switch {
	case file.Changes():
		actions = append(actions, reconcile.ExecAction("apply ruleset atomically", "nft", "-f", p.path))
	case !p.isLoaded():
		// Ruleset unchanged but the kernel lost the table — a reboot, a manual flush,
		// or a re-provision that re-applied the baseline. Reload to self-heal (ADR-0015
		// pattern, mirroring masterNATPlanner/routingPlanner). Without this the exit
		// would silently run with no whitelist/AS-blacklist while health checks pass.
		actions = append(actions, reconcile.ExecAction("reload firewall (kernel table missing)", "nft", "-f", p.path))
	default:
		actions = append(actions, reconcile.NoChangeAction("nft -f", "ruleset already loaded"))
	}
	return actions, nil
}

func (p firewallPlanner) isLoaded() bool {
	if p.loaded == nil {
		return firewallLoaded()
	}
	return p.loaded()
}

// firewallLoaded is the real kernel probe behind firewallPlanner.isLoaded:
// `nft list table inet wgfleet` succeeds only when the table is present. Any exec
// error (table absent, non-Linux, missing nft) reports "not loaded" so the planner
// re-applies — harmless in plan mode, self-healing on a real node.
func firewallLoaded() bool {
	return exec.Command("nft", "list", "table", "inet", netfw.ExitTable).Run() == nil
}

// --- wireguard / amneziawg interface ---

type wgPlanner struct {
	path       string
	privateKey string
	up         func(name string) bool
}

func (wgPlanner) Component() string { return "wireguard interface" }

func (p wgPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	// AmneziaWG obfuscation is interface-level (spec.WGServer.AWG); peers are plain.
	cfg, err := wg.RenderInterface(wg.RenderInput{
		Spec:       spec.WGServer,
		Peers:      spec.Peers,
		PrivateKey: p.privateKey,
	})
	if err != nil {
		return nil, err
	}
	file, err := reconcile.FileAction(p.path, []byte(cfg), 0o600, wg.RedactConfig)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	switch {
	case file.Changes():
		// Config changed: re-apply. down is best-effort (the interface does not
		// exist on the first run, and `awg-quick down` errors on a missing one).
		actions = append(actions,
			reconcile.BestEffortExecAction("bring interface down (if up)", "awg-quick", "down", p.path),
			reconcile.ExecAction("bring interface up with new config", "awg-quick", "up", p.path))
	case !p.isUp():
		// Config unchanged but the interface is down (reboot, or a prior up failed):
		// bring it up so reconcile converges to the running state, not just config.
		actions = append(actions,
			reconcile.ExecAction("bring interface up (interface was down)", "awg-quick", "up", p.path))
	default:
		actions = append(actions, reconcile.NoChangeAction("awg-quick", "interface already up"))
	}
	return actions, nil
}

func (p wgPlanner) isUp() bool {
	if p.up == nil {
		return ipLinkUp(ifaceName(p.path))
	}
	return p.up(ifaceName(p.path))
}

// shArg single-quotes a string for safe interpolation into an `sh -c` command.
func shArg(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// --- WARP egress (wgcf) ---

type warpPlanner struct {
	path string
	dir  string // WARPDir: where wgcf keeps the account + generated profile
	warp *egress.WARPConfig
	up   func(name string) bool
}

func (warpPlanner) Component() string { return "warp egress (wgcf)" }

func (p warpPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.EgressChainHas(domain.EgressWARP) {
		return nil, nil // WARP not a candidate egress: nothing to render
	}
	// NB: wgcf is brought up whenever WARP is ANYWHERE in the chain, even while the
	// node is failed over to a fallback (active egress != warp). The tunnel stays
	// established (cheap, keepalive) but client traffic only routes through it when
	// the routing planner points at it (active == warp), so recovery can be probed
	// without disrupting client traffic (ADR-0017).
	if p.warp == nil {
		// No parsed credentials yet: register (once — one key per node, an earlier finding;
		// --accept-tos avoids the interactive ToS prompt that fails on EOF) and
		// generate the profile. Idempotent: register only when there is no account
		// file, generate every pass (it just rewrites the profile from the account).
		// The NEXT reconcile reads + parses the profile and renders the interface.
		cmd := fmt.Sprintf(
			"mkdir -p %s && cd %s && { test -f wgcf-account.toml || wgcf register --accept-tos; } && wgcf generate",
			shArg(p.dir), shArg(p.dir))
		return []reconcile.Action{reconcile.ExecAction(
			"register + generate Cloudflare WARP profile (wgcf)", "sh", "-c", cmd,
		)}, nil
	}
	cfg := *p.warp
	if cfg.MTU == 0 {
		// WARP rides the exit's own physical link to Cloudflare (sequential model,
		// ADR-0014): the master↔exit tunnel terminates here and the bare payload is
		// re-encapsulated afresh, so WARP's carrier is the physical MTU, never the
		// inner master↔exit MTU (that would set WARP below the client MTU and
		// fragment every egress packet, an earlier finding). The controller pins the value in
		// spec.WARPMTU (operator override for a constrained WARP path, an earlier finding's
		// 1320-1420 band); fall back to the computed 1440 when unset. WARP is vanilla
		// WG — Cloudflare can't do AmneziaWG.
		if spec.WARPMTU > 0 {
			cfg.MTU = spec.WARPMTU
		} else {
			cfg.MTU = wg.FleetTunnelMTU(false, false)
		}
	}
	content, err := egress.RenderWGCF(cfg)
	if err != nil {
		return nil, err
	}
	file, err := reconcile.FileAction(p.path, []byte(content), 0o600, wg.RedactConfig)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	switch {
	case file.Changes():
		actions = append(actions,
			reconcile.BestEffortExecAction("bring WARP down (if up)", "wg-quick", "down", p.path),
			reconcile.ExecAction("bring WARP interface up", "wg-quick", "up", p.path))
	case !p.isUp():
		actions = append(actions,
			reconcile.ExecAction("bring WARP interface up (was down)", "wg-quick", "up", p.path))
	default:
		actions = append(actions, reconcile.NoChangeAction("wg-quick", "WARP interface already up"))
	}
	return actions, nil
}

func (p warpPlanner) isUp() bool {
	if p.up == nil {
		return ipLinkUp(ifaceName(p.path))
	}
	return p.up(ifaceName(p.path))
}

// --- policy routing ---

type routingPlanner struct {
	statePath string
	// applied reports whether the live kernel still reflects the routing intent.
	// nil ⇒ a real `ip rule list` + `ip route show` probe; tests inject a stub.
	applied func(domain.RoutingSpec) bool
}

func (routingPlanner) Component() string { return "policy routing" }

func (p routingPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	steps, err := routing.Render(spec.Routing)
	if err != nil {
		return nil, err
	}
	if len(steps) == 0 {
		return []reconcile.Action{
			reconcile.NoChangeAction("policy routing", "direct egress, no policy routing"),
		}, nil
	}

	// Gate the routing commands on a state file describing the desired intent.
	// The kernel keeps applied rules until reboot, so re-running `ip rule add` /
	// `conntrack -D` every pass is both wasteful and wrong: an earlier finding says flush
	// conntrack on route CHANGE, not on a timer. The state file lives on tmpfs
	// (/run), so a reboot clears it alongside the kernel rules and the next pass
	// re-applies from scratch.
	file, err := reconcile.FileAction(p.statePath, []byte(routing.Script(steps)), 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	switch {
	case file.Changes():
		// Intent changed: apply the full set (incl. the conntrack flush).
		actions = append(actions, routingExecActions(steps)...)
	case !p.isApplied(spec.Routing):
		// Intent unchanged but the live kernel no longer reflects it — someone
		// flushed or edited `ip rule`/`ip route` by hand, or a partial state.
		// Re-apply the full idempotent set to self-heal (ADR-0015 live-kernel
		// drift repair). The conntrack flush rides along, which is correct: the
		// path was effectively broken.
		actions = append(actions, routingExecActions(steps)...)
	default:
		actions = append(actions, reconcile.NoChangeAction("policy routing", "intent unchanged; kernel reflects it"))
	}
	return actions, nil
}

func (p routingPlanner) isApplied(r domain.RoutingSpec) bool {
	if p.applied == nil {
		return routingApplied(r)
	}
	return p.applied(r)
}

// routingExecActions wraps routing steps as reconcile exec actions, honoring the
// best-effort flag (e.g. `ip rule del` of a rule that is not there yet).
func routingExecActions(steps []routing.Step) []reconcile.Action {
	out := make([]reconcile.Action, 0, len(steps))
	for _, s := range steps {
		if s.BestEffort {
			out = append(out, reconcile.BestEffortExecAction(s.Summary, s.Argv...))
		} else {
			out = append(out, reconcile.ExecAction(s.Summary, s.Argv...))
		}
	}
	return out
}

// routingApplied is the real kernel probe behind routingPlanner.isApplied: it
// captures `ip rule list` and `ip route show table <EgressTable>` and asks the
// pure routing.KernelReflects whether the intent is still in force. Any exec
// error (non-Linux dev box, missing iproute2) reports "not applied", so the
// planner re-emits the apply steps — harmless in plan mode, self-healing on a
// real node.
func routingApplied(r domain.RoutingSpec) bool {
	if r.EgressInterface == "" {
		return true // direct egress: nothing to verify
	}
	rules, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return false
	}
	routes, err := exec.Command("ip", "route", "show", "table", fmt.Sprintf("%d", routing.EgressTable)).Output()
	if err != nil {
		return false
	}
	return routing.KernelReflects(r, string(rules), string(routes))
}

// --- dns filter ---

type dnsPlanner struct {
	configPath  string
	composePath string
	up          func(file string) bool // nil ⇒ real `docker compose ps` probe
}

func (dnsPlanner) Component() string { return "dns filter (blocky)" }

func (p dnsPlanner) isUp() bool {
	if p.up == nil {
		return compose.StackUp(p.composePath)
	}
	return p.up(p.composePath)
}

func (p dnsPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.DNS.Enabled {
		return []reconcile.Action{reconcile.NoChangeAction("dns filter", "disabled")}, nil
	}
	if spec.DNS.MgmtAddr == "" {
		// The resolver must bind the mgmt/ZT address; until the controller knows
		// it, defer rather than crash the whole pass or bind something public.
		return []reconcile.Action{reconcile.NoChangeAction("dns filter",
			"pending: node mgmt address unknown, cannot pick a safe listen addr")}, nil
	}
	cfg, err := dnsfilter.RenderBlocky(spec.DNS)
	if err != nil {
		return nil, fmt.Errorf("render dns filter: %w", err)
	}
	composeYAML, err := compose.RenderBlockyCompose(compose.BlockyInput{
		Image:      spec.DNS.Image,
		ConfigPath: p.configPath,
	})
	if err != nil {
		return nil, fmt.Errorf("render dns compose: %w", err)
	}

	cfgFile, err := reconcile.FileAction(p.configPath, []byte(cfg), 0o644, nil)
	if err != nil {
		return nil, err
	}
	composeFile, err := reconcile.FileAction(p.composePath, []byte(composeYAML), 0o644, nil)
	if err != nil {
		return nil, err
	}

	actions := []reconcile.Action{composeFile, cfgFile}

	// Operator extra files (Custom.Files): include lists referenced from the
	// overrides (e.g. a local denylist). Relative paths land next to config.yml.
	dir := filepath.Dir(p.configPath)
	configChanged := cfgFile.Changes()
	for _, f := range spec.DNS.Custom.Files {
		target := f.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		var redact reconcile.Redactor
		if f.Secret {
			redact = func(string) string { return "<redacted: operator secret file>" }
		}
		fa, err := reconcile.FileAction(target, []byte(f.Content), 0o644, redact)
		if err != nil {
			return nil, err
		}
		actions = append(actions, fa)
		configChanged = configChanged || fa.Changes()
	}

	switch {
	case composeFile.Changes():
		// A compose-file change pulls the new definition on the same up -d.
		actions = append(actions, reconcile.ExecAction("bring blocky stack up",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	case configChanged:
		// Config (or a mounted include) is a volume: restart blocky to reload.
		actions = append(actions, reconcile.ExecAction("restart resolver",
			"docker", "compose", "-f", p.composePath, "restart", "blocky"))
	case !p.isUp():
		// Definition and config unchanged but the resolver is (partly) down — a
		// crash, reboot, or a prior up that failed. Bring it up so the reconcile
		// loop self-heals a dead blocky instead of leaving the node Degraded until
		// the operator intervenes (the convergence guarantee must hold for DNS too).
		actions = append(actions, reconcile.ExecAction("bring blocky stack up (was down)",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	default:
		// Steady state: everything in place and running. Record a no-change so the
		// engine doesn't see a perpetual exec "change" every pass.
		actions = append(actions, reconcile.NoChangeAction("dns filter", "resolver already up"))
	}
	return actions, nil
}
