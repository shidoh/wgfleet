package master

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/tuning"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// Input is everything the master planners need beyond the NodeSpec. PrivateKey
// is the master's WireGuard key (real persisted key in apply mode, ephemeral in
// plan mode), shared across all mihomo exit-tunnel proxies.
type Input struct {
	Paths      Paths
	PrivateKey string
	// ClientInterface is the client WG interface the NAT/forward rules reference.
	// Default is applied when empty. (The master masquerades on every egress except
	// this interface, so a separate egress iface no longer needs detecting.)
	ClientInterface string
	// AdminUsername / AdminPassword seed wg-easy's unattended setup (INIT_*), so a
	// fresh master never stops at the interactive setup wizard. They are resolved
	// agent-locally — the password is generated and persisted on-node and never
	// sent by the controller (ADR-0008). Empty password ⇒ no unattended setup.
	AdminUsername string
	AdminPassword string
	// OverlayMSS clamps TCP MSS on the mgmt overlay (control-plane insurance);
	// 0 disables. See config.AgentSection.MgmtOverlayMSS and netfw.RenderInput.
	OverlayMSS int
}

const defaultClientInterface = "wg0"

// mssTCPIPOverhead is the IPv4 + TCP header size subtracted from the path MTU to
// get the MSS to advertise (20 + 20). Matches the exit's ClampMSS derivation.
const mssTCPIPOverhead = 40

// Planners returns the ordered master reconcilers: mihomo config + its included
// files + operator extra files, then the NAT rules that wire clients into mihomo.
func Planners(in Input) []reconcile.Planner {
	if in.ClientInterface == "" {
		in.ClientInterface = defaultClientInterface
	}
	return []reconcile.Planner{
		// Node tuning first (BBR congestion control); cheap, independent of the rest.
		tuning.BBRPlanner(),
		// Input firewall: bring the drop policy up before the services, the same
		// ordering the bootstrap uses ("firewall before traffic").
		firewallPlanner{path: in.Paths.FirewallNFT, overlayMSS: in.OverlayMSS, clientIface: in.ClientInterface},
		composePlanner{path: in.Paths.Compose, adminUser: in.AdminUsername, adminPass: in.AdminPassword},
		wgEasyPlanner{dbPath: in.Paths.WGEasyDB, iface: wgeasy.DefaultInterface, compose: in.Paths.Compose},
		wgEasyUserConfigPlanner{dbPath: in.Paths.WGEasyDB, iface: wgeasy.DefaultInterface},
		wgEasyMetricsPlanner{dbPath: in.Paths.WGEasyDB},
		// Extra files (operator rule-provider lists like direct-domains.yaml) MUST be
		// written before mihomo renders + hot-reloads its config, which references them
		// as `file` rule-providers — otherwise the first reload points at a missing
		// file and mihomo can reject the new config.
		extraFilesPlanner{dir: in.Paths.ExtraFilesDir},
		// Dashboard before mihomo too: the agent populates the external-ui dir (mihomo
		// only serves it, never downloads — see dashboardPlanner).
		dashboardPlanner{uiDir: in.Paths.UIDir},
		mihomoPlanner{paths: in.Paths, privateKey: in.PrivateKey},
		masterNATPlanner{path: in.Paths.NFT, clientIface: in.ClientInterface},
		masterForwardPlanner{clientIface: in.ClientInterface},
	}
}

// composeStart is the idempotent "bring the stack up" action: docker compose up
// -d is a no-op when nothing changed.
func composeStart(file string) reconcile.Action {
	return reconcile.ExecAction("ensure the container stack is up",
		"docker", "compose", "-f", file, "up", "-d")
}

func composeRestart(file, service string) reconcile.Action {
	return reconcile.ExecAction("restart "+service,
		"docker", "compose", "-f", file, "restart", service)
}

// --- container stack (docker-compose.yml + up -d) ---

type composePlanner struct {
	path      string
	adminUser string                 // wg-easy unattended-setup admin user (INIT_USERNAME)
	adminPass string                 // wg-easy unattended-setup admin password (INIT_PASSWORD); agent-local
	up        func(file string) bool // nil ⇒ real `docker compose ps` probe
}

func (composePlanner) Component() string { return "container stack (docker compose)" }

func (p composePlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("compose: node has no master spec")
	}
	yamlText, err := compose.RenderMasterCompose(compose.RenderInput{
		Compose:          spec.Master.Compose,
		ClientListenPort: spec.WGServer.ListenPort,
		ClientPool:       spec.WGServer.AddressPool,
		MgmtAddr:         masterMgmtAddr(spec),
		AdminUsername:    p.adminUser,
		AdminPassword:    p.adminPass,
	})
	if err != nil {
		return nil, err
	}
	// Redact INIT_PASSWORD so the dry-run plan / Web UI preview never print the
	// wg-easy admin password (it is written verbatim to the on-disk compose file,
	// which is root-only).
	file, err := reconcile.FileAction(p.path, []byte(yamlText), 0o644, compose.RedactComposeEnv)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	switch {
	case file.Changes():
		// Definition changed: `up -d` recreates only the services whose config moved.
		actions = append(actions, composeStart(p.path))
	case !p.isUp():
		// Definition unchanged but the stack is (partly) down — reboot, crash, or a
		// prior up that failed: bring it up so reconcile converges to the running
		// state, not just the on-disk config.
		actions = append(actions, composeStart(p.path))
	default:
		// Steady state: `up -d` is a no-op at the docker level, but the reconcile
		// engine still counts the exec as a change, which would show perpetual
		// drift every pass. Skip it so an unchanged master reports a clean pass.
		actions = append(actions, reconcile.NoChangeAction("docker compose", "container stack already up"))
	}
	return actions, nil
}

func (p composePlanner) isUp() bool {
	if p.up == nil {
		return compose.StackUp(p.path)
	}
	return p.up(p.path)
}

// masterMgmtAddr derives the master's mgmt address from the Clash external
// controller (host:9090) so the compose render can bind wg-easy's UI to it.
func masterMgmtAddr(spec domain.NodeSpec) string {
	ec := spec.Master.ExternalController
	if i := indexByte(ec, ':'); i > 0 {
		return ec[:i]
	}
	return ec
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// --- wg-easy client-facing AWG obfuscation (SQLite-backed, ADR-0008) ---

type wgEasyPlanner struct {
	dbPath  string
	iface   string
	compose string
}

func (wgEasyPlanner) Component() string { return "wg-easy client AWG" }

func (p wgEasyPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.WGServer.AWG == nil {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy AWG", "no client AWG params")}, nil
	}
	// Reconcile the obfuscation params AND the transport columns (port, pool, MTU):
	// INIT_* env only seed those on first DB creation, so a manifest change to the
	// client port/pool would never apply on a running node without writing the DB.
	desired := wgeasy.ColumnsFromSpec(spec.WGServer)
	display := wgeasy.RenderUpdateSQL(p.iface, desired)

	// wg-easy must be set up first; if its DB is absent, surface a pending notice
	// rather than failing the whole pass (the DB appears once wg-easy runs).
	if _, err := os.Stat(p.dbPath); os.IsNotExist(err) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy interface",
			"pending: wg-easy DB not found at "+p.dbPath+" (set up wg-easy first)")}, nil
	}

	current, found, err := wgeasy.ReadInterface(ctx, p.dbPath, p.iface)
	if err != nil {
		return nil, err
	}
	if !found {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy interface",
			"pending: wg-easy interface row not created yet")}, nil
	}
	if current == desired {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy interface", "interface settings already current")}, nil
	}

	dbPath, iface := p.dbPath, p.iface
	update := reconcile.CustomAction(reconcile.ActionUpdate, "wg-easy interface",
		"set client-facing port/pool/MTU + obfuscation in wg-easy DB", display,
		func(ctx context.Context) error { return wgeasy.UpdateInterface(ctx, dbPath, iface, desired) })

	// wg-easy regenerates its .conf from the DB on (re)start.
	return []reconcile.Action{update, composeRestart(p.compose, "wg-easy")}, nil
}

// --- wg-easy per-client defaults (SQLite-backed, ADR-0008) ---

// wgEasyUserConfigPlanner reconciles wg-easy's user_configs_table: the defaults
// wg-easy bakes into every generated client config (endpoint host/port, MTU, DNS,
// allowed-IPs, and the client-side AmneziaWG junk j_c/j_min/j_max). INIT_* seed
// only some of these and only at first DB creation; the client junk is not
// seedable at all and its schema default underflows our transport-junk size S4, so
// we enforce them by direct DB write (sibling of wgEasyPlanner).
type wgEasyUserConfigPlanner struct {
	dbPath string
	iface  string
}

func (wgEasyUserConfigPlanner) Component() string { return "wg-easy client defaults" }

func (p wgEasyUserConfigPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("wg-easy user config: node has no master spec")
	}
	if _, err := os.Stat(p.dbPath); os.IsNotExist(err) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy client defaults",
			"pending: wg-easy DB not found at "+p.dbPath)}, nil
	}
	current, found, err := wgeasy.ReadUserConfig(ctx, p.dbPath, p.iface)
	if err != nil {
		return nil, err
	}
	if !found {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy client defaults",
			"pending: wg-easy user-config row not created yet")}, nil
	}

	cc := spec.Master.Compose
	var allowedIPs []string
	for _, ip := range strings.Split(cc.ClientAllowedIPs, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			allowedIPs = append(allowedIPs, ip)
		}
	}
	desired := wgeasy.DesiredUserConfig(current, spec.WGServer, cc.PublicIP, cc.ClientDNS, allowedIPs)
	if desired.Equal(current) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy client defaults", "client defaults already current")}, nil
	}

	dbPath, iface := p.dbPath, p.iface
	update := reconcile.CustomAction(reconcile.ActionUpdate, "wg-easy client defaults",
		"set client-facing DNS/allowed-IPs/MTU/host/port + client AWG junk in wg-easy DB",
		wgeasy.RenderUserConfigUpdateSQL(iface, desired),
		func(ctx context.Context) error { return wgeasy.UpdateUserConfig(ctx, dbPath, iface, desired) })
	// No restart: wg-easy reads user_configs live when generating client configs.
	return []reconcile.Action{update}, nil
}

// --- wg-easy Prometheus metrics (SQLite-backed, like the AWG planner) ---

type wgEasyMetricsPlanner struct {
	dbPath string
}

func (wgEasyMetricsPlanner) Component() string { return "wg-easy metrics" }

func (p wgEasyMetricsPlanner) Plan(ctx context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	// wg-easy must be set up first; if its DB is absent, defer (it appears once
	// wg-easy runs) rather than failing the whole pass — same as the AWG planner.
	if _, err := os.Stat(p.dbPath); os.IsNotExist(err) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy metrics",
			"pending: wg-easy DB not found at "+p.dbPath)}, nil
	}

	enabled, found, err := wgeasy.ReadMetricsPrometheus(ctx, p.dbPath)
	if err != nil {
		return nil, err
	}
	if !found {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy metrics",
			"pending: wg-easy settings row not created yet")}, nil
	}
	if enabled {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy metrics", "prometheus already enabled")}, nil
	}

	dbPath := p.dbPath
	enable := reconcile.CustomAction(reconcile.ActionUpdate, "wg-easy prometheus metrics",
		"enable the wg-easy Prometheus endpoint", wgeasy.EnablePrometheusSQL(),
		func(ctx context.Context) error { return wgeasy.EnablePrometheus(ctx, dbPath) })
	return []reconcile.Action{enable}, nil
}

// --- mihomo config + included direct-networks ---

type mihomoPlanner struct {
	paths      Paths
	privateKey string
	// reload hot-applies the config via the Clash API (nil ⇒ the real mihomo.Reload);
	// injected in tests. Preferred over a container restart so a routine change like
	// draining one exit does not drop every client's connection.
	reload func(ctx context.Context, controllerAddr, secret string, cfgYAML []byte) error
}

func (mihomoPlanner) Component() string { return "mihomo (data plane)" }

func (p mihomoPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo: node has no master spec")
	}
	cfg, err := mihomo.RenderConfig(mihomo.RenderInput{Spec: *spec.Master, PrivateKey: p.privateKey})
	if err != nil {
		return nil, err
	}
	configAction, err := reconcile.FileAction(p.paths.MihomoConfig, []byte(cfg), 0o644, mihomo.RedactConfig)
	if err != nil {
		return nil, err
	}

	direct, err := mihomo.RenderDirectNetworks(*spec.Master)
	if err != nil {
		return nil, err
	}
	directAction, err := reconcile.FileAction(p.paths.DirectNetworks, []byte(direct), 0o644, nil)
	if err != nil {
		return nil, err
	}

	actions := []reconcile.Action{configAction, directAction}
	if configAction.Changes() || directAction.Changes() {
		actions = append(actions, p.applyConfigAction(spec, []byte(cfg)))
	} else {
		actions = append(actions, reconcile.NoChangeAction("mihomo", "config already current"))
	}
	return actions, nil
}

// applyConfigAction makes a running mihomo pick up the freshly written config. It
// prefers an in-process hot reload via the Clash API (no container restart, so
// existing client connections survive — draining one exit must not disconnect
// everyone), and falls back to `docker compose restart mihomo` only when the API is
// unreachable (mihomo down / mid-start). A config the controller actively REJECTS is
// surfaced as an error WITHOUT a restart, so the previous good config keeps running.
func (p mihomoPlanner) applyConfigAction(spec domain.NodeSpec, cfgYAML []byte) reconcile.Action {
	reload := p.reload
	if reload == nil {
		reload = mihomo.Reload
	}
	addr := spec.Master.ExternalController
	secret := clashSecret(spec.Master)
	compose := p.paths.Compose

	display := fmt.Sprintf("PUT http://%s/configs (hot reload; fallback: docker compose restart mihomo)",
		orPlaceholder(addr, "<external-controller>"))
	apply := func(ctx context.Context) error {
		err := reload(ctx, addr, secret, cfgYAML)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, mihomo.ErrUnreachable):
			// Not reachable (down / mid-start): restart so it reads the fresh file.
			// Heavier (drops connections) but rare — the compose planner already
			// brought the stack up earlier in the same pass.
			c := exec.CommandContext(ctx, "docker", "compose", "-f", compose, "restart", "mihomo")
			if out, rerr := c.CombinedOutput(); rerr != nil {
				return fmt.Errorf("mihomo reload unreachable (%v) and restart failed: %w: %s",
					err, rerr, strings.TrimSpace(string(out)))
			}
			return nil
		default:
			// Reachable but rejected the config: leave the old config running.
			return err
		}
	}
	return reconcile.CustomAction(reconcile.ActionUpdate, "mihomo",
		"reload mihomo config in place (Clash API; existing connections preserved)", display, apply)
}

// clashSecret extracts the Clash API secret from the operator's mihomo overrides
// (where it is configured), so the agent can authenticate its reload call. Empty
// when no secret is set (the API is then bound to mgmt only and unauthenticated).
func clashSecret(ms *domain.MasterSpec) string {
	if ms == nil || ms.Custom.Overrides == nil {
		return ""
	}
	if s, ok := ms.Custom.Overrides["secret"].(string); ok {
		return s
	}
	return ""
}

func orPlaceholder(s, placeholder string) string {
	if s == "" {
		return placeholder
	}
	return s
}

// --- operator extra files (CustomConfig.Files) ---

type extraFilesPlanner struct{ dir string }

func (extraFilesPlanner) Component() string { return "mihomo extra files" }

func (p extraFilesPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil || len(spec.Master.Custom.Files) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("extra files", "none")}, nil
	}
	var actions []reconcile.Action
	for _, f := range spec.Master.Custom.Files {
		target := f.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(p.dir, target)
		}
		var redact reconcile.Redactor
		if f.Secret {
			redact = func(string) string { return "<redacted: operator secret file>" }
		}
		a, err := reconcile.FileAction(target, []byte(f.Content), 0o644, redact)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}
	return actions, nil
}

// --- master input firewall (nftables filter, mirrors the exit) ---

// firewallPlanner reconciles the master's input-filter firewall. Unlike the exit,
// the master previously had NO reconciled input firewall — only the bootstrap
// baseline, which is lost on reboot and never re-applied — so after a reboot the
// master ran with no input policy until re-provisioned. It renders the shared
// netfw input chain with Role=master (drop policy; overlay/SSH/client-port open; no
// masquerade — that stays in the exit ruleset; the master's own NAT is a separate
// table) and self-heals like masterNATPlanner when the kernel loses the table.
type firewallPlanner struct {
	path string
	// overlayMSS clamps TCP MSS on the mgmt overlay (0 ⇒ no clamp).
	overlayMSS int
	// clientIface is the client-facing WG interface ("wg0") whose DNAT'd TCP must be
	// accepted into the local mihomo redir port (see RenderInput.RedirInterface).
	clientIface string
	// loaded reports whether the live kernel has the input-firewall table.
	// nil ⇒ a real `nft list table inet wgfleet` probe; tests inject a stub.
	loaded func() bool
}

func (firewallPlanner) Component() string { return "master firewall (nftables)" }

func (p firewallPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	// The redirect the input firewall must open matches masterNATPlanner's DNAT
	// target, so resolve the redir port the same way (spec, else mihomo default).
	redir := mihomo.DefaultRedirPort
	if spec.Master != nil && spec.Master.RedirPort != 0 {
		redir = spec.Master.RedirPort
	}
	var adminPorts []int
	if spec.Master != nil {
		adminPorts = spec.Master.ClientAdminPorts
	}
	// Clamp client-facing TCP MSS to the true client-path MTU (the minimum across all
	// hops, which the controller already computed into WGServer.MTU). The master is
	// the only node that sees every client flow and knows this value; without it the
	// exit's looser clamp and the unclamped master-local path black-hole large
	// segments (an earlier finding, see netfw.RenderInput.ClientMSS).
	clientMSS := 0
	if spec.WGServer.MTU > 0 {
		clientMSS = spec.WGServer.MTU - mssTCPIPOverhead
	}
	ruleset, err := netfw.RenderRuleset(netfw.RenderInput{
		Firewall:         spec.Firewall,
		Role:             domain.RoleMaster,
		OverlayMSS:       p.overlayMSS,
		RedirPort:        redir,
		RedirInterface:   p.clientIface,
		ClientAdminPorts: adminPorts,
		ClientMSS:        clientMSS,
	})
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
		actions = append(actions, reconcile.ExecAction("apply master firewall atomically", "nft", "-f", p.path))
	case !p.isLoaded():
		// Ruleset unchanged but the kernel lost the table — a reboot cleared nft
		// state, or the baseline was re-applied by a re-provision. Reload to self-heal
		// (ADR-0015 / ADR-0020). Without this the master silently runs with no input
		// firewall after a reboot while health checks still pass.
		actions = append(actions, reconcile.ExecAction("reload master firewall (kernel table missing)", "nft", "-f", p.path))
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
// `nft list table inet wgfleet` succeeds only when the input-firewall table is
// present. Any exec error (table absent, non-Linux dev box, missing nft) reports
// "not loaded", so the planner re-applies — harmless in plan mode, self-healing on
// a real node.
func firewallLoaded() bool {
	return exec.Command("nft", "list", "table", "inet", netfw.ExitTable).Run() == nil
}

// --- master NAT (DNAT clients → mihomo, MASQUERADE, drop QUIC) ---

type masterNATPlanner struct {
	path        string
	clientIface string
	// loaded reports whether the live kernel currently has the master NAT table.
	// nil ⇒ a real `nft list table ip wgfleet_master` probe; tests inject a stub.
	loaded func() bool
}

func (masterNATPlanner) Component() string { return "master NAT (nftables)" }

func (p masterNATPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("master NAT: node has no master spec")
	}
	redir := spec.Master.RedirPort
	if redir == 0 {
		redir = mihomo.DefaultRedirPort
	}
	ruleset, err := netfw.RenderMasterNAT(netfw.MasterNATInput{
		ClientInterface: p.clientIface,
		ClientCIDR:      spec.WGServer.AddressPool,
		RedirAddr:       fmt.Sprintf("%s:%d", spec.Master.BindAddress, redir),
		PrivateCIDRs:    spec.Master.DirectCIDRs,
	})
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
		actions = append(actions, reconcile.ExecAction("apply master NAT atomically", "nft", "-f", p.path))
	case !p.isLoaded():
		// Ruleset unchanged but the kernel no longer has the table — a reboot cleared
		// nft state, or someone flushed it by hand. Reload to self-heal (ADR-0015
		// live-kernel drift repair, mirroring routingPlanner). Without this the master
		// silently runs with no DNAT/MASQUERADE/drop-QUIC after a reboot while health
		// checks still pass: a "Ready but broken" client ingress.
		actions = append(actions, reconcile.ExecAction("reload master NAT (kernel table missing)", "nft", "-f", p.path))
	default:
		actions = append(actions, reconcile.NoChangeAction("nft -f", "ruleset already loaded"))
	}
	return actions, nil
}

func (p masterNATPlanner) isLoaded() bool {
	if p.loaded == nil {
		return masterNATLoaded()
	}
	return p.loaded()
}

// masterNATLoaded is the real kernel probe behind masterNATPlanner.isLoaded:
// `nft list table ip wgfleet_master` succeeds only when the table is present.
// Any exec error (table absent, non-Linux dev box, missing nft) reports "not
// loaded", so the planner re-applies — harmless in plan mode, self-healing on a
// real node.
func masterNATLoaded() bool {
	return exec.Command("nft", "list", "table", "ip", netfw.MasterNATTable).Run() == nil
}

// --- master forwarding (ip_forward + docker FORWARD accept) ---

// masterForwardPlanner makes the master actually forward client traffic. Two
// kernel facts conspire against it:
//
//  1. Docker sets the filter FORWARD policy to DROP and only accepts its own
//     bridge traffic, so client packets routed wg0→uplink are dropped. wg-easy's
//     own `FORWARD -i wg0 -j ACCEPT` is emitted via the container's iptables,
//     which on a modern host is iptables-LEGACY — invisible to Docker's nft
//     FORWARD chain, so it does not help. The sanctioned override is the
//     DOCKER-USER chain (Docker never flushes it); an ACCEPT there makes the
//     FORWARD base chain return accept instead of hitting the drop policy. A
//     separate nft base chain cannot help: a drop in Docker's chain is final
//     regardless of an accept in another base chain at the same hook.
//  2. IPv4 forwarding must be on. Docker enables it, but the master data plane
//     should not depend on that side effect, so we assert it too.
//
// Only TCP is DNAT'd to mihomo (a local address ⇒ INPUT, not FORWARD); ICMP, DNS
// and other UDP are plain-forwarded, so without this they silently black-hole
// while the AmneziaWG handshake looks healthy.
type masterForwardPlanner struct {
	clientIface string
	// Probes (nil ⇒ real). Injected in tests.
	forwardOn   func() bool           // ip_forward == 1
	chainExists func() bool           // DOCKER-USER chain present (Docker up)
	rulePresent func(m []string) bool // iptables -C DOCKER-USER <m>
}

func (masterForwardPlanner) Component() string { return "master forwarding (ip_forward + DOCKER-USER)" }

// dockerUserRule is one DOCKER-USER accept we maintain, with its match args (the
// part after `-I DOCKER-USER`) and a human summary.
type dockerUserRule struct {
	summary string
	match   []string
}

func masterForwardRules(iface string) []dockerUserRule {
	return []dockerUserRule{
		{"accept client→uplink forwarding (DOCKER-USER)", []string{"-i", iface, "-j", "ACCEPT"}},
		{"accept return traffic to clients (DOCKER-USER)", []string{"-o", iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}
}

func (p masterForwardPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	iface := p.clientIface
	if iface == "" {
		iface = defaultClientInterface
	}
	var actions []reconcile.Action

	// 1. IPv4 forwarding.
	if p.isForwardOn() {
		actions = append(actions, reconcile.NoChangeAction("ip_forward", "already enabled"))
	} else {
		actions = append(actions, reconcile.ExecAction("enable IPv4 forwarding",
			"sysctl", "-w", "net.ipv4.ip_forward=1"))
	}

	// 2. DOCKER-USER accept rules. The chain only exists once Docker is up; until
	// then defer rather than fail the pass (the compose planner brings Docker up
	// earlier in the same reconcile, so it converges next pass at the latest).
	if !p.dockerUserExists() {
		actions = append(actions, reconcile.NoChangeAction("DOCKER-USER",
			"pending: DOCKER-USER chain not present yet (docker not up)"))
		return actions, nil
	}
	for _, r := range masterForwardRules(iface) {
		if p.isRulePresent(r.match) {
			actions = append(actions, reconcile.NoChangeAction("DOCKER-USER", r.summary+" already present"))
			continue
		}
		argv := append([]string{"iptables", "-I", "DOCKER-USER"}, r.match...)
		actions = append(actions, reconcile.ExecAction(r.summary, argv...))
	}
	return actions, nil
}

func (p masterForwardPlanner) isForwardOn() bool {
	if p.forwardOn != nil {
		return p.forwardOn()
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func (p masterForwardPlanner) dockerUserExists() bool {
	if p.chainExists != nil {
		return p.chainExists()
	}
	return exec.Command("iptables", "-S", "DOCKER-USER").Run() == nil
}

func (p masterForwardPlanner) isRulePresent(match []string) bool {
	if p.rulePresent != nil {
		return p.rulePresent(match)
	}
	argv := append([]string{"-C", "DOCKER-USER"}, match...)
	return exec.Command("iptables", argv...).Run() == nil
}
