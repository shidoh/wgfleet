package master

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/dockerfw"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/restart"
	"github.com/shidoh/wgfleet/internal/agent/tuning"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/netns"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// Input is everything the master planners need beyond the NodeSpec. PrivateKey
// is the master's WireGuard key (real persisted key in apply mode, ephemeral in
// plan mode), shared across all mihomo exit-tunnel proxies.
type Input struct {
	Paths      Paths
	PrivateKey string
	// RealityPrivateKey is the master's CLIENT-FACING REALITY x25519 private key
	// (agent-local, persisted on the master, never on the wire). Empty ⇒ the
	// client-vless planner no-ops until the key is available (same gate as the exit
	// reality inbound). Only used when spec.Master.ClientVLESS is set.
	RealityPrivateKey string
	// ClientWGPrivateKey is the master's CLIENT-FACING WireGuard private key — the
	// identity of the interface end users dial once the agent owns it. Agent-local
	// (adopted from wg-easy's database on handover, else generated), never on the
	// wire. Empty ⇒ the client-interface planner defers, like the vless one.
	ClientWGPrivateKey string
	// SyntheticKey is the keypair of the master's OWN client — the peer it sends
	// traffic through to measure whether a packet entering the client interface
	// comes back. The ADDRESS is derived from the pool at plan time rather than
	// passed here, so a pool the operator resizes moves the prober with it. Zero
	// value ⇒ no prober, and everything renders as it did before it existed.
	SyntheticKey wg.KeyPair
	// ClientWGPublicKey is the master's client-interface public key — what the
	// prober dials. Derived from the private key by the caller so this package
	// never has to.
	ClientWGPublicKey string
	// NetnsAttached reports the CURRENT decision about where client traffic is
	// intercepted. Read, never taken, here: the decision needs evidence a planner
	// cannot cheaply gather (can the namespace resolve, does the client path still
	// work), so the agent takes it once per pass with the probes it already runs
	// and the planners render whatever it decided. Deciding a pass later than the
	// evidence is the safe direction — it means nothing moves on a guess.
	NetnsAttached func() bool
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
	// Tier carries the exit-tier failover decision ACROSS reconcile passes. It must
	// be owned by the caller and reused, because Planners() is invoked once per pass
	// (cmd/wgfleet-agent: the engine is rebuilt every 30s). A selector constructed
	// here would have its hysteresis reset every pass — streaks would never reach
	// their thresholds, so failover could never fire and the standby would never be
	// warmed. That is not hypothetical: it is exactly what happened when this was
	// first built, and it was invisible because every individual pass looked correct.
	// nil ⇒ a throwaway selector, i.e. no failover: safe for tests, wrong in prod.
	Tier *TierSelector
	// Restart throttles the SELF-HEAL restarts (mihomo rebind, leaked WG devices)
	// so a condition that a restart cannot fix does not bounce the container — and
	// with it every client's connection — twice a minute forever. Like Tier it must
	// be owned by the caller and reused across passes; a governor built here would
	// forget every restart it saw. nil ⇒ unthrottled (the pre-governor behaviour).
	Restart *restart.Governor
}

const defaultClientInterface = "wg0"

// ClientWGInterface is the same name, exported for the agent's identity audit,
// which has to ask the LIVE interface what key it is serving.
const ClientWGInterface = defaultClientInterface

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
		firewallPlanner{path: in.Paths.FirewallNFT, overlayMSS: in.OverlayMSS, clientIface: in.ClientInterface,
			netnsAttached: in.NetnsAttached},
		// The client interface goes BEFORE compose, and the order is load-bearing in
		// the REVERSE direction. On the rollback pass compose restores wg-easy and
		// lets it recreate wg0; if we ran after it, we would tear down the interface
		// it had just made — every pass, forever, because our config file stays on
		// disk. Running first, we release the interface while it is still ours and
		// compose then hands it to wg-easy cleanly.
		//
		// The handover direction is unaffected: claiming wg0 does not require
		// wg-easy to be stopped first (we take the interface from it either way),
		// and the compose planner in the same pass retires the container.
		clientWGPlanner{confPath: in.Paths.ClientWGConf, privateKey: in.ClientWGPrivateKey,
			synthKey: in.SyntheticKey},
		// After the client interface: the prober dials it, so it has to exist first.
		synthPlanner{confPath: in.Paths.SynthConf, synthKey: in.SyntheticKey,
			serverPub: in.ClientWGPublicKey},
		composePlanner{path: in.Paths.Compose, adminUser: in.AdminUsername, adminPass: in.AdminPassword,
			netnsAttached: in.NetnsAttached},
		// Extra files (operator rule-provider lists like direct-domains.yaml) MUST be
		// written before mihomo renders + hot-reloads its config, which references them
		// as `file` rule-providers — otherwise the first reload points at a missing
		// file and mihomo can reject the new config.
		extraFilesPlanner{dir: in.Paths.ExtraFilesDir},
		// Dashboard before mihomo too: the agent populates the external-ui dir (mihomo
		// only serves it, never downloads — see dashboardPlanner).
		dashboardPlanner{uiDir: in.Paths.UIDir},
		// After the compose planner (which creates the holder) and BEFORE mihomo and
		// the master NAT: the namespace has to exist before anything can be asked to
		// live in it, but nothing routes into it yet.
		netnsPlanner{attached: in.NetnsAttached, clientIface: in.ClientInterface,
			composePath: in.Paths.Compose},
		mihomoPlanner{paths: in.Paths, privateKey: in.PrivateKey, tier: in.Tier,
			netnsAttached: in.NetnsAttached},
		masterNATPlanner{path: in.Paths.NFT, v6Path: in.Paths.V6NFT, clientIface: in.ClientInterface,
			netnsAttached: in.NetnsAttached},
		// The client leg has exactly one owner. While wg-easy holds it these three
		// keep its database converged; once the operator hands the leg to the agent
		// they all no-op (see handedOver) and clientWGPlanner takes over. Writing to
		// a database whose service we just stopped would be harmless but misleading —
		// the plan would report work on a component that is gone.
		//
		// They sit AFTER the data plane rather than before it, and the reason is the
		// pass on which client interception moves into mihomo's namespace. Compose
		// puts mihomo in the namespace; the host stops intercepting only when the
		// master NAT is re-rendered, several planners later — and in between, the host
		// is still redirecting client traffic at listeners that have moved. Everything
		// standing in that gap is time clients spend with no path, so only the things
		// that MUST precede mihomo (its extra files, its dashboard) are left there.
		wgEasyPlanner{dbPath: in.Paths.WGEasyDB, iface: wgeasy.DefaultInterface, compose: in.Paths.Compose},
		wgEasyUserConfigPlanner{dbPath: in.Paths.WGEasyDB, iface: wgeasy.DefaultInterface},
		wgEasyMetricsPlanner{dbPath: in.Paths.WGEasyDB},
		dockerfw.NewForwardPlanner(
			"master forwarding (ip_forward + DOCKER-USER)",
			in.ClientInterface, defaultClientInterface,
			"accept client→uplink forwarding (DOCKER-USER)",
			// The veth to mihomo's namespace crosses the same FORWARD path, and Docker's
			// policy there is DROP. Listed unconditionally rather than gated on the
			// migration: the interface only exists once the namespace does, the rule is
			// inert until then, and the alternative is a rule that arrives after the
			// traffic it has to carry.
			domain.NetnsHostIface),
		// Client-facing blocky resolver (ADR-0024): runs after the stack is up so wg0
		// (the client gateway it binds) exists. Renders config + its own compose,
		// restarts blocky on change (no hot-reload for upstreams), self-heals when down.
		dnsPlanner{configPath: in.Paths.DNS, composePath: in.Paths.DNSCompose},
		// Client-facing VLESS+REALITY+XHTTP inbound (xray). Runs after mihomo is up:
		// its outbound forwards decrypted client traffic to mihomo's loopback SOCKS
		// listener. Renders config (holding the master's REALITY private key) + its own
		// compose, restarts on change, self-heals when down, tears down when disabled.
		clientVlessPlanner{
			configPath:    in.Paths.ClientVLESS,
			composePath:   in.Paths.ClientVLESSYML,
			privateKey:    in.RealityPrivateKey,
			netnsAttached: in.NetnsAttached,
		},
		// Last: ensure mihomo's redirect listener is actually bound. It runs after the
		// stack is up and wg0 exists, and self-heals the case where mihomo silently
		// lost its redir bind (the client iface was recreated under it, e.g. a wg-easy
		// restart flapped the bind address) — DNAT'd client TCP black-holes otherwise.
		mihomoRedirPlanner{compose: in.Paths.Compose, gov: in.Restart,
			netnsAttached: in.NetnsAttached},
		// Also last: clear mihomo's leaked userspace AmneziaWG devices. A hot reload
		// can leave a second device alive per AWG exit, and because every exit tunnel
		// shares one master WG identity the exit's single peer slot then flaps between
		// the two sockets — intermittent failures and ~7s REKEY_TIMEOUT stalls on AWG
		// exits. Gated on an observed duplicate, never on config change, because the
		// repair is a connection-dropping restart.
		mihomoWGDupPlanner{compose: in.Paths.Compose, gov: in.Restart},
	}
}

// composeStart is the idempotent "bring the stack up" action: docker compose up
// -d is a no-op when nothing changed.
//
// BEST-EFFORT, and not as a convenience. The reconcile engine stops the whole
// pass at the first failing action, and this planner runs third of a dozen — so
// one unfetchable image, one registry timeout, one service that will not start
// takes the namespace, mihomo, the master NAT, DOCKER-USER, blocky and the VLESS
// inbound down with it, on every pass, until someone intervenes. A master that
// cannot start a container should converge everything else and say so; the same
// argument the client-interface planner makes for the same treatment.
func composeStart(file string) reconcile.Action {
	return reconcile.BestEffortExecAction("ensure the container stack is up",
		"docker", "compose", "-f", file, "up", "-d")
}

func composeRestart(file, service string) reconcile.Action {
	return reconcile.ExecAction("restart "+service,
		"docker", "compose", "-f", file, "restart", service)
}

// --- container stack (docker-compose.yml + up -d) ---

type composePlanner struct {
	// netnsAttached reports whether mihomo should join the namespace holder.
	netnsAttached func() bool
	path          string
	adminUser     string                 // wg-easy unattended-setup admin user (INIT_USERNAME)
	adminPass     string                 // wg-easy unattended-setup admin password (INIT_PASSWORD); agent-local
	up            func(file string) bool // nil ⇒ real `docker compose ps` probe
}

func (composePlanner) Component() string { return "container stack (docker compose)" }

func (p composePlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("compose: node has no master spec")
	}
	yamlText, err := compose.RenderMasterCompose(masterComposeInput(spec, p.adminUser, p.adminPass, p.netnsAttached))
	if err != nil {
		return nil, err
	}
	// Redact INIT_PASSWORD so the dry-run plan / Web UI preview never print the
	// wg-easy admin password. Redaction is display-only — the password IS written
	// verbatim to this file — so the mode is what actually protects it. It shipped
	// 0644 while the comment claimed "root-only"; that claim is now enforced by
	// FileAction, which refuses a group/world-readable mode for redacted content.
	file, err := reconcile.FileAction(p.path, []byte(yamlText), 0o600, compose.RedactComposeEnv)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	// Dropping the service from the file does NOT retire the container — compose
	// treats it as an orphan and leaves it running, and `restart: unless-stopped`
	// brings it back after a reboot. The explicit removal lives in the client
	// interface planner instead, which is the only component that knows whether the
	// replacement is actually carrying traffic yet; retiring the fallback from here,
	// on the strength of the manifest knob alone, would remove it in the very pass
	// where our own interface failed to come up.
	switch {
	case file.Changes():
		// Definition changed: `up -d` recreates only the services whose config moved.
		actions = append(actions, composeStart(p.path))
	case !p.isUp(ctx):
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

func (p composePlanner) isUp(ctx context.Context) bool {
	if p.up == nil {
		return compose.StackUp(ctx, p.path)
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
	if handedOver(spec) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy AWG", wgEasyHandedOver)}, nil
	}
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
	if handedOver(spec) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy client defaults", wgEasyHandedOver)}, nil
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

func (p wgEasyMetricsPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if handedOver(spec) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy metrics", wgEasyHandedOver)}, nil
	}
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

// mihomo planners (mihomoPlanner config/reload + mihomoRedirPlanner self-heal)
// live in mihomo.go.

// --- operator extra files (CustomConfig.Files) ---

type extraFilesPlanner struct{ dir string }

func (extraFilesPlanner) Component() string { return "mihomo extra files" }

func (p extraFilesPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil || len(spec.Master.Custom.Files) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("extra files", "none")}, nil
	}
	return reconcile.ManagedFileActions(spec.Master.Custom.Files, p.dir)
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
	// loaded reports whether the live kernel holds THIS input-firewall ruleset.
	// nil ⇒ a real probe against the kernel; tests inject a stub.
	loaded func() bool
	// lastRendered is what Plan just rendered, so isLoaded can ask the strong
	// question — does the kernel hold this — rather than "is a table by this name
	// present". Set on the receiver copy inside Plan, which is why isLoaded is only
	// ever taken as a method value after the assignment.
	lastRendered string
	// netnsAttached reports whether client interception has moved into mihomo's
	// namespace. When it has, the drop-policy input chain must trust the veth or the
	// namespace can reach nothing on this host — including the resolver.
	netnsAttached func() bool
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
	// Open the client-facing resolver port when the master runs blocky (ADR-0024):
	// clients query the master gateway for DNS, which lands on INPUT and the drop
	// policy would otherwise swallow it. 0 keeps it closed (clients use another DNS).
	clientDNSPort := 0
	if spec.DNS.Enabled {
		clientDNSPort = dnsfilter.DefaultDNSPort
		if spec.DNS.Ports.DNS > 0 {
			clientDNSPort = spec.DNS.Ports.DNS
		}
	}
	// The mark masterNATPlanner's TPROXY chain sets. Both planners must agree, so
	// both read it from the same constant — an accept for a mark nothing sets is
	// dead, and a mark with no accept means every intercepted datagram is dropped.
	tproxyMark := 0
	if spec.Master != nil && spec.Master.BindAddress != "" {
		tproxyMark = netfw.TProxyMark
	}
	ruleset, err := netfw.RenderRuleset(netfw.RenderInput{
		Firewall:         spec.Firewall,
		Role:             domain.RoleMaster,
		OverlayMSS:       p.overlayMSS,
		RedirPort:        redir,
		TProxyMark:       tproxyMark,
		RedirInterface:   p.clientIface,
		ClientAdminPorts: adminPorts,
		ClientMSS:        clientMSS,
		ClientDNSPort:    clientDNSPort,
		// Rendered from the same decision the NAT table reads, so the interception
		// moving and the host trusting the veth are one change rather than two that
		// converge at different times.
		NetnsHostIface: netnsVethIface(spec),
	})
	if err != nil {
		return nil, err
	}
	// Same gate as the NAT table beside it, and for the same two reasons: an apply
	// that FAILED must not be recorded as done, and a table that is merely PRESENT is
	// not a table that holds what we wrote. Measured on the stand before this changed:
	// `nft add rule inet wgfleet input udp dport 65099 accept` and
	// `nft delete rule inet wgfleet input handle 15` (the ICMP accept) both survived
	// three reconcile passes and an agent restart with the node reporting
	// `drift=0 state=Ready`. This is the table holding the drop policy, the whitelist,
	// the SSH accept and the mark accept every intercepted datagram depends on — the
	// one where a rule someone added by hand should not outlive the next pass.
	p.lastRendered = ruleset
	actions, err := reconcile.NFTApply(p.path, []byte(ruleset), p.isLoaded, nil, "apply master firewall atomically")
	if err != nil {
		return nil, err
	}
	return actions, nil
}

func (p firewallPlanner) isLoaded() bool {
	if p.loaded != nil {
		return p.loaded()
	}
	// The master input firewall shares the exit's `inet wgfleet` table name.
	if matches, known := netfw.TableMatches("inet", netfw.ExitTable, p.lastRendered); known {
		return matches
	}
	return netfw.TableLoaded("inet", netfw.ExitTable)
}

// --- master NAT (DNAT clients → mihomo, MASQUERADE, drop QUIC) ---

type masterNATPlanner struct {
	path        string
	v6Path      string
	clientIface string
	// loaded reports whether the live kernel currently has the master NAT table.
	// nil ⇒ a real `nft list table ip wgfleet_master` probe; tests inject a stub.
	loaded func() bool
	// lastRendered is the ruleset this pass produced, so isLoaded can compare the
	// kernel against it rather than against the mere existence of a table.
	lastRendered string
	// v6Loaded is the same probe for the client-facing IPv6 table.
	v6Loaded func() bool
	// lastV6Rendered is the ip6 ruleset this pass produced, so isV6Loaded can compare
	// the kernel against it rather than against the mere existence of a table.
	lastV6Rendered string
	// v6Forwarding reports whether net.ipv6.conf.all.forwarding is 1. nil ⇒ read
	// /proc. It is a separate question from v6Loaded and has to be asked separately:
	// the table and the sysctl are lost by different accidents.
	v6Forwarding func() bool
	// tproxyReady reports whether the kernel still carries the policy routing the
	// TPROXY rules depend on. nil ⇒ a real `ip rule`/`ip route` probe.
	tproxyReady func() bool
	// netnsAttached reports whether the interception has moved into mihomo's
	// namespace. When it has, this ruleset must stop intercepting and start routing
	// instead — leaving both in place would feed listeners that are no longer here.
	netnsAttached func() bool
}

// netnsVethIface names the veth to mihomo's namespace once interception lives
// there, and nothing before that.
func netnsVethIface(spec domain.NodeSpec) string {
	if spec.Master == nil {
		return ""
	}
	// As soon as the namespace is wanted, not when the interception moves: the
	// readiness probe runs from in there before anything is switched over, and a
	// drop-policy input chain that does not trust the veth makes the namespace
	// unable to resolve — which is one of the two things the probe checks.
	if wanted, err := spec.Master.NetnsWanted(); err != nil || !wanted {
		return ""
	}
	return domain.NetnsHostIface
}

// NATInput builds the input the master's NAT ruleset is rendered from.
//
// Exported, and a free function rather than a planner method, because a second
// caller needs the SAME value: the UDP-return check asks netfw which ports this
// ruleset refuses, and an answer derived from a differently-built input is an
// answer about a ruleset that was never applied. Planners are rebuilt every pass
// and hold no state worth sharing, so passing the two things they know — the
// client interface and whether the interception has moved — is enough.
func NATInput(spec domain.NodeSpec, clientIface string, netnsAttached bool) netfw.MasterNATInput {
	if spec.Master == nil {
		return netfw.MasterNATInput{}
	}
	redir := spec.Master.RedirPort
	if redir == 0 {
		redir = mihomo.DefaultRedirPort
	}
	// TPROXY needs a listener to hand the packet to. The port is derived from the
	// redirect port by the same rule mihomo's renderer uses, so the two cannot drift
	// apart through an operator override; an empty bind address means the controller
	// has not resolved the gateway yet, and we render no interception rather than
	// steer UDP at an address that does not exist.
	tproxyAddr := ""
	if spec.Master.BindAddress != "" {
		tproxyAddr = fmt.Sprintf("%s:%d", spec.Master.BindAddress, mihomo.TProxyPortFor(redir))
	}
	// Once the interception has moved, this ruleset stops intercepting and the veth
	// exemptions appear. Both follow from the same flag because they are one change:
	// routing client traffic into the namespace without exempting it from the
	// masquerade would rewrite its source — and mihomo, which works precisely
	// because TPROXY does not rewrite the packet, could not answer the right client.
	// Exempting only the masquerade then leaves the source in the client pool and
	// the leak guard drops it one hook later.
	// The namespace's own EGRESS is armed as soon as the namespace is wanted, not
	// when the interception moves — and the two really are separate questions.
	//
	// Everything mihomo will send from in there needs a source the world can answer,
	// and so does the readiness probe that decides whether the move may happen at
	// all. Gating the masquerade on `attached` made that a circle: the gate asked the
	// namespace to reach an exit, and the rule that let it do so was only rendered
	// once the gate had passed. Measured on the stand 2026-09-05 — the namespace
	// could not ping the exit, the gate never passed, and the migration never
	// started. Before the move nothing but the probe sources traffic from this link,
	// so arming it early costs nothing.
	netnsGW, netnsIface := "", ""
	wanted, werr := spec.Master.NetnsWanted()
	if werr == nil && wanted {
		netnsIface = domain.NetnsHostIface
	}
	if netnsAttached {
		if _, peer, aerr := netns.LinkAddrs(spec.Master.NetnsLinkCIDR()); aerr == nil {
			netnsGW, _, _ = strings.Cut(peer, "/")
			netnsIface = domain.NetnsHostIface
		}
	}
	return netfw.MasterNATInput{
		ClientInterface:  clientIface,
		ClientCIDR:       spec.WGServer.AddressPool,
		RedirAddr:        fmt.Sprintf("%s:%d", spec.Master.BindAddress, redir),
		TProxyAddr:       tproxyAddr,
		PrivateCIDRs:     spec.Master.DirectCIDRs,
		NetnsGateway:     netnsGW,
		NetnsHostIface:   netnsIface,
		NetnsLinkCIDR:    spec.Master.NetnsLinkCIDR(),
		ClashAPI:         spec.Master.ExternalController,
		ClientAdminPorts: spec.Master.ClientAdminPorts,
	}
}

func (masterNATPlanner) Component() string { return "master NAT (nftables)" }

func (p masterNATPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("master NAT: node has no master spec")
	}
	attached := p.netnsAttached != nil && p.netnsAttached()
	natIn := NATInput(spec, p.clientIface, attached)
	ruleset, err := netfw.RenderMasterNAT(natIn)
	if err != nil {
		return nil, err
	}
	// NFTApply gates on what was APPLIED, not on what was written. Gating on the file
	// alone let a FAILED `nft -f` look finished: the apply is atomic, so the kernel
	// keeps the old table while the new bytes sit on disk, and the next pass sees an
	// unchanged file plus a present table and reports "already loaded" forever. It
	// also re-applies when the kernel has lost the table, which is what a reboot does.
	p.lastRendered = ruleset
	actions, err := reconcile.NFTApply(p.path, []byte(ruleset), p.isLoaded, nil, "apply master NAT atomically")
	if err != nil {
		return nil, err
	}
	natChanged := changesAmong(actions)
	// The client-facing IPv6 policy, when the controller has decided this master
	// answers IPv6 at all. Rendered here rather than in its own planner because it is
	// the same decision as the NAT above — what happens to a client's packets — and
	// splitting it would let the two halves converge at different times, which for
	// the seconds in between is a client with a ::/0 route and a master that ignores
	// it. Forwarding has to be on for the reject to be reachable at all; the chain's
	// drop policy is what keeps that from turning a master with a public IPv6 address
	// into an open router.
	if p.v6Path != "" {
		v6Wanted := spec.Master.ClientWG != nil && spec.Master.ClientWG.IPv6Prefix != ""
		switch {
		case v6Wanted:
			v6, verr := netfw.RenderMasterV6Block(p.clientIface, spec.Master.ClientWG.IPv6Prefix)
			if verr != nil {
				return nil, verr
			}
			// Forwarding first, every time the ruleset is (re-)applied. It is a sysctl,
			// so a reboot silently returns it to 0 while the file on disk is unchanged —
			// and a client whose config already carries ::/0 then meets a master that
			// drops IPv6 in silence, which is precisely the black hole this feature
			// exists to replace. NFTApply's kernel probe is what notices; gating on the
			// file alone re-created the hazard on the first reboot.
			p.lastV6Rendered = v6
			v6Actions, verr := reconcile.NFTApply(p.v6Path, []byte(v6), p.isV6Loaded, nil,
				"apply the client-facing IPv6 refusal atomically")
			if verr != nil {
				return nil, verr
			}
			// Forwarding is checked against the KERNEL, not against whether the nft
			// actions happen to be changing. It is a sysctl: a `sysctl --system`, a
			// package postinst, a hardening drop-in or a reboot returns it to 0 while
			// the ruleset on disk and the table in the kernel are both untouched — and
			// the reconciler, gating on `changesAmong(v6Actions)`, then had nothing to
			// do, forever. The kernel discards client IPv6 before any chain runs, no
			// ICMPv6 is generated, and every client holding ::/0 is back in the silent
			// black hole this feature exists to replace. The nft half was watched; the
			// half that makes it reachable at all was not.
			//
			// It goes FIRST, before the chain that depends on it, so the window between
			// the two is a master that forwards nothing rather than one that forwards
			// everything with no policy loaded.
			if !p.isV6ForwardingOn() {
				actions = append(actions, reconcile.ExecAction(
					"enable IPv6 forwarding so the client refusal is reachable",
					"sysctl", "-w", "net.ipv6.conf.all.forwarding=1"))
			} else {
				actions = append(actions, reconcile.NoChangeAction(
					"net.ipv6.conf.all.forwarding", "already 1"))
			}
			actions = append(actions, v6Actions...)
		case p.isV6Loaded() || p.weEnabledV6Forwarding():
			// The operator turned the block off, or handed the client interface back.
			// Keyed on EITHER half being present, not just the table: a table lost some
			// other way used to leave forwarding=1 with nothing gating it and no path
			// back, because the only branch that could lower it required the table to
			// still be there.
			// Forwarding goes down BEFORE the chain does: between those two commands the
			// master would otherwise be an IPv6 router with its drop policy already
			// deleted, which is a worse state than either end of the transition.
			actions = append(actions,
				reconcile.ExecAction("stop forwarding IPv6 now that the client refusal is going away",
					"sysctl", "-w", "net.ipv6.conf.all.forwarding=0"),
				reconcile.ExecAction("remove the client-facing IPv6 refusal",
					"nft", "delete", "table", "ip6", netfw.MasterV6Table).BestEffort())
			if forget, ferr := reconcile.RemoveFileAction(reconcile.NFTAppliedMarker(p.v6Path),
				"forget the applied IPv6 ruleset"); ferr == nil {
				actions = append(actions, forget)
			}
			// The rendered file must go too, not just its marker. A ruleset left on
			// disk is one the next pass can re-apply from — and after the operator
			// turned client IPv6 off, reinstalling the refusal table is precisely what
			// must not happen. Remove the intent, not only the record of it.
			if drop, derr := reconcile.RemoveFileAction(p.v6Path,
				"remove the rendered IPv6 ruleset so it is not replayed at boot"); derr == nil {
				actions = append(actions, drop)
			}
		}
	}

	// The nft rules mark the packet; these two tell the kernel a marked packet stays
	// here so the transparent socket can accept it. Without them TPROXY silently
	// does nothing useful: the datagram is routed normally, no socket ever sees it,
	// and client UDP is dropped rather than proxied — worse than the leak it
	// replaces. Repaired on drift for the same reason the nft table is (ADR-0015):
	// someone flushing `ip rule` must not break every client until the next reboot.
	if natIn.TProxyAddr != "" && (natChanged || !p.isTProxyReady()) {
		actions = append(actions, tproxyRouteActions()...)
	} else if natIn.TProxyAddr != "" {
		actions = append(actions, reconcile.NoChangeAction("tproxy policy routing", "fwmark rule and local route in place"))
	}
	return actions, nil
}

// tproxyRouteActions installs the policy routing TPROXY needs, idempotently: the
// delete is best-effort so a first run has nothing to fail on, and `ip route
// replace` is idempotent by construction.
func tproxyRouteActions() []reconcile.Action {
	table := fmt.Sprintf("%d", netfw.TProxyTable)
	mark := fmt.Sprintf("%#x", netfw.TProxyMark)
	pref := fmt.Sprintf("%d", netfw.TProxyRulePref)
	return []reconcile.Action{
		reconcile.BestEffortExecAction(
			fmt.Sprintf("drop any stale tproxy rule (fwmark %s table %s)", mark, table),
			"ip", "rule", "del", "fwmark", mark, "lookup", table),
		reconcile.ExecAction(
			fmt.Sprintf("send tproxy-marked packets (fwmark %s) to table %s", mark, table),
			"ip", "rule", "add", "fwmark", mark, "lookup", table, "pref", pref),
		reconcile.ExecAction(
			fmt.Sprintf("keep tproxy-marked packets local (local default in table %s)", table),
			"ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", table),
	}
}

func (p masterNATPlanner) isTProxyReady() bool {
	if p.tproxyReady == nil {
		return tproxyPolicyRoutingLive()
	}
	return p.tproxyReady()
}

// tproxyPolicyRoutingLive asks the kernel whether BOTH halves are still there.
// Either one missing breaks interception, so both are checked.
func tproxyPolicyRoutingLive() bool {
	table := fmt.Sprintf("%d", netfw.TProxyTable)
	rules, err := exec.Command("ip", "rule", "list").Output()
	if err != nil || !strings.Contains(string(rules), "lookup "+table) {
		return false
	}
	routes, err := exec.Command("ip", "route", "show", "table", table).Output()
	return err == nil && strings.Contains(string(routes), "local default")
}

// changesAmong reports whether any of these actions would do something.
func changesAmong(actions []reconcile.Action) bool {
	for _, a := range actions {
		if a.Changes() {
			return true
		}
	}
	return false
}

// isV6ForwardingOn reads the sysctl rather than assuming it. An unreadable value —
// a non-Linux dev box, where the file does not exist — reports "off", so the plan
// still SHOWS the intent. `sysctl -w` is idempotent, so re-asserting a value that is
// already set costs nothing on the node that matters.
func (p masterNATPlanner) isV6ForwardingOn() bool {
	if p.v6Forwarding != nil {
		return p.v6Forwarding()
	}
	raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == "1"
}

// weEnabledV6Forwarding reports whether THIS agent is the reason IPv6 forwarding is
// on, evidenced by the applied-marker beside the ruleset we wrote.
//
// The off-path needs it. Keying "lower forwarding" on the sysctl alone would have
// the agent switch off a setting the host has for its own reasons the first time the
// block is disabled; keying it on the table alone left forwarding=1 with nothing
// gating it whenever the table was lost some other way. The marker is the record of
// what we did, which is the only thing we are entitled to undo.
func (p masterNATPlanner) weEnabledV6Forwarding() bool {
	if p.v6Path == "" {
		return false
	}
	_, err := os.Stat(reconcile.NFTAppliedMarker(p.v6Path))
	return err == nil
}

// isV6Loaded asks the same strong question its three siblings ask: does the kernel
// hold what we WROTE, not merely a table by that name.
//
// It was the last presence-only probe left after the rest moved to TableMatches, and
// it guards the newest and least forgiving table: an ip6 forward chain whose policy
// is drop and whose one rule is the ICMPv6 refusal. A flushed chain there leaves the
// policy in place and the refusal gone — every forwarded client IPv6 packet
// disappears with no ICMP back, which is precisely the silent black hole this table
// was added to replace. Fixing a bug class on three resources and leaving the fourth
// is how the class comes back.
func (p masterNATPlanner) isV6Loaded() bool {
	if p.v6Loaded != nil {
		return p.v6Loaded()
	}
	if matches, known := netfw.TableMatches("ip6", netfw.MasterV6Table, p.lastV6Rendered); known {
		return matches
	}
	return netfw.TableLoaded("ip6", netfw.MasterV6Table)
}

// isLoaded asks whether the kernel holds THIS ruleset, not merely a table by that
// name. Presence alone left a hand-flushed chain invisible: measured on a rehearsal,
// flushing the TPROXY chain leaked a client's DNS query in cleartext one second
// later while four consecutive passes reported drift=0. An unanswerable question
// (no nft, a dev box) falls back to presence, which is the old, safe behaviour.
func (p masterNATPlanner) isLoaded() bool {
	if p.loaded != nil {
		return p.loaded()
	}
	if matches, known := netfw.TableMatches("ip", netfw.MasterNATTable, p.lastRendered); known {
		return matches
	}
	return netfw.TableLoaded("ip", netfw.MasterNATTable)
}

// Master forwarding (ip_forward + DOCKER-USER accept, an earlier finding) is handled by
// the shared dockerfw.ForwardPlanner, constructed in Planners() with iface wg0.

// wgEasyHandedOver is the reason the wg-easy planners report once the agent owns
// the client leg. Stated rather than silent: an operator reading a plan should
// see that these components stood down deliberately, not that they vanished.
const wgEasyHandedOver = "the agent owns the client interface; wg-easy is no longer managed"

// handedOver reports whether this master's client leg belongs to the agent.
func handedOver(spec domain.NodeSpec) bool {
	return spec.Master != nil && spec.Master.ClientWG != nil
}

// masterComposeInput builds the compose render input from a spec. One function
// rather than two call sites: the test helper used to assemble its own copy, so a
// field added to the render (the namespace holder) made the fixture and the
// planner disagree and the idempotency test failed for a reason that had nothing
// to do with idempotency.
func masterComposeInput(spec domain.NodeSpec, adminUser, adminPass string, attached func() bool) compose.RenderInput {
	return compose.RenderInput{
		Compose:          spec.Master.Compose,
		ClientListenPort: spec.WGServer.ListenPort,
		ClientPool:       spec.WGServer.AddressPool,
		MgmtAddr:         masterMgmtAddr(spec),
		AdminUsername:    adminUser,
		AdminPassword:    adminPass,
		ClientWGManaged:  handedOver(spec),
		NetnsHolderImage: netnsHolderImage(spec),
		// Phase A renders the holder but does NOT move mihomo: the namespace stays
		// inert until the interception rules move with it (see netnsAttach).
		NetnsAttachMihomo: netnsAttach(attached),
	}
}

// netnsAttach reports whether mihomo should live in the namespace yet.
//
// The holder existing and mihomo living in it are two different decisions, and
// keeping them apart is what makes the plumbing inspectable on a live master at
// no risk. This one is taken by the agent, from evidence, once per pass.
func netnsAttach(attached func() bool) bool { return attached != nil && attached() }

// netnsHolderImage returns the image that should own mihomo's network namespace,
// or "" to leave mihomo on host networking.
//
// The holder is rendered as soon as the master wants the namespace at all —
// BEFORE anything is switched over. That is deliberate: the container and its veth
// are inert until the interception rules move, so building them early turns the
// riskiest part of the migration into something that can be inspected on a live
// node with no consequence if it is wrong.
func netnsHolderImage(spec domain.NodeSpec) string {
	if spec.Master == nil {
		return ""
	}
	if wanted, err := spec.Master.NetnsWanted(); err != nil || !wanted {
		return ""
	}
	if img := spec.Master.Compose.NetnsHolderImage; img != "" {
		return img
	}
	// The master's OWN mihomo image, not a small generic one.
	//
	// This started as busybox:1.36, which reads like the obvious choice and is the
	// wrong one on the fleet this runs on. The holder is added to the compose file
	// unconditionally, `docker compose up -d` is run every pass, and a master behind
	// the filtering this fleet exists to get around is exactly where a registry pull
	// fails — so an unfetchable holder meant `up -d` failing on every pass, which
	// (before the same change made it best-effort) took every planner after it down
	// with it: the namespace, mihomo, the master NAT, DOCKER-USER, blocky, VLESS.
	// The node stopped converging entirely over a container it was one step away
	// from not needing.
	//
	// The mihomo image is on the node by construction — it is running. Using it
	// removes the pull rather than making it more likely to succeed, and the holder
	// does not care what is inside it: the container exists to own a namespace and
	// sleep.
	return spec.Master.Compose.MihomoImage
}
