package exit

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/dockerfw"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/tuning"
	"github.com/shidoh/wgfleet/internal/awgmod"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/routing"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/xray"
)

// Input is everything the exit planners need beyond the NodeSpec. PrivateKey is
// the node's WG key (a real persisted key in apply mode, or an ephemeral one in
// plan mode). WARP is the registered wgcf material; nil until `wgcf register`
// has run, in which case the WARP planner emits a notice instead of a config.
type Input struct {
	Paths      Paths
	PrivateKey string
	// RealityPrivateKey is the exit's locally-generated REALITY x25519 private key
	// (ADR-0025), persisted in apply mode / ephemeral in plan mode. Empty on exits
	// that do not run the reality transport (the xray planner then no-ops).
	RealityPrivateKey string
	WARP              *egress.WARPConfig
	// IfaceUp reports whether a network interface currently exists/is up. It lets
	// the WG/WARP planners bring an interface up when it is down even though its
	// config file is unchanged (after a reboot, or a previously failed `up`).
	// nil ⇒ a real `ip link show` check; tests inject a stub.
	IfaceUp func(name string) bool
	// OverlayMSS clamps TCP MSS on the mgmt overlay (control-plane insurance);
	// 0 disables. See config.AgentSection.MgmtOverlayMSS and netfw.RenderInput.
	OverlayMSS int
	// ASBlacklistV4URL / ASBlacklistV6URL / ASBlacklistInterval configure the
	// scanner-ASN feed refresh (agent-local operational knobs, like OverlayMSS).
	// Empty URLs / 0 interval fall back to asnfeed defaults. The per-node enable
	// toggle is spec.Firewall.ASBlacklist (from the wire); these only say where the
	// feed comes from and how often to refresh it.
	ASBlacklistV4URL    string
	ASBlacklistV6URL    string
	ASBlacklistInterval time.Duration
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
		// Node tuning first (BBR congestion control); cheap, independent of the rest.
		tuning.BBRPlanner(),
		firewallPlanner{path: in.Paths.NFT, wgConf: in.Paths.WGConf, overlayMSS: in.OverlayMSS, asBlacklistCache: in.Paths.ASBlacklist, warpMTUCache: in.Paths.WARPMTUCache},
		wgPlanner{path: in.Paths.WGConf, privateKey: in.PrivateKey, up: up},
		warpPlanner{path: in.Paths.WGCF, dir: in.Paths.WARPDir, warp: in.WARP, up: up, warpMTUCache: in.Paths.WARPMTUCache},
		routingPlanner{statePath: in.Paths.RoutingState},
		dnsPlanner{configPath: in.Paths.DNS, composePath: in.Paths.DNSCompose},
		// REALITY/XHTTP inbound (ADR-0025): renders + runs the xray container when the
		// exit's active transport set includes reality; a no-op otherwise. Its
		// host-originated outbound is mark-routed to WARP by the routing planner.
		xrayPlanner{configPath: in.Paths.XrayConfig, composePath: in.Paths.XrayCompose, privateKey: in.RealityPrivateKey},
		// blocky runs in Docker, which sets the nft FORWARD policy to DROP and would
		// silently black-hole client traffic forwarded awg0→wgcf (an earlier finding, same as
		// the master). Runs after dnsPlanner so the DOCKER-USER chain exists.
		dockerfw.NewForwardPlanner(
			"exit forwarding (ip_forward + DOCKER-USER)",
			wgIfaceName(in.Paths.WGConf), "awg0",
			"accept client→egress forwarding (DOCKER-USER)"),
		// Last: refresh the scanner-ASN feed cache (network, Apply-side only). It only
		// writes a file; the firewall (first) renders it into the nft sets next pass.
		newASNFeedPlanner(in),
		// Auto-probe the WARP path MTU (network, Apply-side only): writes the wgcf MTU
		// to a cache file; the WARP + firewall planners read it via effectiveWARPMTU.
		newWARPMTUPlanner(in),
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

// tcpIPHeaderBytes is the IPv4 (20) + TCP (20) header overhead subtracted from a
// tunnel MTU to derive the MSS to clamp to.
const tcpIPHeaderBytes = 40

// wgIfaceName is ifaceName but returns "" for an empty path (filepath.Base("")
// is ".", which would otherwise leak a bogus interface name into the ruleset).
func wgIfaceName(confPath string) string {
	if confPath == "" {
		return ""
	}
	return ifaceName(confPath)
}

// --- firewall ---

type firewallPlanner struct {
	path string
	// wgConf is the exit WG config path; its basename is the interface name the
	// MASQUERADE excludes (`oifname != <iface>`). Empty ⇒ the renderer defaults it.
	wgConf string
	// overlayMSS clamps TCP MSS on the mgmt overlay (0 ⇒ no clamp).
	overlayMSS int
	// asBlacklistCache is the scanner-ASN feed cache path; read (best-effort) and
	// rendered into the as_blacklist sets when spec.Firewall.ASBlacklist is on.
	asBlacklistCache string
	// warpMTUCache is the auto-probed WARP MTU cache path (effectiveWARPMTU), used to
	// size the forwarded-TCP MSS clamp to the real WARP path.
	warpMTUCache string
	// loaded reports whether the live kernel holds THIS exit firewall ruleset.
	// nil ⇒ a real probe against the kernel; tests inject a stub.
	loaded func() bool
	// lastRendered is what Plan just rendered, so isLoaded can ask the strong
	// question — does the kernel hold this — rather than "is a table by this name
	// present". Set on the receiver copy inside Plan, which is why isLoaded is only
	// ever taken as a method value after the assignment.
	lastRendered string
}

func (firewallPlanner) Component() string { return "firewall (nftables)" }

func (p firewallPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	in := netfw.RenderInput{
		Firewall: spec.Firewall,
		Role:     spec.Role,
		// SNAT client traffic on egress so packets leaving WARP carry the egress
		// address, not the master's private tunnel IP (else the upstream drops them).
		ClientCIDR:      spec.WGServer.AddressPool,
		WGInterface:     wgIfaceName(p.wgConf),
		EgressInterface: spec.Routing.EgressInterface,
		OverlayMSS:      p.overlayMSS,
	}
	// On an egress-routed exit, mark this node's WG-server reply/handshake packets
	// so the routing `ip rule fwmark` keeps them off the WARP interface (earlier findings
	// ). The mark MUST match the routing ip-rule's, so both resolve it the same
	// way. Direct egress ⇒ no egress interface ⇒ no mark needed.
	if spec.Routing.EgressInterface != "" {
		in.WGReplyMark = routing.EffectiveFwMark(spec.Routing)
	}
	// Clamp forwarded TCP MSS (both directions) to the tightest tunnel on the client
	// path: the master↔exit tunnel (WGServer.MTU) or, if smaller, a constrained WARP
	// path (WARPMTU). Without it the server's response segments — sized for the looser
	// egress — black-hole on the return through the master↔exit tunnel.
	if spec.Role == domain.RoleExit && spec.WGServer.MTU > 0 {
		clampMTU := spec.WGServer.MTU
		if warpMTU := effectiveWARPMTU(spec, p.warpMTUCache); warpMTU > 0 && warpMTU < clampMTU {
			clampMTU = warpMTU
		}
		in.ClampMSS = clampMTU - tcpIPHeaderBytes
	}
	// Render the scanner-ASN blacklist from the on-disk feed cache (best-effort: a
	// missing or corrupt cache yields empty sets, fail-open). Reading a local file
	// keeps Plan side-effect-free; the feed planner does the network fetch Apply-side.
	if spec.Firewall.ASBlacklist {
		in.ASBlacklistV4, in.ASBlacklistV6 = readASBlacklistCache(p.asBlacklistCache)
	}
	ruleset, err := netfw.RenderRuleset(in)
	if err != nil {
		return nil, err
	}
	// NFTApply, and a by-content probe: an apply that FAILED must not be recorded as
	// done, and a table that is merely PRESENT is not a table that holds what we
	// wrote. Measured on the stand before this changed — `nft delete rule inet wgfleet
	// input handle 15` on the exit survived three reconcile passes with the node
	// reporting `drift=0 state=Ready`, while deleting the WHOLE table was repaired in
	// under 15 seconds. This table carries the whitelist, the scanner-ASN blacklist,
	// `ct state invalid drop` and the egress leak guard; a rule quietly removed from
	// it is exactly what nothing else in the system would notice.
	p.lastRendered = ruleset
	actions, err := reconcile.NFTApply(p.path, []byte(ruleset), p.isLoaded, nil, "apply ruleset atomically")
	if err != nil {
		return nil, err
	}
	return actions, nil
}

func (p firewallPlanner) isLoaded() bool {
	if p.loaded != nil {
		return p.loaded()
	}
	if matches, known := netfw.TableMatches("inet", netfw.ExitTable, p.lastRendered); known {
		return matches
	}
	return netfw.TableLoaded("inet", netfw.ExitTable)
}

// --- amneziawg interface ---

type wgPlanner struct {
	path       string
	privateKey string
	up         func(name string) bool
	// awgGen reports this node's AmneziaWG kernel module MAJOR version; nil ⇒ the
	// real modinfo probe. Only consulted for a spec that asks for AmneziaWG 3.0
	// (see awgmod.CheckAWG3Supported).
	awgGen func() (int, error)
}

func (wgPlanner) Component() string { return "amneziawg interface" }

// awgTransportDisabled reports whether this exit has EXPLICITLY turned the AWG
// master↔exit transport off (ADR-0025).
//
// The test is deliberately narrow. NodeSpec.Transports() treats an EMPTY
// EnabledTransports as [TransportAWG] for back-compat, so an old controller, a
// conversion bug, or any spec that simply fails to populate the field reads as
// "AWG enabled" — and this returns false, i.e. we never tear anything down on
// missing information. Only a spec that names its transports AND omits AWG
// counts as an instruction to remove the interface.
//
// That asymmetry is the whole point: bringing an interface down on a bad spec
// costs an exit's data plane, while leaving a stale one up costs some dropped
// packets. Fail toward the cheap mistake.
func awgTransportDisabled(spec domain.NodeSpec) bool {
	return len(spec.EnabledTransports) > 0 && !spec.HasTransport(domain.TransportAWG)
}

func (p wgPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	// A reality-only exit must not keep an AWG server interface up. Rendering it
	// unconditionally left pn8 (awg.enabled=false) carrying awg0 with the master's
	// stale peer and no endpoint, quietly accumulating TX drops — and, because the
	// peer still held the pre-ADR-0030 shared master key, a live trap for whenever
	// AWG got re-enabled there. Observed 2026-07-19; the interface was deleted by
	// hand and the agent had rebuilt it within the day, which is what identified
	// this planner rather than a leftover as the source.
	if awgTransportDisabled(spec) {
		if !p.isUp() {
			return []reconcile.Action{reconcile.NoChangeAction("amneziawg interface",
				"awg transport disabled; interface already down")}, nil
		}
		// Down only — the config file stays. Re-enabling then needs no special path
		// (the render/up branch below just runs again), and the firewall planner
		// still derives its interface name from that path.
		return []reconcile.Action{reconcile.BestEffortExecAction(
			"awg transport disabled — bring the interface down", "awg-quick", "down", p.path)}, nil
	}

	// AmneziaWG 3.0 needs a 3.x kernel module: its netlink attribute layout is not
	// the 1.x one, so awg setconf would reject the config and leave the interface
	// down. Check BEFORE rendering — writing a config we know cannot be applied and
	// then running awg-quick would take a live exit's data plane with it.
	if awg := spec.WGServer.AWG; awg != nil && awg.AWG3Enabled() {
		if err := awgmod.CheckAWG3Supported(p.awgGen); err != nil {
			return nil, err
		}
	}

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
	path         string
	dir          string // WARPDir: where wgcf keeps the account + generated profile
	warp         *egress.WARPConfig
	up           func(name string) bool
	warpMTUCache string // auto-probed WARP MTU cache (effectiveWARPMTU)
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
		// the operator override (spec.WARPMTU, an earlier finding's 1320-1420 band), else the
		// auto-probed path MTU from the cache, else wg.DefaultWARPMTU (effectiveWARPMTU).
		// WARP is vanilla WG — Cloudflare can't do AmneziaWG.
		cfg.MTU = effectiveWARPMTU(spec, p.warpMTUCache)
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

// directEgressMarker is the routing state-file content for a direct-egress exit.
// It is deliberately a comment line that can never appear in a routing Script
// (which holds ip rule/route/conntrack/sysctl commands), so the WARP↔direct
// transition is always a content change the FileAction gate detects.
const directEgressMarker = "# direct egress: no policy routing\n"

type routingPlanner struct {
	statePath string
	// applied reports whether the live kernel still reflects the routing intent.
	// nil ⇒ a real `ip rule list` + `ip route show` probe; tests inject a stub.
	applied func(domain.RoutingSpec) bool
}

func (routingPlanner) Component() string { return "policy routing" }

func (p routingPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	// Scope the egress rule to THIS exit's client pool so only client traffic is
	// WARP-routed — never the host's own. The pool is not a wire field;
	// derive it agent-side from the WG server spec the agent already holds.
	rspec := spec.Routing
	rspec.ClientCIDR = spec.WGServer.AddressPool
	// When this exit runs the REALITY transport, its xray inbound dials from the
	// host and marks its sockets so policy routing sends them through WARP, not the
	// host default route. Mirror that mark into the routing intent so
	// the matching `fwmark <mark> lookup <egress-table>` rule is rendered (ADR-0025).
	// Only meaningful with a WARP egress; routing.Render no-ops for direct egress.
	if spec.HasTransport(domain.TransportRealityXHTTP) {
		rspec.RealityEgressMark = xray.EgressMark
	}
	steps, err := routing.Render(rspec)
	if err != nil {
		return nil, err
	}
	if len(steps) == 0 {
		// Direct egress runs no policy routing — but if the state file currently holds
		// a WARP ruleset, the active egress just switched WARP→direct (a censorship
		// failover, ADR-0017). routing.Render can't see that transition: it is handed
		// only the new direct intent and returns nothing.
		//
		// Rendering nothing is not the same as undoing something, and for a long time
		// this branch confused the two. It flushed conntrack and stopped there, so
		// `ip rule from <pool> lookup <egress-table>` and the table's `default dev
		// wgcf` survived in the kernel — and warpPlanner keeps wgcf UP on purpose, so
		// there was still a live interface for them to point at. Every client packet
		// went on being policy-routed into the tunnel ADR-0017 had just declared
		// blocked, and the flush re-pinned the flows onto that same dead path. The
		// whole failover was a no-op in the data plane.
		//
		// TeardownActions is the exact inverse of Render and ends with its own
		// conntrack flush, so it subsumes what this branch used to do. Its deletes
		// tolerate "does not exist", which is what makes it safe on a node that never
		// had WARP. The state-file marker keeps it a one-shot: it fires only on the
		// pass the intent actually changes.
		file, err := reconcile.FileAction(p.statePath, []byte(directEgressMarker), 0o644, nil)
		if err != nil {
			return nil, err
		}
		actions := []reconcile.Action{file}
		if file.Changes() {
			actions = append(actions, routingExecActions(routing.TeardownActions())...)
		} else {
			actions = append(actions, reconcile.NoChangeAction("policy routing", "direct egress, no policy routing"))
		}
		return actions, nil
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
	case !p.isApplied(rspec):
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

func (p dnsPlanner) isUp(ctx context.Context) bool {
	if p.up == nil {
		return compose.StackUp(ctx, p.composePath)
	}
	return p.up(p.composePath)
}

func (p dnsPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
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
	extra, err := reconcile.ManagedFileActions(spec.DNS.Custom.Files, filepath.Dir(p.configPath))
	if err != nil {
		return nil, err
	}
	configChanged := cfgFile.Changes()
	for _, fa := range extra {
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
	case !p.isUp(ctx):
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
