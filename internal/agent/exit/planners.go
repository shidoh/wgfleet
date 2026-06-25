package exit

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/tuning"
	"github.com/shidoh/wgfleet/internal/asnfeed"
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
		firewallPlanner{path: in.Paths.NFT, wgConf: in.Paths.WGConf, overlayMSS: in.OverlayMSS, asBlacklistCache: in.Paths.ASBlacklist},
		wgPlanner{path: in.Paths.WGConf, privateKey: in.PrivateKey, up: up},
		warpPlanner{path: in.Paths.WGCF, dir: in.Paths.WARPDir, warp: in.WARP, up: up},
		routingPlanner{statePath: in.Paths.RoutingState},
		dnsPlanner{configPath: in.Paths.DNS, composePath: in.Paths.DNSCompose},
		// REALITY/XHTTP inbound (ADR-0025): renders + runs the xray container when the
		// exit's active transport set includes reality; a no-op otherwise. Its
		// host-originated outbound is mark-routed to WARP by the routing planner.
		xrayPlanner{configPath: in.Paths.XrayConfig, composePath: in.Paths.XrayCompose, privateKey: in.RealityPrivateKey},
		// blocky runs in Docker, which sets the nft FORWARD policy to DROP and would
		// silently black-hole client traffic forwarded awg0→wgcf (an earlier finding, same as
		// the master). Runs after dnsPlanner so the DOCKER-USER chain exists.
		forwardPlanner{wgIface: wgIfaceName(in.Paths.WGConf)},
		// Last: refresh the scanner-ASN feed cache (network, Apply-side only). It only
		// writes a file; the firewall (first) renders it into the nft sets next pass.
		newASNFeedPlanner(in),
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

// --- docker FORWARD accept ---

// forwardPlanner keeps the exit forwarding client traffic despite Docker. The
// blocky container makes Docker set the nft filter FORWARD policy to DROP and
// accept only its own bridge traffic, so client packets routed awg0→wgcf are
// dropped in the forward hook — the master↔exit AWG handshake stays healthy
// (that is INPUT on awg0's port, not forward) while all transit silently dies.
// The exit's own `inet wgfleet` forward chain (policy accept) cannot override
// it: a drop in Docker's base chain is final regardless of an accept in another
// at the same hook. The sanctioned fix is an ACCEPT in DOCKER-USER, which Docker
// never flushes. Mirrors the master's forward planner with iface = awg0.
type forwardPlanner struct {
	wgIface string
	// Probes (nil ⇒ real); injected in tests.
	forwardOn   func() bool
	chainExists func() bool
	rulePresent func(m []string) bool
}

func (forwardPlanner) Component() string { return "exit forwarding (ip_forward + DOCKER-USER)" }

func (p forwardPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	iface := p.wgIface
	if iface == "" {
		iface = "awg0"
	}
	var actions []reconcile.Action

	if p.isForwardOn() {
		actions = append(actions, reconcile.NoChangeAction("ip_forward", "already enabled"))
	} else {
		actions = append(actions, reconcile.ExecAction("enable IPv4 forwarding",
			"sysctl", "-w", "net.ipv4.ip_forward=1"))
	}

	if !p.dockerUserExists() {
		actions = append(actions, reconcile.NoChangeAction("DOCKER-USER",
			"pending: DOCKER-USER chain not present yet (docker not up)"))
		return actions, nil
	}
	rules := []struct {
		summary string
		match   []string
	}{
		{"accept client→egress forwarding (DOCKER-USER)", []string{"-i", iface, "-j", "ACCEPT"}},
		{"accept return traffic to clients (DOCKER-USER)", []string{"-o", iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}
	for _, r := range rules {
		if p.isRulePresent(r.match) {
			actions = append(actions, reconcile.NoChangeAction("DOCKER-USER", r.summary+" already present"))
			continue
		}
		argv := append([]string{"iptables", "-I", "DOCKER-USER"}, r.match...)
		actions = append(actions, reconcile.ExecAction(r.summary, argv...))
	}
	return actions, nil
}

func (p forwardPlanner) isForwardOn() bool {
	if p.forwardOn != nil {
		return p.forwardOn()
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func (p forwardPlanner) dockerUserExists() bool {
	if p.chainExists != nil {
		return p.chainExists()
	}
	return exec.Command("iptables", "-S", "DOCKER-USER").Run() == nil
}

func (p forwardPlanner) isRulePresent(match []string) bool {
	if p.rulePresent != nil {
		return p.rulePresent(match)
	}
	argv := append([]string{"-C", "DOCKER-USER"}, match...)
	return exec.Command("iptables", argv...).Run() == nil
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
	// loaded reports whether the live kernel has the exit firewall table.
	// nil ⇒ a real `nft list table inet wgfleet` probe; tests inject a stub.
	loaded func() bool
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
		if spec.WARPMTU > 0 && spec.WARPMTU < clampMTU {
			clampMTU = spec.WARPMTU
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

// readASBlacklistCache loads the scanner-ASN feed cache into canonical v4/v6
// prefix lists. It is deliberately best-effort: a missing or corrupt cache (the
// feed has not been fetched yet, or was torn) yields empty lists so the firewall
// renders empty sets (fail-open) rather than failing the whole reconcile.
func readASBlacklistCache(path string) (v4, v6 []string) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	v4, v6, err = asnfeed.DecodeCache(f)
	if err != nil {
		slog.Warn("AS-blacklist cache unreadable; rendering empty sets (fail-open)", "path", path, "err", err)
		return nil, nil
	}
	return v4, v6
}

// --- scanner-ASN blacklist feed refresh (lesson: hide exits from VPN scanners) ---

// asnFeedPlanner refreshes the scanner-ASN blacklist cache from the C24Be feeds.
// It is a feed CACHE writer, not a kernel actor: it downloads the feeds (Apply-
// side only, so dry-run never hits the network) and writes the cache file; the
// firewall planner renders that cache into the nft sets on the next pass. The
// refresh is gated on the cache file's age (the persisted last-success time) so it
// runs about once per interval, with a shorter retry window on failure so a flaky
// source is not hammered every reconcile. A failed fetch is non-fatal — the last-
// good list stays in place (fail-safe).
type asnFeedPlanner struct {
	cachePath string
	v4URL     string
	v6URL     string
	interval  time.Duration
	now       func() time.Time
	// refresh fetches+parses the feeds and returns the cache bytes to persist.
	// nil ⇒ the real asnfeed.Refresh; tests inject a stub.
	refresh func(ctx context.Context, v4URL, v6URL string, now time.Time) ([]byte, error)
}

func newASNFeedPlanner(in Input) asnFeedPlanner {
	v4 := in.ASBlacklistV4URL
	if v4 == "" {
		v4 = asnfeed.DefaultV4URL
	}
	v6 := in.ASBlacklistV6URL
	if v6 == "" {
		v6 = asnfeed.DefaultV6URL
	}
	interval := in.ASBlacklistInterval
	if interval <= 0 {
		interval = asnfeed.DefaultInterval
	}
	return asnFeedPlanner{cachePath: in.Paths.ASBlacklist, v4URL: v4, v6URL: v6, interval: interval}
}

func (asnFeedPlanner) Component() string { return "AS-blacklist feed" }

// Scheduled marks the feed refresh as out-of-band (timer-driven): its daily cache
// update is expected work, not divergence from the spec, so the drift detector
// must not count it — otherwise every refresh would WARN and bump
// agent_drift_total. See reconcile.ScheduledPlanner / Report.DriftComponents.
func (asnFeedPlanner) Scheduled() bool { return true }

// attemptPath is the marker touched on every refresh ATTEMPT (success or failure)
// so a failing source backs off to the retry window instead of refetching every
// pass. It sits next to the cache.
func (p asnFeedPlanner) attemptPath() string { return p.cachePath + ".attempt" }

func (p asnFeedPlanner) nowTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// retryFloor is the minimum spacing between refresh attempts after a stale cache
// is detected — bounded so it never exceeds the interval (short test intervals
// still retry promptly) and never spams a flaky source faster than hourly.
func (p asnFeedPlanner) retryFloor() time.Duration {
	if p.interval < time.Hour {
		return p.interval
	}
	return time.Hour
}

func (p asnFeedPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.Firewall.ASBlacklist {
		return []reconcile.Action{reconcile.NoChangeAction("AS-blacklist feed", "disabled")}, nil
	}
	if p.cachePath == "" {
		return []reconcile.Action{reconcile.NoChangeAction("AS-blacklist feed", "no cache path configured")}, nil
	}
	now := p.nowTime()
	if fi, err := os.Stat(p.cachePath); err == nil && now.Sub(fi.ModTime()) < p.interval {
		return []reconcile.Action{reconcile.NoChangeAction(p.cachePath, "feed fresh (within interval)")}, nil
	}
	// Cache stale or absent: refresh, unless we attempted too recently (backoff).
	if ai, err := os.Stat(p.attemptPath()); err == nil && now.Sub(ai.ModTime()) < p.retryFloor() {
		return []reconcile.Action{reconcile.NoChangeAction(p.cachePath, "feed stale; awaiting retry window")}, nil
	}
	display := fmt.Sprintf("GET %s\nGET %s", p.v4URL, p.v6URL)
	apply := func(ctx context.Context) error {
		// Record the attempt first so a failure backs off even though the cache mtime
		// (the success marker) does not advance.
		_ = os.WriteFile(p.attemptPath(), []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o644)
		refresh := p.refresh
		if refresh == nil {
			refresh = func(c context.Context, v4, v6 string, t time.Time) ([]byte, error) {
				cache, _, _, err := asnfeed.Refresh(c, &http.Client{}, v4, v6, t)
				return cache, err
			}
		}
		cache, err := refresh(ctx, p.v4URL, p.v6URL, now)
		if err != nil {
			// Non-fatal, never silent: keep the last-good list and try again next window.
			slog.Warn("AS-blacklist refresh failed (non-fatal; keeping last-good list)",
				"v4", p.v4URL, "v6", p.v6URL, "err", err)
			return nil
		}
		if err := atomicWriteFile(p.cachePath, cache, 0o644); err != nil {
			return fmt.Errorf("write AS-blacklist cache: %w", err)
		}
		slog.Info("AS-blacklist refreshed", "bytes", len(cache), "path", p.cachePath)
		return nil
	}
	return []reconcile.Action{reconcile.CustomAction(
		reconcile.ActionUpdate, p.cachePath, "refresh scanner-ASN blacklist feed", display, apply,
	)}, nil
}

// atomicWriteFile writes data to a temp file in the same dir and renames it over
// path, so a reader (the firewall planner) never sees a half-written cache.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".asnfeed-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp over %q: %w", path, err)
	}
	return nil
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
		// failover, ADR-0017). routing.Render can't see that transition (it sees only
		// the new direct intent and returns nothing), so flush conntrack here: flows
		// pinned to the now-dead WARP path must re-resolve at once instead of black-
		// holing for up to the conntrack timeout. The state-file marker
		// makes it a one-shot — it fires only the pass the intent actually changes.
		file, err := reconcile.FileAction(p.statePath, []byte(directEgressMarker), 0o644, nil)
		if err != nil {
			return nil, err
		}
		actions := []reconcile.Action{file}
		if file.Changes() {
			actions = append(actions, reconcile.BestEffortExecAction(
				"flush conntrack on egress switch to direct", "conntrack", "-D"))
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

// --- REALITY/XHTTP inbound (xray, ADR-0025) ---

type xrayPlanner struct {
	configPath  string
	composePath string
	privateKey  string                 // REALITY x25519 private key (exit-local)
	up          func(file string) bool // nil ⇒ real `docker compose ps` probe
}

func (xrayPlanner) Component() string { return "reality inbound (xray)" }

func (p xrayPlanner) isUp() bool {
	if p.up == nil {
		return compose.StackUp(p.composePath)
	}
	return p.up(p.composePath)
}

func (p xrayPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.HasTransport(domain.TransportRealityXHTTP) || spec.Reality == nil {
		// Exit does not run the reality transport: nothing to converge. Full removal of
		// a previously-running xray happens via teardown/decommission (mirrors the dns
		// filter's disabled path).
		return []reconcile.Action{reconcile.NoChangeAction("reality inbound", "disabled")}, nil
	}
	if p.privateKey == "" {
		return []reconcile.Action{reconcile.NoChangeAction("reality inbound",
			"pending: REALITY private key not yet available")}, nil
	}
	cfg, err := xray.RenderConfig(xray.RenderInput{
		Spec:       *spec.Reality,
		PrivateKey: p.privateKey,
		EgressMark: xray.EgressMark,
	})
	if err != nil {
		return nil, fmt.Errorf("render reality inbound: %w", err)
	}
	composeYAML, err := compose.RenderXrayCompose(compose.XrayInput{
		Image:      spec.Reality.Image,
		ConfigPath: p.configPath,
	})
	if err != nil {
		return nil, fmt.Errorf("render reality compose: %w", err)
	}

	// config.json carries the REALITY private key; redact it in plan/dry-run output.
	cfgFile, err := reconcile.FileAction(p.configPath, []byte(cfg), 0o600, xray.RedactConfig)
	if err != nil {
		return nil, err
	}
	composeFile, err := reconcile.FileAction(p.composePath, []byte(composeYAML), 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{composeFile, cfgFile}

	switch {
	case composeFile.Changes():
		actions = append(actions, reconcile.ExecAction("bring xray stack up",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	case cfgFile.Changes():
		actions = append(actions, reconcile.ExecAction("restart reality inbound",
			"docker", "compose", "-f", p.composePath, "restart", "xray"))
	case !p.isUp():
		actions = append(actions, reconcile.ExecAction("bring xray stack up (was down)",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	default:
		actions = append(actions, reconcile.NoChangeAction("reality inbound", "xray already up"))
	}
	return actions, nil
}
