package master

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/restart"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netns"
	"github.com/shidoh/wgfleet/internal/wg"
)

// --- mihomo config + included direct-networks ---

// mihomoConfigMode is the at-rest mode of the rendered mihomo config. Named rather
// than repeated as a literal because two places write that file — the normal
// FileAction and the rejection rollback in applyConfigAction — and a rollback that
// silently widened the mode would expose one WireGuard private key per exit.
const mihomoConfigMode = 0o600

type mihomoPlanner struct {
	paths      Paths
	privateKey string
	// reload hot-applies the config via the Clash API (nil ⇒ the real mihomo.Reload);
	// injected in tests. Preferred over a container restart so a routine change like
	// draining one exit does not drop every client's connection.
	reload func(ctx context.Context, controllerAddr, secret string, cfgYAML []byte) error
	// probeBudget bounds the whole probing phase (0 ⇒ mihomo.ProbePhaseBudget).
	// Injected in tests so the bound can be asserted without waiting out the real one.
	probeBudget time.Duration
	// restart bounces the container (nil ⇒ real `docker compose restart mihomo`);
	// injected in tests. Used when a wireguard-proxy change can't be hot-reloaded.
	restart func(ctx context.Context) error
	// tier decides whether wg-best routes to the reserve tier. Stateful across
	// reconcile passes (hysteresis streaks, warm-up cadence), so it is OWNED BY THE
	// AGENT and passed in via Input.Tier — Planners() runs once per pass, so a
	// selector built here would reset every 30s and silently never fail over.
	// nil ⇒ never fail over (the correct degenerate behaviour with no reserve).
	tier *TierSelector
	// netnsAttached reports whether mihomo has been moved into its own network
	// namespace. Everything mihomo binds and everything the agent dials depends on
	// the answer, so it is threaded here rather than re-derived: the config and the
	// namespace disagreeing is the whole failure mode.
	netnsAttached func() bool
	// disturbed is told after a reload or restart of mihomo has been applied; nil
	// ⇒ nobody listens. See Input.OnMihomoDisturbed.
	disturbed func()
}

func (mihomoPlanner) Component() string { return "mihomo (data plane)" }

// tunnelKey derives the master's dedicated private key for one master↔exit tunnel
// (ADR-0030). It is the render input's key resolver, kept here rather than in the
// renderer so mihomo.RenderConfig never touches key material — it only ever
// receives a key it was handed.
func (p mihomoPlanner) tunnelKey(tunnel string) (string, error) {
	kp, err := wg.DeriveTunnelKey(p.privateKey, tunnel)
	if err != nil {
		return "", err
	}
	return kp.PrivateKey, nil
}

func (p mihomoPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo: node has no master spec")
	}
	// Decide the active tier BEFORE rendering: mihomo cannot choose between tiers
	// itself (see mihomo.wgBestGroups), so the group's membership is our call.
	reserveActive := false
	if p.tier != nil {
		primary, reserve := mihomo.TierMembers(*spec.Master)
		addr, secret := ClashAPIAddr(spec, p.netnsAttached != nil && p.netnsAttached()), clashSecret(spec.Master)
		// One budget for the WHOLE phase, not per member. The three probe phases below
		// coincide every 10th pass — 11 members on the live fleet — and each member is
		// bounded only by its own timeout, so a blocked destination could push the pass
		// far past the 30s interval and slide the status report toward the staleness
		// alert. Running out of budget is safe by construction: every probe path here
		// treats an unanswerable sample as "hold the current verdict".
		budget := p.probeBudget
		if budget == 0 {
			budget = mihomo.ProbePhaseBudget
		}
		probeCtx, cancelProbes := context.WithTimeout(ctx, budget)
		defer cancelProbes()
		probe := func(ctx context.Context, name string) (int, int, error) {
			return mihomo.ProbeMember(ctx, addr, secret, name, nil)
		}
		reserveActive = p.tier.ReserveActive(probeCtx, probe, primary, reserve)
		// The standby transports are drained on purpose, so they are in neither tier
		// and nothing above reaches them. Probing them changes no decision here — the
		// transport switch is the operator's — it only makes the answer available
		// BEFORE the switch instead of after it.
		p.tier.ProbeStandbyTransports(probeCtx, probe, mihomo.StandbyProxies(*spec.Master))
	}
	attached := p.netnsAttached != nil && p.netnsAttached()
	peerIP := NetnsPeerIP(spec, attached)
	cfg, err := mihomo.RenderConfig(mihomo.RenderInput{
		Spec: *spec.Master, PrivateKey: p.privateKey, ReserveActive: reserveActive,
		TunnelPrivateKey: p.tunnelKey, Resolvers: mihomoResolvers(spec, attached),
		NetnsPeerAddr: peerIP,
	})
	if err != nil {
		// Defer this component; do NOT fail the pass.
		//
		// The engine aborts on the first planner error, and this planner runs before
		// the master NAT, DOCKER-USER, blocky and the client VLESS inbound. So a
		// spec the controller sent that mihomo cannot render — every exit drained, a
		// tunnel whose per-tunnel key will not resolve, params mihomo's userspace
		// backend rejects — stopped ALL of them. On a master that rebooted in that
		// state it came back with no client DNAT, no TPROXY and no masquerade, and
		// the !isLoaded() self-heal branches written for exactly that never ran.
		//
		// Keeping the last-good config is what this situation calls for anyway: the
		// data plane on disk still works, and the fault is upstream, not here.
		return []reconcile.Action{reconcile.NoChangeAction("mihomo (data plane)",
			"spec rejected, keeping the last-good config: "+err.Error())}, nil
	}
	// Snapshot the on-disk config BEFORE the FileAction overwrites it, so we can tell
	// whether the wireguard proxies (AmneziaWG params) changed and a hot reload would
	// silently no-op (see applyConfigAction / mihomo.ProxiesChanged).
	oldCfg, _ := os.ReadFile(p.paths.MihomoConfig)
	configAction, err := reconcile.FileAction(p.paths.MihomoConfig, []byte(cfg), mihomoConfigMode, mihomo.RedactConfig)
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
		// A wireguard-proxy change (AmneziaWG params/keys/endpoint/MTU) needs a full
		// container restart — a Clash API hot reload does not re-init the proxy's
		// device. Routine changes (drain, rules, DNS, direct-networks) hot-reload so
		// existing client connections survive.
		// Listeners count as "cannot be hot-reloaded" for a stronger reason than
		// proxies do: a reload accepts a moved bind-address, reports success and
		// re-opens nothing, so mihomo goes on listening where it was while the rules
		// point at where it is supposed to be.
		changed := mihomo.ChangedProxies(oldCfg, []byte(cfg))
		changed = append(changed, mihomo.ChangedListeners(oldCfg, []byte(cfg))...)
		// Name what moved, as key paths. The rendered config is not kept, so once the
		// file is overwritten this line in the journal is the only record of why
		// mihomo was asked to reload — and a reload is never free (see the
		// leaked-device planner below).
		why := mihomo.DescribeChange(oldCfg, []byte(cfg))
		if directAction.Changes() {
			why = strings.TrimPrefix(why+"; direct-networks.yaml", "; ")
		}
		actions = append(actions, p.applyConfigAction(spec, []byte(cfg), oldCfg, changed, why).OnApplied(p.disturbed))
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
// surfaced as an error WITHOUT a restart, so the previous good config keeps running —
// and prevCfg (the bytes that were on disk before this pass overwrote them) is put
// BACK, so disk and the running config agree again. Leaving the rejected bytes on
// disk would be a delayed-action failure: the pass merely errors, but the next
// restart for an unrelated reason (host reboot, compose planner, mihomoRedirPlanner's
// rebind self-heal, mihomoWGDupPlanner) loads the bad file and drops the data plane
// far from the change that caused it. prevCfg empty (first ever write) ⇒ nothing to
// roll back to, so the file is left as-is and only the rejection is reported.
func (p mihomoPlanner) applyConfigAction(spec domain.NodeSpec, cfgYAML, prevCfg []byte, changedProxies []string, why string) reconcile.Action {
	if why == "" {
		why = "<no difference found>"
	}
	reload := p.reload
	if reload == nil {
		reload = mihomo.Reload
	}
	addr := ClashAPIAddr(spec, p.netnsAttached != nil && p.netnsAttached())
	secret := clashSecret(spec.Master)
	compose := p.paths.Compose

	restart := p.restart
	if restart == nil {
		restart = composeRestartMihomo(compose)
	}

	// A wireguard-proxy change must restart the container: a hot reload cannot
	// re-init an existing AmneziaWG device, so new S/H params silently never apply.
	//
	// The summary NAMES the proxies. A restart drops every client connection and
	// every UDP NAT entry, so "why" belongs in the record: on 2026-09-04 the master
	// bounced twice in 36 seconds and nothing on the box could say which proxy moved.
	if len(changedProxies) > 0 {
		return reconcile.CustomAction(reconcile.ActionUpdate, "mihomo",
			"restart mihomo (proxy definitions changed, hot reload can't re-init the device): "+
				strings.Join(changedProxies, ", ")+" — changed: "+why,
			"docker compose restart mihomo", restart)
	}

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
			if rerr := restart(ctx); rerr != nil {
				return fmt.Errorf("mihomo reload unreachable (%v) and %w", err, rerr)
			}
			return nil
		default:
			// Reachable but rejected the config: leave the old config running AND
			// restore it on disk, so a later restart cannot resurrect the rejection.
			if len(prevCfg) == 0 {
				return err
			}
			if rerr := reconcile.AtomicWrite(p.paths.MihomoConfig, prevCfg, mihomoConfigMode); rerr != nil {
				return fmt.Errorf("mihomo rejected the config (%w) and restoring the previous one failed: %v", err, rerr)
			}
			return fmt.Errorf("%w (previous config restored on disk)", err)
		}
	}
	return reconcile.CustomAction(reconcile.ActionUpdate, "mihomo",
		"reload mihomo config in place (Clash API; existing connections preserved) — changed: "+why, display, apply)
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

// restartKeyMihomo names mihomo's restart budget in the governor. One key for the
// whole container: both self-heal planners below bounce the SAME process, so they
// must share a budget or two alternating conditions would each keep their own and
// together restart twice as often as either is allowed to.
const restartKeyMihomo = "mihomo"

// gateRestart wraps a self-heal restart action in the governor's budget. When the
// budget is spent it returns a no-change action that SAYS SO — a suppressed repair
// must not read as a healthy pass, or an operator looking at the plan sees
// "nothing to do" while the data plane is broken.
//
// The Record hook rides OnApplied, so plan mode cannot spend budget: repeatedly
// inspecting a broken master would otherwise throttle the very repair the operator
// is about to authorise.
func gateRestart(gov *restart.Governor, disturbed func(), target string, act reconcile.Action) reconcile.Action {
	ok, until := gov.Allow(restartKeyMihomo)
	if !ok {
		return reconcile.NoChangeAction(target, fmt.Sprintf(
			"restart throttled until %s — mihomo has needed a self-heal restart too often, "+
				"so restarting again is not fixing it; investigate rather than wait",
			until.Format(time.RFC3339)))
	}
	return act.OnApplied(func() {
		gov.Record(restartKeyMihomo)
		if disturbed != nil {
			disturbed()
		}
	})
}

// --- mihomo redirect-listener self-heal ---

// mihomoRedirPlanner verifies that mihomo is actually listening on its transparent
// redirect port (<BindAddress>:<RedirPort>) — the target masterNATPlanner DNATs all
// client TCP to. mihomo binds that listener to the client gateway IP (e.g.
// 10.73.0.1, the wg0 address); if the client interface is recreated under a running
// mihomo (a wg-easy restart flaps the address), mihomo silently loses the bind and
// does NOT re-bind on its own. The container still reports "up" and its config is
// unchanged, so neither composePlanner nor mihomoPlanner notices — but every DNAT'd
// client TCP connection now black-holes (pings and the WG handshake keep working,
// which makes it look healthy). When the listener is down we restart mihomo to
// rebind. Guarded by a local-address check so we never thrash while wg0 itself is
// still down (the wg-easy/compose planners bring it back first).
type mihomoRedirPlanner struct {
	compose string
	// listening reports whether a TCP socket is LISTENing on addr; nil ⇒ a passive
	// socket-table read (socketListening). It must never open a connection to addr.
	listening func(addr string) bool
	// udpListening is the same for the TPROXY listener. Client UDP is handed to a
	// transparent socket, and TPROXY to a socket that is not there DROPS the
	// datagram — so a lost UDP bind breaks every client's DNS, QUIC and games in
	// silence, which is the failure this planner exists to catch on TCP.
	udpListening func(addr string) bool
	// localUp reports whether host is assigned to a local interface; nil ⇒ real check.
	localUp func(host string) bool
	// gov throttles this SELF-HEAL restart; nil ⇒ unthrottled. Shares mihomo's
	// budget with mihomoWGDupPlanner — both bounce the same container.
	gov *restart.Governor
	// netnsAttached reports whether mihomo has moved into its own network
	// namespace, and run executes the command that looks in there (nil ⇒ netns.Exec).
	//
	// Without these this planner asks the HOST's socket table about a listener that
	// is in another namespace, gets "not there", and restarts mihomo — every pass.
	// Each restart re-initialises mihomo's userspace WireGuard devices, and on the
	// live master 2026-09-05 that took three exits out of the balancer within three
	// minutes of the migration. The config, the API address and the health check had
	// all been made namespace-aware; this probe had not, and it is the one that
	// ACTS on its answer.
	netnsAttached func() bool
	run           netns.Runner
	disturbed     func() // see Input.OnMihomoDisturbed
}

func (mihomoRedirPlanner) Component() string { return "mihomo redirect listener" }

func (p mihomoRedirPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo redir: node has no master spec")
	}
	attached := p.netnsAttached != nil && p.netnsAttached()
	// Where mihomo actually is. Both the address it binds and the socket table that
	// can see it move together; asking the right question at the wrong address, or
	// the right address in the wrong namespace, both come back "listener down".
	bindHost := strings.TrimSpace(spec.Master.BindAddress)
	nsPath := ""
	if attached {
		peer := NetnsPeerIP(spec, true)
		if peer == "" {
			return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
				"deferred: the namespace link has no address yet")}, nil
		}
		run := p.run
		if run == nil {
			run = netns.Exec
		}
		path, err := netns.Path(ctx, domain.NetnsHolder, run)
		if err != nil {
			// The holder is not up. Restarting mihomo cannot fix that and would loop.
			return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
				"deferred: mihomo's namespace holder is not up")}, nil
		}
		bindHost, nsPath = peer, path
	}
	if bindHost == "" {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
			"no bind address in spec")}, nil
	}
	redir := mihomo.DefaultRedirPort
	if spec.Master.RedirPort != 0 {
		redir = spec.Master.RedirPort
	}
	addr := net.JoinHostPort(bindHost, strconv.Itoa(redir))

	localUp := p.localUp
	if localUp == nil {
		localUp = localAddrPresent
	}
	if nsPath != "" {
		// The namespace end of the veth is local IN THERE, never out here.
		localUp = func(host string) bool { return nsAddrPresent(ctx, p.runner(), nsPath, host) }
	}
	// If the bind address isn't up on a local interface yet (wg0/wg-easy down or
	// mid-recreate), restarting mihomo can't bind it and would loop — defer to the
	// wg-easy/compose planners and re-check next pass.
	if !localUp(bindHost) {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
			"deferred: bind address "+bindHost+" not up locally yet")}, nil
	}

	listening := p.listening
	if listening == nil {
		listening = socketListening
	}
	udpListening := p.udpListening
	if udpListening == nil {
		udpListening = udpSocketListening
	}
	if nsPath != "" {
		listening = func(a string) bool { return nsSocketListening(ctx, p.runner(), nsPath, a, "-ltnH") }
		udpListening = func(a string) bool { return nsSocketListening(ctx, p.runner(), nsPath, a, "-lunH") }
	}
	tproxyAddr := net.JoinHostPort(bindHost, strconv.Itoa(mihomo.TProxyPortFor(redir)))
	tcpUp, udpUp := listening(addr), udpListening(tproxyAddr)
	if tcpUp && udpUp {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
			"listening on "+addr+" and "+tproxyAddr)}, nil
	}
	down := tproxyAddr
	if !tcpUp {
		down = addr
		if !udpUp {
			down = addr + " and " + tproxyAddr
		}
	}

	compose := p.compose
	restart := reconcile.CustomAction(reconcile.ActionUpdate, "mihomo redirect listener",
		"listener down on "+down+" — restart mihomo to rebind",
		"docker compose -f "+compose+" restart mihomo",
		func(ctx context.Context) error {
			c := exec.CommandContext(ctx, "docker", "compose", "-f", compose, "restart", "mihomo")
			if out, err := c.CombinedOutput(); err != nil {
				return fmt.Errorf("restart mihomo: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		})
	return []reconcile.Action{gateRestart(p.gov, p.disturbed, "mihomo redirect listener", restart)}, nil
}

// --- mihomo leaked-wireguard-device self-heal ---

// mihomoWGDupPlanner detects mihomo's leaked userspace AmneziaWG devices and
// restarts the container to clear them.
//
// mihomo builds every `type: wireguard` proxy as an in-process userspace WireGuard
// device bound to its own UDP socket. A Clash API hot reload (PUT /configs)
// constructs the new proxy set but does NOT always tear the old devices down, so a
// second device for the same exit can survive with its keepalive/rekey timers still
// running (observed live 2026-07-19: two sockets per exit, leaked at two of ~22
// reloads). mihomoPlanner's ProxiesChanged guard forces a restart when the proxies
// section itself changes, but the leak also happens on reloads that guard lets
// through — hence this independent, evidence-based check.
//
// Why the duplicate is destructive rather than merely wasteful: every exit tunnel
// shares ONE master WireGuard identity, so the exit's kernel has a single peer slot
// for that key. Two live devices make the peer's endpoint flap between their two
// source ports, and whichever socket is not currently selected black-holes. A dial
// through the losing device stalls until wireguard-go's REKEY_TIMEOUT expires
// (measured: 7.1s), which surfaces as intermittent connection failures and multi-
// second latency spikes on AWG exits only — REALITY/XHTTP is unaffected because it
// is stateless TCP.
//
// Restarting is a blunt repair (it drops every client connection), so it is gated on
// an OBSERVED duplicate rather than on config change: a transport switch or a drain
// re-renders proxy-GROUP membership and hot-reloads with no restart at all.
type mihomoWGDupPlanner struct {
	compose string
	// peerSockets counts connected UDP sockets whose peer is addr; nil ⇒ a passive
	// socket-table read (udpPeerSocketCount). Injected in tests.
	peerSockets func(addr string) (int, bool)
	// restart bounces the container (nil ⇒ real `docker compose restart mihomo`).
	restart func(ctx context.Context) error
	// gov throttles this SELF-HEAL restart; nil ⇒ unthrottled (tests, and any
	// caller that has not wired one). Owned by the agent, not built here: planners
	// are rebuilt every pass, so a governor constructed here would forget every
	// restart it saw and never throttle anything.
	gov *restart.Governor
	// disturbed is told after the restart has been applied; see Input.OnMihomoDisturbed.
	disturbed func()
}

func (mihomoWGDupPlanner) Component() string { return "mihomo wireguard devices" }

func (p mihomoWGDupPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo wireguard devices: node has no master spec")
	}

	count := p.peerSockets
	if count == nil {
		count = udpPeerSocketCount
	}

	var dupes []string
	for _, t := range spec.Master.ExitTunnels {
		// Only AWG tunnels carry a userspace WireGuard device; a reality-xhttp exit
		// dials plain TCP and cannot leak one.
		if t.Transport.OrDefault() != domain.TransportAWG {
			continue
		}
		n, ok := count(t.Endpoint)
		if !ok {
			// Unreadable socket table: fail safe. A restart drops every client
			// connection, so never trigger one on a guess.
			return []reconcile.Action{reconcile.NoChangeAction("mihomo wireguard devices",
				"socket table unreadable — skipping duplicate-device check")}, nil
		}
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%s (%d devices on %s)", t.Name, n, t.Endpoint))
		}
	}

	if len(dupes) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo wireguard devices",
			"one device per AWG exit")}, nil
	}

	restart := p.restart
	if restart == nil {
		restart = composeRestartMihomo(p.compose)
	}
	return []reconcile.Action{gateRestart(p.gov, p.disturbed, "mihomo wireguard devices",
		reconcile.CustomAction(reconcile.ActionUpdate, "mihomo wireguard devices",
			"leaked AmneziaWG device(s) detected — restart mihomo to clear: "+strings.Join(dupes, ", "),
			"docker compose restart mihomo", restart))}, nil
}

// udpPeerSocketCount counts connected UDP sockets whose PEER address is addr, read
// passively from the kernel socket table. Only mihomo dials an exit's AWG port from
// the master, so the peer address alone identifies its devices without needing to
// resolve the container's PID. Reports ok=false when the table cannot be read, so
// callers can fail safe rather than act on a guess.
func udpPeerSocketCount(addr string) (int, bool) {
	out, err := exec.Command("ss", "-unaH").CombinedOutput()
	if err != nil {
		return 0, false
	}
	n := 0
	for line := range strings.SplitSeq(string(out), "\n") {
		// ss udp columns: State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port
		if f := strings.Fields(line); len(f) >= 5 && f[4] == addr {
			n++
		}
	}
	return n, true
}

// composeRestartMihomo returns an apply closure that bounces the mihomo container.
func composeRestartMihomo(compose string) func(context.Context) error {
	return func(ctx context.Context) error {
		c := exec.CommandContext(ctx, "docker", "compose", "-f", compose, "restart", "mihomo")
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("mihomo restart failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// socketListening reports whether a TCP socket is LISTENing on addr (host:port),
// read passively from the kernel socket table.
//
// It MUST NOT open a connection to addr. The redir port is a transparent proxy: a
// probe connection to it gets proxied by mihomo, and because the probe is not DNAT'd
// its original destination is the redir address itself, which the direct-networks
// rule matches — so mihomo dials DIRECT back into its own redir port, igniting a
// self-amplifying connection storm that pins the master's CPU. A passive socket-table
// read avoids that entirely. Fails safe to true (an unreadable probe must never
// trigger a needless mihomo restart).
func socketListening(addr string) bool { return socketListeningOn(addr, "-ltnH") }

// udpSocketListening is the same question for a UDP bind. It exists because the
// TCP-only form was the only one there was, so the TPROXY listener — which is what
// carries every client datagram now — had nothing watching it at all: a lost bind
// meant client UDP was silently dropped, since TPROXY hands packets to a socket
// that is not there.
func udpSocketListening(addr string) bool { return socketListeningOn(addr, "-lunH") }

func socketListeningOn(addr, ssFlags string) bool {
	out, err := exec.Command("ss", ssFlags).CombinedOutput()
	if err != nil {
		return true // can't tell → assume up; never falsely restart mihomo
	}
	return ssOutputHasPort(string(out), addr)
}

// ssOutputHasPort scans `ss` output for a listener on addr's port. Shared by the
// host and namespace readers so the two cannot answer the same output differently.
func ssOutputHasPort(out, addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		switch f[3] { // ss "Local Address:Port" column
		case addr, "0.0.0.0:" + port, "*:" + port, "[::]:" + port:
			return true
		}
	}
	return false
}

// localAddrPresent reports whether host is currently assigned to a local interface.
func localAddrPresent(host string) bool {
	target, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	target = target.Unmap()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if got, ok := netip.AddrFromSlice(ipnet.IP); ok && got.Unmap() == target {
			return true
		}
	}
	return false
}

// mihomoResolvers picks where mihomo sends its own lookups on THIS node.
//
// Loopback first when the master runs blocky: blocky binds 127.0.0.1 alongside the
// client gateway, and loopback is the one address that does not wait for wg0 to
// come up — mihomo starts before the client interface exists. From there ADR-0024
// takes over: blocky forwards to the exits' blocky over the management overlay,
// which forwards over DoT. Nothing leaves this node's uplink in cleartext, and
// mihomo's own lookups get the same blocklists the clients get.
//
// There is no loop to worry about: blocky's upstreams are mgmt IP literals, so it
// needs no DNS of its own, and mihomo routes the management overlay DIRECT.
//
// If blocky is not running here, the clients' own resolvers (the exits' blocky) are
// the next best answer — and if there is none of that either, RenderConfig falls
// back to encrypted public resolvers. Pointing at blocky costs nothing in
// availability: blocky is already the clients' ONLY resolver, so a blocky that is
// down has taken their DNS with it whatever mihomo does.
func mihomoResolvers(spec domain.NodeSpec, inNetns bool) []string {
	if spec.DNS.Enabled {
		if inNetns {
			// Loopback inside the namespace is the NAMESPACE's loopback, with nothing on
			// it. blocky is on the host and binds the client gateway, which the namespace
			// reaches over its route back to the client pool — so that address, not this
			// node's idea of "local". Pointing at 127.0.0.1 from in there is the specific
			// trap the readiness gate was written to catch, and the one that would have
			// taken every client's DNS down while looking like a working migration.
			if gw := strings.TrimSpace(spec.Master.BindAddress); gw != "" {
				return []string{gw}
			}
		}
		return []string{"127.0.0.1"}
	}
	if spec.Master != nil && len(spec.Master.Compose.ClientDNS) > 0 {
		return append([]string(nil), spec.Master.Compose.ClientDNS...)
	}
	return nil
}

// ClashAPIAddr is where the agent reaches mihomo's control API.
//
// The management-overlay address the controller hands down is on the HOST, and
// once mihomo lives in its own namespace it cannot bind it — so the API moves to
// the veth and the agent has to follow. Everything the agent does to mihomo goes
// through here: tier probing, hot reloads, the mihomo-api health check, the
// dashboard link.
func ClashAPIAddr(spec domain.NodeSpec, attached bool) string {
	if spec.Master == nil {
		return ""
	}
	ec := spec.Master.ExternalController
	peer := NetnsPeerIP(spec, attached)
	if peer == "" || ec == "" {
		return ec
	}
	_, port, err := net.SplitHostPort(ec)
	if err != nil {
		return ec
	}
	return net.JoinHostPort(peer, port)
}

// runner is this planner's command runner, defaulting to the real one.
func (p mihomoRedirPlanner) runner() netns.Runner {
	if p.run != nil {
		return p.run
	}
	return netns.Exec
}

// nsSocketListening asks the socket table INSIDE a namespace whether anything is
// listening on addr's port. Same question and same failure posture as its host
// sibling: a read we cannot take answers "yes", because this planner's action is a
// restart and a false negative is an outage.
func nsSocketListening(ctx context.Context, run netns.Runner, nsPath, addr, ssFlags string) bool {
	out, err := run(ctx, "nsenter", "--net="+nsPath, "ss", ssFlags)
	if err != nil {
		return true
	}
	return ssOutputHasPort(out, addr)
}

// nsAddrPresent reports whether host is assigned to an interface inside the
// namespace. Unreadable answers "no", which DEFERS rather than restarts.
func nsAddrPresent(ctx context.Context, run netns.Runner, nsPath, host string) bool {
	out, err := run(ctx, "nsenter", "--net="+nsPath, "ip", "-br", "addr")
	if err != nil {
		return false
	}
	return strings.Contains(out, host+"/")
}
