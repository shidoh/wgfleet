package health

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/wgiface"
	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
)

// HandshakeMaxAge is the freshness threshold for a WG handshake. Older than this
// and the tunnel is considered stale (latency through the tunnel is
// expected to be high, so we judge liveness by handshake age, not RTT).
const HandshakeMaxAge = 3 * time.Minute

// probeTimeout bounds each external probe.
const probeTimeout = 8 * time.Second

// DefaultExitProbes wires the real exec/http probes for an exit node from its
// spec. These run system tools (awg, curl) and are therefore only meaningful on
// a provisioned Linux node; they are not exercised on the dev box.
// lifelineConf is the exit's lifeline interface config path; the probe derives the
// planner's deferral marker from it (wgiface.DeferredPath), so a lifeline the
// agent has stopped applying cannot report green just because awgl0 is still up
// from the last good config.
func DefaultExitProbes(spec domain.NodeSpec, lifelineConf string) ExitProbes {
	wgIface := "awg0"
	egressIface := spec.Routing.EgressInterface
	if egressIface == "" {
		egressIface = "wgcf"
	}
	var realityPort int
	var bridge *domain.RealityBridgeSpec
	if spec.Reality != nil {
		realityPort = spec.Reality.ListenPort
		bridge = spec.Reality.Bridge
	}
	return ExitProbes{
		HandshakeFresh: handshakeFreshProbe(wgIface),
		WARPEgress:     warpEgressProbe(egressIface),
		DNSResolves:    dnsResolvesProbe(dnsListenAddr(spec.DNS)),
		EgressConfirm:  warpHandshakeProbe(egressIface),
		RealityInbound: realityInboundProbe(realityPort),
		RealityBridge:  bridgeProbe(bridge, runCmd),
		// The reserve client leg (awgl0). `ip link show` is the right question about the
		// world here and not, say, a handshake: the lifeline is warm standby by design,
		// so it can be perfectly healthy with no client on it for weeks. The planner's
		// verdict is the other half — see LifelineUpProbe.
		LifelineUp: LifelineUpProbe(lifelineConf, domain.LifelineInterface),
	}
}

// DefaultMasterProbes wires the real probes for a master node.
//
// controllerAddr overrides where mihomo's Clash API is reached; empty ⇒ the
// address in the spec. Only the agent knows whether mihomo has been moved into
// its own network namespace, and once it has, the management-overlay address in
// the spec is not one mihomo can bind — a probe still dialling it would report a
// healthy master as dead every pass.
func DefaultMasterProbes(spec domain.NodeSpec, controllerAddr string) MasterProbes {
	var controller, secret string
	var clientVLESSPort, portalPort int
	if spec.Master != nil {
		controller = spec.Master.ExternalController
		if controllerAddr != "" {
			controller = controllerAddr
		}
		secret = clashSecret(spec.Master.Custom.Overrides)
		if spec.Master.ClientVLESS != nil {
			clientVLESSPort = spec.Master.ClientVLESS.ListenPort
		}
		if spec.Master.RealityPortal != nil {
			portalPort = spec.Master.RealityPortal.ListenPort
		}
	}
	return MasterProbes{
		// The master's client-facing interface is wg0 — NOT awg0 (that is the
		// exit's awg-quick interface). It is an AmneziaWG device, so `ip link show`
		// sees it even though vanilla `wg show` would not.
		WGServerUp: ifaceUpProbe(domain.ClientWGInterface),
		// Set by the caller, which knows where the agent records its claim.
		ClientWGOwned: nil,
		MihomoAPI:     mihomoAPIProbe(controller, secret),
		// Master-tier blocky binds the mgmt address too, so the on-host probe queries
		// it the same way the exit does (ADR-0024). MasterChecks omits the check unless
		// spec.DNS is enabled, so this is nil-safe for a master without a resolver.
		DNSResolves: dnsResolvesProbe(dnsListenAddr(spec.DNS)),
		// Client-facing VLESS/REALITY inbound (ADR-0031): reuse the socket-table probe
		// (reads `ss -ltnH`, never dials — a dial would only exercise REALITY's
		// camouflage fallback, not the proxy). MasterChecks omits the check unless the
		// master spec carries ClientVLESS, so a zero port here is never checked.
		ClientVLESSUp:   realityInboundProbe(clientVLESSPort),
		RealityPortalUp: realityInboundProbe(portalPort),
	}
}

// clashSecret extracts the mihomo Clash API `secret` from the operator's mihomo
// overrides (the same map deep-merged into the rendered config), so the health
// probe authenticates with exactly the secret the running mihomo enforces. Any
// non-string or missing value yields "" (no auth header).
func clashSecret(overrides map[string]any) string {
	if s, ok := overrides["secret"].(string); ok {
		return s
	}
	return ""
}

// handshakeFreshProbe checks the freshest handshake across peers via
// `awg show <iface> latest-handshakes`.
func handshakeFreshProbe(iface string) Probe {
	return func(ctx context.Context) Result {
		start := now()
		out, err := runCmd(ctx, "awg", "show", iface, "latest-handshakes")
		if err != nil {
			return fail(fmt.Sprintf("awg show failed: %v", err))
		}
		newest := newestHandshake(out)
		if newest == 0 {
			return fail("no handshake yet")
		}
		age := time.Since(time.Unix(newest, 0))
		if age > HandshakeMaxAge {
			return fail(fmt.Sprintf("stale handshake (%s old)", age.Round(time.Second)))
		}
		return ok(fmt.Sprintf("%s ago", age.Round(time.Second)), since(start))
	}
}

// LatestHandshake returns the freshest WireGuard handshake across the peers of
// iface, read via `awg show <iface> latest-handshakes`. It returns the zero time
// when there is no handshake yet or the command fails (interface absent, not a WG
// device) — so the caller treats zero as "none" and the dashboard shows "—". This
// is the timestamp behind the fleet list's HANDSHAKE column (data-plane liveness),
// distinct from handshakeFreshProbe which only emits a pass/fail self-check.
func LatestHandshake(ctx context.Context, iface string) time.Time {
	out, err := runCmd(ctx, "awg", "show", iface, "latest-handshakes")
	if err != nil {
		return time.Time{}
	}
	if newest := newestHandshake(out); newest > 0 {
		return time.Unix(newest, 0).UTC()
	}
	return time.Time{}
}

// warpEgressProbe confirms egress leaves via the WARP interface and that
// Cloudflare reports warp=on.
func warpEgressProbe(iface string) Probe {
	return func(ctx context.Context) Result {
		start := now()
		out, err := runCmd(ctx, "curl", "-s", "--max-time", "5",
			"--interface", iface, "https://www.cloudflare.com/cdn-cgi/trace")
		if err != nil {
			return fail(fmt.Sprintf("curl via %s failed: %v", iface, err))
		}
		if !strings.Contains(out, "warp=on") && !strings.Contains(out, "warp=plus") {
			return fail("egress is not via WARP")
		}
		return ok("warp on", since(start))
	}
}

// warpHandshakeProbe checks whether the WARP path itself is reachable by reading
// the wgcf interface's latest handshake (`wg show <iface> latest-handshakes`).
// wgcf is vanilla WireGuard, so `wg` (not `awg`) reads it. A fresh handshake means
// WG control packets to the Cloudflare endpoint are getting through; a stale or
// absent one is the signature of a path/ISP block. Read-only — it
// never re-registers wgcf, so it cannot churn the node's WARP account.
func warpHandshakeProbe(iface string) Probe {
	return func(ctx context.Context) Result {
		start := now()
		out, err := runCmd(ctx, "wg", "show", iface, "latest-handshakes")
		if err != nil {
			return fail(fmt.Sprintf("wg show %s failed: %v", iface, err))
		}
		newest := newestHandshake(out)
		if newest == 0 {
			return fail("no WARP handshake")
		}
		age := time.Since(time.Unix(newest, 0))
		if age > HandshakeMaxAge {
			return fail(fmt.Sprintf("WARP handshake stale (%s old)", age.Round(time.Second)))
		}
		return ok(fmt.Sprintf("WARP handshake %s ago", age.Round(time.Second)), since(start))
	}
}

// realityInboundProbe checks the xray REALITY inbound is listening on its TCP
// port (ADR-0025). Like the master redir probe it reads the socket
// table rather than dialing — connecting would just exercise REALITY's
// fallback-to-the-camouflage-site, not prove the proxy itself is ready.
func realityInboundProbe(port int) Probe {
	return func(ctx context.Context) Result {
		start := now()
		if port <= 0 {
			return fail("no reality port")
		}
		out, err := runCmd(ctx, "ss", "-ltnH")
		if err != nil {
			return fail(fmt.Sprintf("ss failed: %v", err))
		}
		if strings.Contains(out, fmt.Sprintf(":%d ", port)) {
			return ok(fmt.Sprintf("listening on :%d", port), since(start))
		}
		return fail(fmt.Sprintf("no listener on :%d", port))
	}
}

// dnsListenAddr reconstructs the resolver's mgmt-address listen endpoint from
// the spec (the renderer binds DNS on loopback + this address).
func dnsListenAddr(spec domain.DNSFilterSpec) string {
	if spec.MgmtAddr == "" {
		return ""
	}
	port := spec.Ports.DNS
	if port == 0 {
		port = dnsfilter.DefaultDNSPort
	}
	return fmt.Sprintf("%s:%d", spec.MgmtAddr, port)
}

// dnsResolvesProbe checks the on-node DNS filter answers a query.
func dnsResolvesProbe(listenAddr string) Probe {
	host := hostOf(listenAddr)
	return func(ctx context.Context) Result {
		if host == "" {
			return fail("no DNS listen address")
		}
		start := now()
		if _, err := runCmd(ctx, "dig", "+short", "+timeout=3", "@"+host, "cloudflare.com"); err != nil {
			return fail(fmt.Sprintf("dig @%s failed: %v", host, err))
		}
		return ok("resolves", since(start))
	}
}

// ifaceUpProbe checks an interface exists and is up via `ip link show`.
func ifaceUpProbe(iface string) Probe {
	return func(ctx context.Context) Result {
		start := now()
		out, err := runCmd(ctx, "ip", "link", "show", iface)
		if err != nil {
			return fail(fmt.Sprintf("%s not found: %v", iface, err))
		}
		if !strings.Contains(out, "state UP") && !strings.Contains(out, "state UNKNOWN") {
			return fail(iface + " is down")
		}
		return ok("up", since(start))
	}
}

// probeHTTPClient bounds health-check HTTP probes at the transport level too, not
// just via the request context, so a stuck dial/TLS handshake can never outlive
// the probe budget and stall the synchronous reconcile loop.
var probeHTTPClient = &http.Client{Timeout: probeTimeout}

// mihomoAPIProbe checks the mihomo Clash API responds at /version. When the
// operator set an API `secret` (via mihomo.overrides), the RESTful API requires
// `Authorization: Bearer <secret>` — without it mihomo answers 401 and the master
// would flap to Degraded, so the probe authenticates with the same secret.
func mihomoAPIProbe(controller, secret string) Probe {
	return func(ctx context.Context) Result {
		if controller == "" {
			return fail("no external controller configured")
		}
		start := now()
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+controller+"/version", nil)
		if err != nil {
			return fail(err.Error())
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := probeHTTPClient.Do(req)
		if err != nil {
			return fail(fmt.Sprintf("mihomo api unreachable: %v", err))
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fail(fmt.Sprintf("mihomo api status %d", resp.StatusCode))
		}
		return ok("responding", since(start))
	}
}

// --- helpers ---

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// newestHandshake parses `awg show latest-handshakes` output (one
// "<pubkey>\t<unix-seconds>" per line) and returns the largest timestamp.
func newestHandshake(out string) int64 {
	var newest int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err != nil {
			continue
		}
		if ts > newest {
			newest = ts
		}
	}
	return newest
}

func hostOf(addr string) string {
	if addr == "" {
		return ""
	}
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

func now() time.Time                  { return time.Now() }
func since(t time.Time) time.Duration { return time.Since(t) }

// ClientPeers reads the live peers on the master's client-facing interface with
// `awg show <iface> dump`, so the controller's client page shows what the kernel
// actually has rather than what the desired state says it should.
//
// Keyed by public key on purpose: the interface knows nothing about the labels
// the operator gave these credentials, and matching happens in the controller,
// which does. Collection is best-effort — a missing tool, a down interface or an
// unparseable line yields no peers rather than failing the status report.
func ClientPeers(ctx context.Context, iface string) []domain.ClientPeerStatus {
	out, err := runCmd(ctx, "awg", "show", iface, "dump")
	if err != nil {
		return nil
	}
	return parseClientPeers(out)
}

// parseClientPeers parses the canonical dump TSV. The first line describes the
// interface itself and is skipped; the rest are peers:
//
//	public-key  preshared-key  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
func parseClientPeers(out string) []domain.ClientPeerStatus {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		return nil
	}
	var peers []domain.ClientPeerStatus
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		pub := strings.TrimSpace(fields[0])
		if pub == "" || pub == "(none)" {
			continue
		}
		// Field 2 is the peer's endpoint — the client's real IP. Deliberately not
		// read: see domain.ClientPeerStatus.
		p := domain.ClientPeerStatus{PublicKey: pub}
		if hs, err := strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64); err == nil && hs > 0 {
			p.LastHandshake = time.Unix(hs, 0).UTC()
		}
		p.ReceivedBytes, _ = strconv.ParseInt(strings.TrimSpace(fields[5]), 10, 64)
		p.SentBytes, _ = strconv.ParseInt(strings.TrimSpace(fields[6]), 10, 64)
		peers = append(peers, p)
	}
	return peers
}

// ClientWGOwnedProbe reports whether the agent is actually carrying the client
// interface: the interface exists AND the agent recorded raising it.
//
// The claim file is what distinguishes us from an interface someone else raised
// under the same name, possibly with the same key. It is
// also absent through every deferral the interface planner can report, which is
// the point: those are exactly the states that must not read as healthy.
func ClientWGOwnedProbe(claimPath, iface string) Probe {
	return func(ctx context.Context) Result {
		start := now()
		// The planner's own verdict comes FIRST. The two probes below read the world,
		// and the world cannot show a decision: once the agent has raised wg0 the claim
		// and the link are both true forever, so every deferral — no key yet, spec
		// rejected, 3.x refused — reported green. The worst of those is a malformed
		// credential freezing the interface, after which every revocation silently
		// stops taking effect while the UI reports success.
		if reason, err := os.ReadFile(deferredPathFor(claimPath)); err == nil {
			if r := strings.TrimSpace(string(reason)); r != "" {
				return fail("the agent is not applying the client interface spec: " + r)
			}
		}
		if _, err := os.Stat(claimPath); err != nil {
			return fail("the agent has not raised the client interface (no claim at " + claimPath + ")")
		}
		if _, err := runCmd(ctx, "ip", "link", "show", iface); err != nil {
			return fail(iface + " is claimed by this agent but not up")
		}
		return ok("client interface carried by the agent", since(start))
	}
}

// deferredPathFor derives the deferral marker's path from the claim's. Both hang
// off the interface config, so one argument determines the other and the probe's
// signature does not have to grow.
func deferredPathFor(claimPath string) string {
	return wgiface.DeferredPath(strings.TrimSuffix(claimPath, ".claim"))
}

// LifelineUpProbe reports on the exit's reserve client interface: first the
// planner's own verdict, then the world.
//
// The order is the whole point. `ip link show awgl0` answers "is an interface up",
// and awgl0 STAYS up from its last good config through every deferral the planner
// can report — no key yet, a rejected spec, AmneziaWG 3.x refused. So a bare link
// probe reports green on an exit whose reserve peers stopped being updated days
// ago, including one still serving a credential the operator revoked. A check
// that reads the world cannot see a decision; it has to read the decision.
func LifelineUpProbe(confPath, iface string) Probe {
	return func(ctx context.Context) Result {
		if confPath != "" {
			if reason, err := os.ReadFile(wgiface.DeferredPath(confPath)); err == nil {
				if r := strings.TrimSpace(string(reason)); r != "" {
					return fail("the agent is not applying the lifeline spec: " + r)
				}
			}
		}
		return ifaceUpProbe(iface)(ctx)
	}
}

// ClientUDPReturnProbe watches ONE invariant: every UDP port this namespace holds
// either leaves the transparent return path intact, or is a port we have already
// decided about.
//
// The two halves fail differently and only one of them is an outage. A port that
// is blocked and ACCEPTED is a known, declared state — the ruleset refuses client
// traffic to it, or the operator has taken the loss knowingly. A port that is
// blocked and NOT accepted is a silent black hole: the client sends and sends and
// nothing ever comes back, which ran for eight days on the live master before
// anyone asked (97787 dropped replies, all on the client WG port).
//
// bindable and accepted are injected so the decision logic is testable off Linux;
// production passes UDPReturnBindable and the rendered refusal set.
func ClientUDPReturnProbe(ports []int, bindable func(int) (bool, error), accepted func(int) bool) Probe {
	return func(context.Context) Result {
		start := now()
		var blind, holes []string
		for _, p := range ports {
			if p <= 0 {
				continue
			}
			ok, err := bindable(p)
			switch {
			case err != nil:
				blind = append(blind, fmt.Sprintf("%d (%v)", p, err))
			case !ok && (accepted == nil || !accepted(p)):
				holes = append(holes, strconv.Itoa(p))
			}
		}
		if len(holes) > 0 {
			return fail("client UDP black-holes on port(s) " + strings.Join(holes, ", ") +
				": no transparent return socket is possible there and nothing refuses them")
		}
		if len(blind) > 0 {
			return fail("could not check the client UDP return path on port(s) " + strings.Join(blind, ", "))
		}
		return ok("every UDP port this namespace holds either returns or is refused", since(start))
	}
}
