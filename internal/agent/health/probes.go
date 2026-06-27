package health

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// HandshakeMaxAge is the freshness threshold for a WG handshake. Older than this
// and the tunnel is considered stale (an earlier finding: latency through the tunnel is
// expected to be high, so we judge liveness by handshake age, not RTT).
const HandshakeMaxAge = 3 * time.Minute

// probeTimeout bounds each external probe.
const probeTimeout = 8 * time.Second

// DefaultExitProbes wires the real exec/http probes for an exit node from its
// spec. These run system tools (awg, curl) and are therefore only meaningful on
// a provisioned Linux node; they are not exercised on the dev box.
func DefaultExitProbes(spec domain.NodeSpec) ExitProbes {
	wgIface := "awg0"
	egressIface := spec.Routing.EgressInterface
	if egressIface == "" {
		egressIface = "wgcf"
	}
	var realityPort int
	if spec.Reality != nil {
		realityPort = spec.Reality.ListenPort
	}
	return ExitProbes{
		HandshakeFresh: handshakeFreshProbe(wgIface),
		WARPEgress:     warpEgressProbe(egressIface),
		DNSResolves:    dnsResolvesProbe(dnsListenAddr(spec.DNS)),
		EgressConfirm:  warpHandshakeProbe(egressIface),
		RealityInbound: realityInboundProbe(realityPort),
	}
}

// DefaultMasterProbes wires the real probes for a master node.
func DefaultMasterProbes(spec domain.NodeSpec) MasterProbes {
	var controller, secret string
	if spec.Master != nil {
		controller = spec.Master.ExternalController
		secret = clashSecret(spec.Master.Custom.Overrides)
	}
	return MasterProbes{
		// The master's client-facing interface is managed by wg-easy, which names
		// it wg0 (wgeasy.DefaultInterface) — NOT awg0 (that is the exit's awg-quick
		// interface). It is an AmneziaWG device, so `ip link show` sees it even
		// though vanilla `wg show` would not.
		WGServerUp: ifaceUpProbe(wgeasy.DefaultInterface),
		MihomoAPI:  mihomoAPIProbe(controller, secret),
		// Master-tier blocky binds the mgmt address too, so the on-host probe queries
		// it the same way the exit does (ADR-0024). MasterChecks omits the check unless
		// spec.DNS is enabled, so this is nil-safe for a master without a resolver.
		DNSResolves: dnsResolvesProbe(dnsListenAddr(spec.DNS)),
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
