// Command wgfleet-agent is the per-node reconcile daemon. Its role (master or
// exit) comes from config; it pulls its NodeSpec from the controller over mTLS
// and drives the node toward it idempotently.
//
// MVP scaffold: this wires config loading, the mTLS client, and a reconcile
// pass that registers, pulls the desired spec and reports status. --plan
// (dry-run) renders/diffs without applying. The role-specific reconcilers
// (WG/AWG, wgcf, routing, nftables, DNS) are layered on in later milestones.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/agent/certrenew"
	"github.com/shidoh/wgfleet/internal/agent/client"
	egressfo "github.com/shidoh/wgfleet/internal/agent/egress"
	"github.com/shidoh/wgfleet/internal/agent/exit"
	"github.com/shidoh/wgfleet/internal/agent/health"
	"github.com/shidoh/wgfleet/internal/agent/host"
	"github.com/shidoh/wgfleet/internal/agent/master"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/restart"
	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/hardening"
	"github.com/shidoh/wgfleet/internal/metrics"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/version"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/wgeasy"
	"github.com/shidoh/wgfleet/internal/xray"
)

// metricsMux builds the agent's /metrics HTTP handler.
func metricsMux(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler(reg))
	return mux
}

// metricsBindAttempts / metricsBindRetryDelay bound how long the metrics server
// waits for its mgmt/overlay address to appear before giving up (≈60s total).
const (
	metricsBindAttempts   = 12
	metricsBindRetryDelay = 5 * time.Second
)

// listenWithRetry opens a TCP listener on addr, retrying on failure (the overlay
// address may not be assigned yet at startup). It returns the listener once bound,
// or the last error after attempts are exhausted.
func listenWithRetry(addr string, attempts int, delay time.Duration, log *slog.Logger) (net.Listener, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		lastErr = err
		if attempt < attempts {
			log.Warn("metrics bind failed, retrying", "addr", addr, "attempt", attempt, "err", err)
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}

// resolveMetricsBind decides the agent /metrics bind address. An explicit
// --metrics value wins; "off"/"none"/"-" disables it; empty defaults to
// mgmtAddr:DefaultAgentMetricsPort so metrics come up without a flag whenever the
// node knows its mgmt/overlay address. Returns "" when metrics must not start.
func resolveMetricsBind(flagVal, mgmtAddr string) string {
	switch strings.ToLower(strings.TrimSpace(flagVal)) {
	case "off", "none", "-":
		return ""
	case "":
		if mgmtAddr == "" {
			return ""
		}
		return net.JoinHostPort(mgmtAddr, strconv.Itoa(config.DefaultAgentMetricsPort))
	default:
		return strings.TrimSpace(flagVal)
	}
}

// wgIfacesForRole returns the WireGuard/AmneziaWG interfaces the WG metrics
// collector probes for a node's role. An exit terminates the master tunnel on
// awg0 and egresses via the wgcf WARP interface; a master's client WG runs inside
// the wg-easy container (wg0 there, not on the host), so wg0 is listed but only
// reported if it happens to be host-visible — the collector fails soft otherwise.
func wgIfacesForRole(role domain.Role) []string {
	if role == domain.RoleExit {
		return []string{"awg0", "wgcf"}
	}
	return []string{"wg0"}
}

// scheduledProbes lists the timer-driven probes whose success/attempt markers the
// probe collector reports on. Both are exit planners (the WARP path-MTU probe and
// the scanner-ASN feed refresh); a master runs neither.
func scheduledProbes(role domain.Role, paths exit.Paths) []metrics.Probe {
	if role != domain.RoleExit {
		return nil
	}
	return []metrics.Probe{
		{
			Name:        "warp_path_mtu",
			SuccessPath: paths.WARPMTUCache,
			AttemptPath: exit.AttemptMarkerPath(paths.WARPMTUCache),
		},
		{
			Name:        "as_blacklist_feed",
			SuccessPath: paths.ASBlacklist,
			AttemptPath: exit.AttemptMarkerPath(paths.ASBlacklist),
		},
	}
}

func main() {
	if err := run(); err != nil {
		slog.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath    = flag.String("config", "/etc/wgfleet/agent.yaml", "path to agent config")
		logFormat     = flag.String("log-format", "text", "log format: text | json")
		plan          = flag.Bool("plan", false, "dry-run: show what reconcile would change, apply nothing")
		once          = flag.Bool("once", false, "run a single reconcile pass and exit")
		publicIP      = flag.String("public-ip", "", "this node's public IP to advertise (peer endpoint)")
		mgmtAddr      = flag.String("mgmt-addr", "", "this node's mgmt/ZT address (admin + metrics + DNS bind)")
		stateDir      = flag.String("state-dir", "", "root managed files under this dir instead of /etc (non-root/dev runs)")
		metricsBind   = flag.String("metrics", "", "override the agent /metrics bind (mgmt/ZT only); default <mgmt-addr>:9301, 'off' disables")
		showVersion   = flag.Bool("version", false, "print build version and exit")
		supportBundle = flag.Bool("support-bundle", false, "write a read-only diagnostic archive (no secrets, not encrypted) and exit")
		supportNote   = flag.String("note", "", "with --support-bundle: describe what went wrong, embedded in the archive")
		dnsProbe      = flag.String(strings.TrimPrefix(master.DNSProbeFlag, "-"), "",
			"take one UDP DNS query against <host:port> and exit 0/1; used by the client-path prober inside a namespace")
	)
	flag.Parse()

	// The UDP probe, and it exits before anything else runs. This process was
	// started by `ip netns exec` from the agent's own reconcile loop purely to send
	// one datagram from inside another namespace: it must not load a config, dial a
	// controller or write a file. It exists because no tool on a stock node sends a
	// DNS query to a NAMED server without reading resolv.conf first, and reading
	// resolv.conf is exactly what made the previous probe miss the outage.
	if *dnsProbe != "" {
		if err := health.QueryDNSOverUDP(context.Background(), *dnsProbe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return nil
	}

	if *showVersion {
		fmt.Println("wgfleet-agent", version.String())
		fmt.Printf("wire-contract version %d\n", api.WireContractVersion)
		return nil
	}

	setupLogging(*logFormat)

	cfg, err := config.Load(*configPath, &config.AgentConfig{})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	role, err := domain.ParseRole(cfg.Agent.Role)
	if err != nil {
		return err
	}

	paths := exit.DefaultPaths()
	if *stateDir != "" {
		paths = exit.PathsUnder(*stateDir)
	}

	// --support-bundle exits here, before anything that touches the controller:
	// it must work on a node whose controller connectivity is exactly what is
	// broken (see runSupportBundle's doc comment).
	if *supportBundle {
		return runSupportBundle(role, paths, *stateDir, cfg.Agent.NodeID, *supportNote)
	}

	tlsCfg, err := buildClientTLS(cfg)
	if err != nil {
		return fmt.Errorf("build mTLS: %w", err)
	}
	conn, err := client.Dial(cfg.Agent.Controller, tlsCfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Resolve the mgmt/overlay address: the --mgmt-addr flag overrides agent.yaml's
	// mgmt_addr. It is the bind for the metrics endpoint and other off-public surfaces.
	mgmt := strings.TrimSpace(*mgmtAddr)
	if mgmt == "" {
		mgmt = strings.TrimSpace(cfg.Agent.MgmtAddr)
	}

	a := &agent{
		cfg:      cfg,
		role:     role,
		publicIP: *publicIP,
		mgmtAddr: mgmt,
		stateDir: *stateDir,
		paths:    paths,
		client:   conn,
		log:      slog.With("node", cfg.Agent.NodeID, "role", role),
	}
	// Built ONCE for the process, not per reconcile pass — see agent.tier and
	// agent.restarts. Role-agnostic: self-heal restarts exist on exits too.
	a.restarts = restart.New(a.log)
	if role == domain.RoleMaster {
		a.tier = master.NewTierSelector(a.log)
		// One per process, like the tier selector and for the same reason: it has to
		// remember how many times it has already tried and failed.
		a.netnsMove = master.NewNetnsMove(a.masterPaths().NetnsMoveState)
	}

	// Agent /metrics (own reconcile/health counters). Defaults to mgmt:9301 so the
	// endpoint comes up without an explicit flag; --metrics overrides, 'off' disables.
	// Bind mgmt/ZT only: this endpoint is unauthenticated and leaks fleet topology
	// (node id, role, egress IP, health) if exposed publicly, so refuse a public bind.
	if bind := resolveMetricsBind(*metricsBind, mgmt); bind != "" {
		if err := config.RequireMgmtBind("--metrics", bind); err != nil {
			return err
		}
		reg := metrics.NewRegistry()
		a.metrics = metrics.NewAgentMetrics(reg, cfg.Agent.NodeID, role, time.Now())
		metrics.RegisterBuildInfo(reg, "agent", version.Version, version.Commit)
		// Scrape-time collectors (no extra goroutine): per-peer WG/AWG telemetry and
		// firewall stats. Both fail soft — a missing wg/nft, a down interface, or a
		// non-Linux dev box simply yields no series. The WG interface set is
		// role-dependent (exits run the awg0 client tunnel + the wgcf WARP leg; a
		// master's client wg lives inside the wg-easy container, so wg0 is probed
		// best-effort). Firewall metrics are only populated on exits (table inet
		// wgfleet), but the collector is safe to register everywhere.
		metrics.NewWGCollector(reg, cfg.Agent.NodeID, string(role), wgIfacesForRole(role), nil)
		// When this node's control-plane certificate expires. The agent renews it in
		// place (renewCertificateIfDue, below), so the series is read at scrape time
		// rather than at boot — a frozen one would report the pre-renewal date
		// forever and alert on it. A failure to read the file at startup is logged
		// and not fatal, because a node that cannot publish the date is still a node
		// that should keep reconciling.
		if err := metrics.NewCertExpiryCollector(reg, cfg.Agent.NodeID, string(role), cfg.Agent.Identity.Cert); err != nil {
			slog.Warn("certificate expiry gauge unavailable", "node", cfg.Agent.NodeID, "err", err)
		}
		metrics.NewFWCollector(reg, cfg.Agent.NodeID, string(role), nil)
		// Scheduled probes degrade silently by design (a failure keeps the last-good
		// value and only WARNs), so without this a probe that fails 100% of the time
		// looks exactly like one that works — which is how the WARP path-MTU probe
		// stayed dead fleet-wide. Exit-only: both probes are exit
		// planners, and on a master the markers never exist, so the collector would
		// emit nothing anyway.
		metrics.NewProbeCollector(reg, cfg.Agent.NodeID, string(role), scheduledProbes(role, a.paths))
		metricsSrv := &http.Server{Addr: bind, Handler: metricsMux(reg)}
		go func() {
			// The mgmt/overlay (ZeroTier) address may not be on an interface yet at agent
			// start — the ZT daemon assigns it slightly later — so the first bind can fail
			// with "cannot assign requested address". Retry instead of leaving /metrics
			// silently down until the next agent restart.
			ln, err := listenWithRetry(bind, metricsBindAttempts, metricsBindRetryDelay, a.log)
			if err != nil {
				a.log.Error("metrics server: gave up binding", "addr", bind, "err", err)
				return
			}
			if err := metricsSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				a.log.Error("metrics server error", "err", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
	}

	a.log.Info("agent starting",
		"version", version.Version, "commit", version.Commit, "wire", api.WireContractVersion,
		"controller", cfg.Agent.Controller, "interval", cfg.Interval(), "plan", *plan)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		return a.reconcile(ctx, *plan)
	}

	// Daemon path only. Installed above the --once return it would also change how
	// a one-shot run (--support-bundle over a dropping SSH session) behaves.
	defer ignoreSIGHUP(a.log)()

	ticker := time.NewTicker(cfg.Interval())
	defer ticker.Stop()

	if err := a.reconcile(ctx, *plan); err != nil {
		a.log.Error("initial reconcile failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			a.log.Info("agent shutting down")
			return nil
		case <-ticker.C:
			if err := a.reconcile(ctx, *plan); err != nil {
				a.log.Error("reconcile failed", "err", err)
			}
		}
	}
}

type agent struct {
	cfg      *config.AgentConfig
	role     domain.Role
	publicIP string
	mgmtAddr string
	stateDir string // non-empty roots managed files outside /etc (non-root/dev)
	paths    exit.Paths
	metrics  *metrics.AgentMetrics // nil when /metrics is disabled
	// mihomoLogCursor is how far into mihomo's log the error counter has read.
	// Kept here rather than in a planner: planners are rebuilt every pass and would
	// re-count the same window forever.
	mihomoLogCursor time.Time
	// synthKP is the master's own client keypair, minted once and kept on the node.
	synthKP wg.KeyPair
	// netnsMove decides, pass by pass, whether client interception lives in
	// mihomo's namespace. On the agent rather than in a planner because planners
	// are rebuilt every pass and would forget every attempt they ever made — the
	// same mistake that once silently disabled tier failover.
	netnsMove *netnsMoveState
	client    *client.Client
	log       *slog.Logger
	// tier carries the master's exit-tier failover decision for the PROCESS
	// lifetime. It must not live in the planner list: planners() is called on every
	// reconcile pass (the engine is rebuilt each time), so a per-pass selector has
	// its hysteresis reset every 30s — streaks never reach their thresholds, so
	// failover can never fire and the standby is never warmed. Nil for exits.
	tier *master.TierSelector

	// renewBackoff / renewNotBefore hold off a failing certificate renewal. Process
	// lifetime, like tier and restarts above and for the same reason: the reconcile
	// loop is the only caller and it runs every 30 seconds for months.
	renewBackoff   time.Duration
	renewNotBefore time.Time

	// restarts throttles SELF-HEAL restarts for the PROCESS lifetime, for exactly
	// the same reason as tier above: planners are rebuilt every pass, so a governor
	// created per pass would forget every restart it ever recorded and the throttle
	// would never engage. Non-nil on every role — the exit planners take it too.
	restarts *restart.Governor

	// clientKeyAudited records that the client-identity audit has run AND REACHED AN
	// ANSWER. Per PASS would reopen wg-easy's database every reconcile forever; per
	// RESTART is the right cadence for a fact that can only change when someone
	// intervenes, and it puts a fresh line in the journal after every restart.
	//
	// It is not a sync.Once, because a Once latches on the attempt rather than on
	// the result. The audit's most important half reads the LIVE interface, and on
	// the first pass after a host reboot that interface does not exist yet — the
	// client-interface planner raises it later in the very same pass. So the read
	// failed, the check was skipped in silence, and the process's one opportunity
	// was spent: the loudest guard in the whole handover ("the controller is handing
	// out configs pinned to a key nobody answers with") could never fire on a
	// rebooted node, which is precisely the node most likely to need it.
	clientKeyAudited atomic.Bool

	// lastSpecPrint fingerprints the spec from the previous applied pass. A pass
	// that changes resources while this is unchanged is config drift (the world
	// diverged), not a rollout (a new spec). Empty until the first applied pass.
	lastSpecPrint string

	// egress classifies WARP egress reachability across passes (detect-only
	// censorship-block signal); it tracks the consecutive-failure streak so a
	// transient blip reads as degraded and only a confirmed path block as blocked.
	egress health.EgressClassifier

	// egressSel selects the active egress within the node's chain, switching to a
	// fallback on a confirmed block and back on recovery (ADR-0017).
	egressSel egressfo.Selector

	// throughput watches the active egress's real throughput across passes (ADR-0021),
	// smoothing a sustained collapse — which mihomo's latency-only url-test cannot
	// see — into a stable signal that drives failover and controller-side LB suspend.
	throughput health.ThroughputWatchdog
	// Previous egress interface byte counter + timestamp, for the PASSIVE throughput
	// measurement that lets a busy link prove itself without an active probe.
	egressBytesPrev uint64
	egressBytesAt   time.Time
	egressIfacePrev string
}

// Reconcile-pass time budgets. A first-run apply legitimately takes minutes — it
// pulls container images and registers WARP — so the apply budget is generous.
// Status reporting gets its OWN short budget on a fresh context, so a slow or
// failed pass still reports the node's state (otherwise it sticks in Provisioning).
const (
	applyReconcileTimeout = 15 * time.Minute
	planReconcileTimeout  = 2 * time.Minute
	statusReportTimeout   = 20 * time.Second
)

// reconcile runs one pass: register, publish the WG public key, pull the desired
// spec, and converge the node toward it. In plan mode it renders the full plan
// and prints it WITHOUT touching the node or reporting Ready (docs/DESIGN.md #4).
func (a *agent) reconcile(base context.Context, plan bool) error {
	mode := reconcile.ModeApply
	budget := applyReconcileTimeout
	if plan {
		mode = reconcile.ModePlan
		budget = planReconcileTimeout
	}
	ctx, cancel := context.WithTimeout(base, budget)
	defer cancel()

	// Renew the control-plane certificate if it is past its renewal point. Done here
	// because the reconcile loop is already the thing with a live controller
	// connection, and a node that cannot reconcile could not renew anyway. Apply mode
	// only: a dry run must not rotate the node's identity.
	if !plan {
		a.renewCertificateIfDue(ctx)
	}

	// Obtain the node's WG key. In apply mode it is generated and persisted on
	// first run; in plan mode a missing key is generated ephemerally just for
	// rendering, so dry-run never writes anything.
	kp, ephemeral, err := a.ensureWGKey(!plan)
	if err != nil {
		return fmt.Errorf("ensure wg key: %w", err)
	}
	if ephemeral && plan {
		a.log.Info("WG key absent; using an ephemeral key for the plan (apply would generate one)")
	}

	// Master only: resolve the wg-easy admin password that seeds unattended setup
	// (so a fresh master never stops at the interactive wizard). Like the WG key it
	// is persisted on first apply and generated ephemerally in plan mode; it never
	// leaves the node (ADR-0008).
	var adminUser, adminPass string
	if a.role == domain.RoleMaster {
		u, p, adminEph, aerr := a.ensureWGEasyAdmin(!plan)
		if aerr != nil {
			return fmt.Errorf("ensure wg-easy admin password: %w", aerr)
		}
		if adminEph && plan {
			a.log.Info("wg-easy admin password absent; using an ephemeral one for the plan (apply would generate + persist it)")
		}
		adminUser, adminPass = u, p
	}

	// fromCache marks a pass running on the last-good spec because the controller
	// could not be reached. Such a pass converges the node but reports nothing (there
	// is nobody to report to) and does not re-record the cache.
	var (
		spec      domain.NodeSpec
		fromCache bool
	)

	state, err := a.client.Register(ctx, a.role, a.publicIP, "", a.mgmtAddr)
	if err != nil {
		// Every subsystem on this node — interfaces, routing, nftables, mihomo,
		// blocky — is converged by the pass this error used to abort, so a node that
		// rebooted while the controller was unreachable came up with nothing and
		// stayed that way. The reconcilers already self-heal a lost kernel state
		// (reconcile.NFTApply re-applies when the table is gone); they simply never
		// ran. Give them the last spec that worked instead of giving up.
		//
		// Only when NOTHING ANSWERED. A refusal is the controller talking, and its
		// answer wins over anything on disk — see controllerUnreachable.
		if plan || !controllerUnreachable(err) {
			return fmt.Errorf("register: %w", err)
		}
		cached, age, cerr := loadSpec(specCacheFile)
		if cerr != nil {
			return fmt.Errorf("register: %w (and no last-good spec to fall back on: %v)", err, cerr)
		}
		a.log.Warn("controller unreachable; converging on the last-good spec instead of standing still",
			"err", err, "spec_age", age.Round(time.Second), "path", specCacheFile)
		fromCache, spec = true, cached
		state = domain.StateReconciling
	}
	if !plan && !fromCache {
		if err := a.client.PublishPublicKey(ctx, kp.PublicKey); err != nil {
			return fmt.Errorf("publish public key: %w", err)
		}
	}

	// Exits also carry a REALITY x25519 key for the optional reality transport
	// (ADR-0025). Generate+publish it unconditionally so the controller can render
	// the reality proxy the moment the operator flips the active transport — no
	// chicken-and-egg. The key is exit-local (persisted in apply, ephemeral in plan);
	// only the pubkey crosses the wire. Unused on AWG-only exits.
	var realityPriv, clientWGPriv string
	if a.role == domain.RoleExit {
		rPriv, rPub, rEph, rerr := a.ensureRealityKey(!plan)
		if rerr != nil {
			return fmt.Errorf("ensure reality key: %w", rerr)
		}
		if rEph && plan {
			a.log.Info("REALITY key absent; using an ephemeral key for the plan (apply would generate one)")
		}
		realityPriv = rPriv
		if !plan && !fromCache {
			if err := a.client.PublishRealityKey(ctx, rPub); err != nil {
				return fmt.Errorf("publish reality key: %w", err)
			}
		}
	}
	// Masters carry their own REALITY x25519 key for the client-facing VLESS inbound.
	// Generate+publish it unconditionally (like the exit's above) so the controller
	// can build clients' vless:// links the moment the operator enables client_vless —
	// no chicken-and-egg. Master-local; only the pubkey crosses the wire.
	if a.role == domain.RoleMaster {
		cvPriv, cvPub, cvEph, cerr := a.ensureClientVlessKey(!plan)
		if cerr != nil {
			return fmt.Errorf("ensure client vless key: %w", cerr)
		}
		if cvEph && plan {
			a.log.Info("client VLESS REALITY key absent; using an ephemeral key for the plan (apply would generate one)")
		}
		realityPriv = cvPriv
		if !plan && !fromCache {
			if err := a.client.PublishClientVlessKey(ctx, cvPub); err != nil {
				return fmt.Errorf("publish client vless key: %w", err)
			}
		}

		// The client-facing WireGuard identity, resolved the same way and for the
		// same reason: publish it unconditionally so the controller can render client
		// configs the moment the operator hands the leg over. On a master that still
		// runs wg-easy this ADOPTS wg-easy's own key, so the public key we publish is
		// the one clients already pin.
		cwKP, cwEph, cwErr := a.ensureClientWGKey(!plan)
		if cwErr != nil {
			return fmt.Errorf("ensure client wg key: %w", cwErr)
		}
		if cwEph && plan {
			a.log.Info("client WG key absent; using an ephemeral key for the plan (apply would resolve one)")
		}
		clientWGPriv = cwKP.PrivateKey
		// An empty key means "deferred, wg-easy's database would not answer": publish
		// nothing rather than a key we are not sure we should be using.
		if !plan && !fromCache && cwKP.PublicKey != "" {
			if err := a.client.PublishClientWGKey(ctx, cwKP.PublicKey); err != nil {
				return fmt.Errorf("publish client wg key: %w", err)
			}
		}
	}

	if !fromCache {
		spec, err = a.pullSpecOrCache(ctx, base, plan, &fromCache)
		if err != nil {
			return err
		}
	}
	if err := spec.Validate(); err != nil {
		// An invalid spec must never be applied: a zero WG port, bad egress, or an
		// AWG-constraint violation would rewrite awg0.conf/nftables/routing into a
		// broken state on a live node. In plan mode show the (invalid) plan so the
		// operator can diagnose it; in apply mode refuse, report Error so the
		// controller/UI see the reason, and keep the last-good config in place.
		if plan {
			a.log.Warn("pulled spec not yet valid (plan mode: showing anyway)", "err", err)
		} else {
			a.log.Error("refusing to apply invalid spec; keeping last-good config", "err", err)
			repCtx, repCancel := context.WithTimeout(base, statusReportTimeout)
			defer repCancel()
			check := domain.HealthCheck{Name: domain.CheckSpecValid, OK: false, Detail: err.Error()}
			if rerr := a.reportStatus(repCtx, domain.StateError, []domain.HealthCheck{check}, err, "", nil); rerr != nil {
				a.log.Error("failed to report invalid-spec state", "err", rerr)
			}
			return fmt.Errorf("invalid spec, not applied: %w", err)
		}
	}
	if spec.Decommission {
		return a.teardown(ctx, plan)
	}

	// Per-tunnel master identities (ADR-0030). This runs AFTER PullSpec, not
	// alongside the shared-key publish above, because the master learns which exits
	// exist only from its own spec — there is no exit list before the first pull.
	// The consequence is deliberate two-pass convergence: pass N publishes the keys,
	// pass N+1 renders exit peers from them. That matches how the fleet already
	// converges as nodes register, and it is why the rollout requires confirming a
	// key is registered before advancing an exit's phase.
	// !fromCache is not cosmetic here. This is the last controller call left in the
	// pass, and it runs BEFORE engine.Reconcile — so on a cached pass it would dial a
	// controller the agent has just concluded is unreachable, on the SAME pass
	// context, with no per-call deadline of its own. Against a black-holing path
	// (which is what DeadlineExceeded usually means, and which counts as
	// unreachable) that call can burn the pass budget and leave nothing for the local
	// convergence this whole fallback exists to guarantee. It would also publish keys
	// derived from a possibly-stale exit list while every other identity publish in
	// the pass is skipped.
	if !plan && !fromCache && a.role == domain.RoleMaster && spec.Master != nil {
		if err := a.publishTunnelKeys(ctx, kp.PrivateKey, spec.Master.ExitTunnels); err != nil {
			// Non-fatal: the shared key still works in every phase up to `switch`, so a
			// publish failure must not stop the reconcile that keeps traffic flowing.
			a.log.Warn("failed to publish per-tunnel master keys; the fleet keeps using the shared key", "err", err)
		}
	}

	// Censorship-adaptive failover (ADR-0017): converge to the agent-selected active
	// egress within the chain, not blindly to the controller's preferred one. The
	// selector defaults to the preferred egress until a confirmed block demotes it;
	// EffectiveSpec is a no-op while the active egress is the preferred one.
	activeEgress := spec.Egress
	if a.role != domain.RoleMaster {
		activeEgress = a.egressSel.Active(spec.EgressMethods())
		spec = egressfo.EffectiveSpec(spec, activeEgress)
	}

	a.log.Info("reconcile pass", "mode", mode, "state", state,
		"peers", len(spec.Peers), "egress", spec.Egress,
		"wg_port", spec.WGServer.ListenPort, "mtu", spec.WGServer.MTU)

	engine := reconcile.NewEngine(a.log, a.planners(kp.PrivateKey, realityPriv, clientWGPriv, adminUser, adminPass)...)
	start := time.Now()
	report, reconcileErr := engine.Reconcile(ctx, spec, mode)
	elapsed := time.Since(start)

	if plan {
		// Dry-run: show exactly what would change, change nothing.
		if reconcileErr != nil {
			return fmt.Errorf("reconcile: %w", reconcileErr)
		}
		fmt.Print(report.String())
		return nil
	}

	// Apply mode: run self-checks and report the derived lifecycle state, so the
	// node moves to Ready/Degraded/Error rather than staying Reconciling.
	checks := a.healthChecks(spec)
	state, results := health.Evaluate(ctx, reconcileErr, checks)

	// Egress reachability classification (detect-only censorship-block signal): on
	// a persistent warp-egress failure, actively confirm whether the WARP path
	// itself is reachable, telling an ISP/DPI block from a transient blip. It adds
	// an egress-reachability self-check (crosses the wire ⇒ UI badge + metric) but
	// does NOT change the lifecycle state — the node is already Degraded on a failed
	// egress check; this only adds the reason.
	var egressClass domain.EgressReachability
	if a.role != domain.RoleMaster && reconcileErr == nil {
		if class, chk := a.egress.Classify(ctx, results, health.DefaultExitProbes(spec).EgressConfirm); chk != nil {
			egressClass = class
			results = append(results, *chk)
			if class == domain.EgressReachBlocked {
				a.log.Warn("egress classified blocked (likely ISP/DPI block)", "detail", chk.Detail)
			}
			if a.metrics != nil {
				a.metrics.ObserveEgress(class)
			}
		}

		// Throughput watchdog (ADR-0021): measure the ACTIVE egress's real bandwidth.
		// mihomo's url-test is latency-only, so a throttled-but-reachable exit (low
		// throughput, fine RTT — the exit-3 case) is invisible to it. A sustained
		// collapse (hysteresis-smoothed) drives both the failover below and the
		// controller's LB auto-suspend (which reads the reported egress-throughput
		// check). 0 floor ⇒ watchdog disabled.
		var throughputDegraded bool
		a.throughput.MinBytesPerSec = float64(spec.EgressThroughputMinBps)
		if spec.EgressThroughputMinBps > 0 {
			// Passive measurement first: real traffic already on the egress interface
			// proves the exit's throughput. A link saturated by a legitimate heavy
			// download reads high here, so the watchdog never actively probes it — that
			// is what stops a busy-but-healthy exit from being falsely auto-suspended.
			passive := a.passiveEgressBytesPerSec(spec.Routing.EgressInterface)
			probe := health.NewThroughputProbe(spec.Routing.EgressInterface, spec.EgressThroughputProbeURL)
			deg, chk := a.throughput.Observe(ctx, passive, probe)
			// Re-baseline the byte counter AFTER the probe so the probe's own ~256 KiB
			// (when it ran) are not counted as "live traffic" in next pass's passive
			// measurement — the watchdog must not measure its own probe (network review H1).
			a.resnapshotEgressBytes(spec.Routing.EgressInterface)
			throughputDegraded = deg
			results = append(results, chk)
			if deg {
				a.log.Warn("egress throughput-degraded (throttled path)", "detail", chk.Detail)
			}
			if a.metrics != nil {
				a.metrics.ObserveEgressThroughput(a.throughput.LastBytesPerSec())
			}
			// A reachable-but-throttled exit passes warp-egress, so Evaluate would call
			// it Ready; surface the throughput collapse as Degraded so it shows in the
			// node list/metrics, matching the LB auto-suspend the controller applies.
			if throughputDegraded && state == domain.StateReady {
				state = domain.StateDegraded
			}
		}

		// Failover decision (ADR-0017 + ADR-0021): demote to a fallback on a confirmed
		// block OR a sustained throughput collapse; promote back to the preferred egress
		// after sustained recovery. The choice takes effect next pass via EffectiveSpec.
		// The recovery probe tests the still-up wgcf interface for BOTH reachability and
		// throughput, so a still-throttled WARP is not promoted back.
		next := a.egressSel.Step(ctx, spec.EgressMethods(), egressClass, throughputDegraded,
			func(c context.Context) bool {
				if !health.DefaultExitProbes(spec).WARPEgress(c).OK {
					return false
				}
				if spec.EgressThroughputMinBps <= 0 {
					return true
				}
				rate, err := health.NewThroughputProbe(egressfo.WARPInterface, spec.EgressThroughputProbeURL)(c)
				return err == nil && rate >= float64(spec.EgressThroughputMinBps)
			})
		if next != activeEgress {
			a.log.Info("egress failover", "from", activeEgress, "to", next, "chain", spec.EgressMethods())
		}
		results = append(results, domain.HealthCheck{Name: domain.CheckEgressActive, OK: true, Detail: string(next)})
		if a.metrics != nil {
			a.metrics.ObserveEgressActive(next)
		}
	}

	// Drift detection: changes applied while the desired spec is UNCHANGED from
	// the last applied pass mean the node diverged and we repaired it (config
	// drift). The first pass (no prior spec) and any spec change are normal
	// reconcile, not drift; a failed pass is a retry, so only count clean passes.
	// DriftComponents (not ChangedComponents) excludes scheduled/out-of-band
	// planners like the AS-blacklist feed, whose timer-driven refresh is expected
	// work — not divergence — so it does not spuriously WARN/bump drift every cycle.
	print := specFingerprint(spec)
	var drifted []string
	if reconcileErr == nil && a.lastSpecPrint != "" && print == a.lastSpecPrint {
		drifted = report.DriftComponents()
	}
	a.lastSpecPrint = print
	if len(drifted) > 0 {
		a.log.Warn("config drift detected and repaired", "components", drifted, "count", len(drifted))
	}
	if a.metrics != nil {
		a.metrics.ObserveReconcile(elapsed, report.ChangeCount(), state, results, reconcileErr)
		a.metrics.ObserveDrift(drifted)
		if a.role == domain.RoleExit {
			a.metrics.ObserveTransport(spec.ActiveTransport.OrDefault())
		}
		// Read AFTER the pass: the mihomo planner takes the tier decision during
		// reconcile, so before it these would report the previous pass's state.
		if a.tier != nil {
			usable, total := a.tier.StandbyHealth()
			a.metrics.ObserveTier(a.tier.ReserveIsActive(), a.tier.Rotation(), usable, total)
			a.metrics.ObserveStandbyTransports(standbyTransportHealth(a.tier, spec))
		}
		if a.role == domain.RoleMaster {
			bindable, known := a.udpReturnObservations(spec)
			a.metrics.ObserveUDPReturn(bindable, known)
			// mihomo's own complaints. The cursor lives on the agent, not in a planner:
			// planners are rebuilt every pass and would forget where they got to.
			if n, cursor, lerr := mihomo.ScanErrors(ctx, "mihomo", a.mihomoLogCursor); lerr == nil {
				a.metrics.ObserveMihomoErrors(n)
				a.mihomoLogCursor = cursor
			}
		}
	}
	// The client path, and the migration decision it drives. OUTSIDE the metrics
	// block, and that is the point: this is a DATA-PLANE decision that happens to
	// produce a metric, not a metric that happens to move traffic. Nested inside
	// `if a.metrics != nil`, turning the exporter off — with --metrics=off, or by
	// leaving the mgmt address unset — silently disabled both the measurement and
	// the automatic revert, so a node could move its clients into a namespace and
	// then have no way of noticing it had broken them.
	//
	// Taken AFTER the pass: the prober's interface may have been created by it.
	if a.role == domain.RoleMaster {
		probes := master.MeasureClientPath(ctx, a.clientPathTargets(spec), nil)
		results := map[string]bool{}
		for _, pr := range probes {
			results[pr.Name] = pr.OK
			if !pr.OK {
				a.log.Warn("client path probe failed", "probe", pr.Name, "err", pr.Why)
			}
		}
		a.decideNetnsMove(ctx, spec, probes)
		if a.metrics != nil {
			a.metrics.ObserveClientPath(results)
			// AFTER the decision, not before. Reported first, the gauge showed the
			// state the pass STARTED in — so a node that had just moved read as
			// waiting for a full pass, and an operator watching the flip saw the
			// migration lag its own logs by thirty seconds.
			a.metrics.ObserveNetnsMove(a.netnsMove.State(), a.netnsMove.Attempts())
		}
	}
	a.log.Info("reconcile applied",
		"changes", report.ChangeCount(), "drift", len(drifted),
		"state", state, "checks", len(results), "err", reconcileErr)
	// Record the spec only once it has actually applied. LAST-GOOD, not
	// last-received: this is what the node converges to when the controller cannot be
	// reached, and replaying a spec that failed to apply, unattended, at boot, is not
	// a recovery. A write failure is not fatal — the pass succeeded, only the safety
	// net is missing — but it must be visible, because its absence is invisible until
	// the reboot that needed it.
	if !plan && reconcileErr == nil && !fromCache {
		if err := saveSpec(specCacheFile, spec); err != nil {
			a.log.Warn("could not record the last-good spec; this node cannot self-heal if it reboots while the controller is unreachable",
				"path", specCacheFile, "err", err)
		}
	}
	// Report on a FRESH context from the parent, never the pass context: a slow or
	// timed-out apply must still report the node's state, or it sticks in Provisioning.
	// A cached pass has nobody to report to — that is why it is a cached pass — and
	// failing here would throw away a convergence that just succeeded.
	if !fromCache {
		repCtx, repCancel := context.WithTimeout(base, statusReportTimeout)
		defer repCancel()
		if err := a.reportStatus(repCtx, state, results, reconcileErr, a.egressIP(repCtx, spec, activeEgress), a.collectExitHealth(repCtx, spec)); err != nil {
			return err
		}
	}
	if reconcileErr != nil {
		return fmt.Errorf("reconcile: %w", reconcileErr)
	}
	return nil
}

// specFingerprint returns a stable hash of the desired spec, used to tell a
// rollout (spec changed) from drift repair (spec unchanged, world diverged). On
// a marshal error it returns "" — treated as "changed", so it never reports a
// false drift.
func specFingerprint(spec domain.NodeSpec) string {
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// healthChecks builds the role-appropriate self-check set from the spec.
func (a *agent) healthChecks(spec domain.NodeSpec) []health.Check {
	if a.role == domain.RoleMaster {
		probes := health.DefaultMasterProbes(spec,
			master.ClashAPIAddr(spec, a.netnsMove != nil && a.netnsMove.Attached()))
		// Only the agent knows where it records its claim on the client interface,
		// so the probe is wired here rather than derived from the spec.
		mp := a.masterPaths()
		probes.ClientWGOwned = health.ClientWGOwnedProbe(
			master.ClaimPathFor(mp.ClientWGConf), clientIfaceName(mp.ClientWGConf))
		probes.ClientUDPReturn = a.clientUDPReturnProbe(spec)
		return health.MasterChecks(spec, probes)
	}
	return health.ExitChecks(spec, health.DefaultExitProbes(spec))
}

// passiveEgressBytesPerSec returns the real throughput on the active egress
// interface since the last pass (rx+tx delta / elapsed), or 0 when it cannot be
// measured (first pass, the interface changed, direct egress with no dedicated
// interface, a counter reset, or unreadable counters). For WARP egress the wgcf
// interface carries ONLY client egress traffic (the host's own traffic goes direct),
// so this is a clean measure of how much the exit is actually moving — a saturated
// link reads high, letting the watchdog prove it healthy without an active probe.
func (a *agent) passiveEgressBytesPerSec(iface string) float64 {
	now := time.Now()
	cur, ok := readIfaceBytes(iface)
	prevBytes, prevAt, prevIface := a.egressBytesPrev, a.egressBytesAt, a.egressIfacePrev
	a.egressBytesPrev, a.egressBytesAt, a.egressIfacePrev = cur, now, iface
	if !ok || iface == "" || iface != prevIface || prevAt.IsZero() {
		return 0
	}
	elapsed := now.Sub(prevAt).Seconds()
	if elapsed <= 0 || cur < prevBytes {
		return 0 // clock skew or a counter reset (interface re-created)
	}
	return float64(cur-prevBytes) / elapsed
}

// resnapshotEgressBytes re-bases the passive byte counter to NOW after the active
// probe has run, so the probe's own ~256 KiB are excluded from the next pass's
// passive delta (the watchdog must not count its own probe as live traffic). A
// no-op when the counter is unreadable, keeping the prior baseline.
func (a *agent) resnapshotEgressBytes(iface string) {
	if cur, ok := readIfaceBytes(iface); ok {
		a.egressBytesPrev = cur
		a.egressBytesAt = time.Now()
		a.egressIfacePrev = iface
	}
}

// readIfaceBytes returns rx+tx bytes for iface from /sys, or (0,false) when it
// cannot be read (non-Linux dev box, missing interface, empty name).
func readIfaceBytes(iface string) (uint64, bool) {
	if iface == "" {
		return 0, false
	}
	rx, ok1 := readCounter("/sys/class/net/" + iface + "/statistics/rx_bytes")
	tx, ok2 := readCounter("/sys/class/net/" + iface + "/statistics/tx_bytes")
	if !ok1 || !ok2 {
		return 0, false
	}
	return rx + tx, true
}

func readCounter(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// teardown reverses the node's data plane (decommission). In plan mode it prints
// the teardown plan and changes nothing; in apply mode it runs it and reports.
func (a *agent) teardown(ctx context.Context, plan bool) error {
	mode := reconcile.ModeApply
	if plan {
		mode = reconcile.ModePlan
	}
	a.log.Info("decommission: tearing down data plane", "mode", mode)

	engine := reconcile.NewEngine(a.log, a.teardownPlanners()...)
	report, err := engine.Reconcile(ctx, domain.NodeSpec{Decommission: true, Role: a.role}, mode)
	if err != nil {
		return fmt.Errorf("teardown: %w", err)
	}
	if plan {
		fmt.Print(report.String())
		return nil
	}
	a.log.Info("decommission complete", "actions", report.ChangeCount())
	// Report a terminal status so the controller/UI sees the node is torn down.
	return a.reportStatus(ctx, domain.StatePending, []domain.HealthCheck{{Name: "decommissioned", OK: true}}, nil, "", nil)
}

func (a *agent) teardownPlanners() []reconcile.Planner {
	if a.role == domain.RoleMaster {
		return master.TeardownPlanners(a.masterPaths())
	}
	return exit.TeardownPlanners(a.paths)
}

// masterPaths returns the master-role on-node file locations, rooted under the
// state dir for non-root/dev runs.
func (a *agent) masterPaths() master.Paths {
	if a.stateDir != "" {
		return master.PathsUnder(a.stateDir)
	}
	return master.DefaultPaths()
}

// planners returns the role-appropriate reconcile planners. The master's data
// plane is mihomo + NAT; the exit's is the WG/AWG interface + wgcf + routing +
// nftables + DNS.
func (a *agent) planners(privateKey, realityPrivateKey, clientWGPrivateKey, adminUser, adminPass string) []reconcile.Planner {
	var base []reconcile.Planner
	if a.role == domain.RoleMaster {
		base = master.Planners(master.Input{
			Tier:               a.tier,
			Restart:            a.restarts,
			Paths:              a.masterPaths(),
			PrivateKey:         privateKey,
			RealityPrivateKey:  realityPrivateKey,
			ClientWGPrivateKey: clientWGPrivateKey,
			SyntheticKey:       a.ensureSynthKeyQuiet(),
			ClientWGPublicKey:  publicKeyOrEmpty(clientWGPrivateKey),
			NetnsAttached:      a.netnsMove.Attached,
			AdminUsername:      adminUser,
			AdminPassword:      adminPass,
			OverlayMSS:         a.cfg.Agent.MgmtOverlayMSS,
		})
	} else {
		in := exit.Input{
			Paths:               a.paths,
			PrivateKey:          privateKey,
			RealityPrivateKey:   realityPrivateKey,
			OverlayMSS:          a.cfg.Agent.MgmtOverlayMSS,
			ASBlacklistV4URL:    a.cfg.Agent.ASBlacklistV4URL,
			ASBlacklistV6URL:    a.cfg.Agent.ASBlacklistV6URL,
			ASBlacklistInterval: a.cfg.Agent.ASBlacklistInterval,
		}
		in.WARP = a.readWARPProfile()
		base = exit.Planners(in)
	}
	// Host hardening (sshd drop-in + fail2ban jail) is role-agnostic: applied on every
	// node so a drifted or hand-overwritten file self-heals on the next reconcile pass,
	// rather than persisting until the node is re-provisioned.
	hostIn := host.Input{MgmtIgnoreCIDRs: a.cfg.Agent.MgmtIgnoreCIDRs}
	if a.stateDir != "" {
		// Root managed files under the state dir for non-root/dev runs (--state-dir),
		// exactly like exit/master paths — never touch the real host's /etc in a sandbox.
		hostIn.SSHDConfigPath = filepath.Join(a.stateDir, hardening.SSHDDropInPath)
		hostIn.Fail2banJailPath = filepath.Join(a.stateDir, hardening.Fail2banJailPath)
	}
	base = append(base, host.Planners(hostIn)...)
	return base
}

// publishTunnelKeys derives and publishes the master's per-tunnel WireGuard public
// key for every AWG exit tunnel in the spec (ADR-0030). Only public keys cross the
// wire; the derived private keys are recomputed on demand at render time and are
// never written to disk (the master's single wg.key remains the only secret).
//
// Keys are published for every exit unconditionally, regardless of that exit's
// migration phase — the controller decides when to USE one, and having the key
// already registered is what makes the operator's off→dual step a pure exit-side
// change with nothing to wait for.
func (a *agent) publishTunnelKeys(ctx context.Context, masterPrivateKey string, tunnels []domain.ExitTunnel) error {
	seen := make(map[string]struct{}, len(tunnels))
	var errs []error
	for _, t := range tunnels {
		// Reality proxies carry no WireGuard identity, and a dual-transport exit
		// contributes both an AWG and a "<name>-reality" tunnel. Deriving off the
		// reality proxy name would mint a key for a tunnel that can never use it.
		if t.Transport.OrDefault() != domain.TransportAWG {
			continue
		}
		// The derivation input is the exit NAME. For AWG tunnels the proxy name is the
		// exit name, but prefer MasterKeyTunnel when the controller supplied it so the
		// two sides can never disagree about which string was hashed.
		tunnel := t.MasterKeyTunnel
		if tunnel == "" {
			tunnel = t.Name
		}
		if _, dup := seen[tunnel]; dup {
			continue
		}
		seen[tunnel] = struct{}{}

		kp, err := wg.DeriveTunnelKey(masterPrivateKey, tunnel)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := a.client.PublishTunnelKey(ctx, tunnel, kp.PublicKey); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ensureRealityKey returns the exit's REALITY x25519 keypair (ADR-0025). With
// persist=true (apply) it loads or creates+persists the private key (0600); with
// persist=false (plan) it loads an existing key or generates an ephemeral one just
// for rendering, reporting ephemeral=true so dry-run never writes anything.
func (a *agent) ensureRealityKey(persist bool) (priv, pub string, ephemeral bool, err error) {
	if persist {
		priv, pub, _, err = xray.LoadOrCreateKey(a.paths.XrayKey)
		return priv, pub, false, err
	}
	if data, rerr := os.ReadFile(a.paths.XrayKey); rerr == nil {
		p := strings.TrimSpace(string(data))
		pk, perr := xray.PublicKeyFor(p)
		if perr != nil {
			return "", "", false, fmt.Errorf("stored reality key invalid: %w", perr)
		}
		return p, pk, false, nil
	}
	priv, pub, err = xray.GenerateKeypair()
	return priv, pub, true, err
}

// ensureClientVlessKey returns the master's client-facing REALITY x25519 keypair,
// mirroring ensureRealityKey but keyed at the master's own key path. With
// persist=true (apply) it loads or creates+persists the private key (0600); with
// persist=false (plan) it loads an existing key or generates an ephemeral one just
// for rendering, so dry-run never writes anything.
func (a *agent) ensureClientVlessKey(persist bool) (priv, pub string, ephemeral bool, err error) {
	if persist {
		priv, pub, _, err = xray.LoadOrCreateKey(a.paths.ClientVLESSKey)
		return priv, pub, false, err
	}
	if data, rerr := os.ReadFile(a.paths.ClientVLESSKey); rerr == nil {
		p := strings.TrimSpace(string(data))
		pk, perr := xray.PublicKeyFor(p)
		if perr != nil {
			return "", "", false, fmt.Errorf("stored client vless key invalid: %w", perr)
		}
		return p, pk, false, nil
	}
	priv, pub, err = xray.GenerateKeypair()
	return priv, pub, true, err
}

// ensureClientWGKey resolves the master's CLIENT-FACING WireGuard identity: the
// key of the interface end users dial.
//
// The order matters and is the whole migration story. An existing key file wins.
// Failing that we ADOPT the key wg-easy generated, if its database still has one:
// every client config in the field pins that public key, so adopting it makes the
// handover invisible — the server implementation changes underneath a tunnel that
// keeps working. Only with neither do we mint a fresh key, which is the right
// answer for a master that never ran wg-easy at all.
//
// Adoption happens once. Afterwards the key lives in our own file and wg-easy's
// database is never read again.
func (a *agent) ensureClientWGKey(persist bool) (kp wg.KeyPair, ephemeral bool, err error) {
	path := a.masterPaths().ClientWGKey
	data, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		priv := strings.TrimSpace(string(data))
		pub, perr := wg.PublicKeyOf(priv)
		if perr != nil {
			return wg.KeyPair{}, false, fmt.Errorf("stored client wg key invalid: %w", perr)
		}
		if !a.clientKeyAudited.Load() && a.auditClientWGKey(pub) {
			a.clientKeyAudited.Store(true)
		}
		return wg.KeyPair{PrivateKey: priv, PublicKey: pub}, false, nil
	case !errors.Is(rerr, fs.ErrNotExist):
		// The file exists but cannot be read (EIO, EACCES, a truncated write).
		// Falling through to mint would ROTATE this master's client-facing identity
		// and invalidate every config in the field, so refuse instead: the planner
		// defers, and the next pass tries again.
		return wg.KeyPair{}, false, fmt.Errorf("read client wg key %q: %w", path, rerr)
	}

	adopted, state := a.adoptWGEasyKey()
	switch state {
	case adoptOK:
		if !persist {
			return adopted, true, nil
		}
		if werr := writeKeyFile(path, adopted.PrivateKey); werr != nil {
			return wg.KeyPair{}, false, werr
		}
		a.log.Info("adopted the client interface key from wg-easy; existing client configs stay valid",
			"public_key", adopted.PublicKey)
		return adopted, false, nil
	case adoptUnreadable:
		// wg-easy IS here and we could not read its key. Minting now would publish a
		// server identity no client pins — the exact outcome the transparent handover
		// exists to prevent — so hand back nothing. The client-interface planner
		// reports "pending" and we retry on the next pass, which is what a locked or
		// mid-write database needs.
		return wg.KeyPair{}, false, nil
	}

	fresh, gerr := wg.GenerateKeyPair()
	if gerr != nil {
		return wg.KeyPair{}, false, gerr
	}
	if !persist {
		return fresh, true, nil
	}
	if werr := writeKeyFile(path, fresh.PrivateKey); werr != nil {
		return wg.KeyPair{}, false, werr
	}
	a.log.Info("generated a client interface key (no wg-easy key to adopt)", "public_key", fresh.PublicKey)
	return fresh, false, nil
}

// auditClientWGKey reports the client-facing identity this master serves, and
// screams when it does not match the one wg-easy is still handing out.
//
// This is the pre-flight check the migration guide asks the operator to run by
// hand — and asks too late, after the cutover, when everyone is already down. The
// divergence it catches is silent by construction: an existing key file wins on
// every subsequent pass, so a key minted once because wg-easy's database was
// momentarily unrecognisable is never revisited. Nothing looks wrong until the
// handover, at which point every config in the field stops handshaking at once.
// auditClientWGKey reports whether it reached an answer. An inconclusive run — the
// live interface not up yet, the database unreadable — returns false so the caller
// tries again next pass instead of treating the attempt as the audit.
func (a *agent) auditClientWGKey(pub string) (conclusive bool) {
	// First against the LIVE interface. This is the check that keeps working after
	// wg-easy is gone, and it catches the case the database cannot see at all: a
	// key file that no longer matches what is actually answering handshakes,
	// because something else raised the interface.
	live, lerr := master.InterfacePublicKey(master.ClientWGInterface)
	switch {
	case lerr != nil || live == "":
		// Not up yet — ordinary on the first pass after a reboot, since the client
		// interface planner raises it later in this same pass. Say so and report the
		// run inconclusive so the next pass repeats it.
		a.log.Info("client interface identity audit deferred: the live interface cannot be read yet",
			"interface", master.ClientWGInterface, "err", lerr)
		return false
	case live != pub:
		a.log.Error("CLIENT INTERFACE IDENTITY MISMATCH — the key this agent publishes is NOT the key the live "+
			"interface is serving. Clients authenticate against the live one, so the controller is handing out "+
			"configs pinned to a key nobody answers with.",
			"published", pub, "live", live, "interface", master.ClientWGInterface)
	}

	db := a.masterPaths().WGEasyDB
	if _, err := os.Stat(db); err != nil {
		// wg-easy is gone: after the handover this is the ordinary state, and there
		// is nothing left to compare against. Still say what we serve.
		a.log.Info("client interface identity", "public_key", pub)
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	priv, found, err := wgeasy.ReadInterfacePrivateKey(ctx, db, wgeasy.DefaultInterface)
	if err != nil || !found {
		a.log.Info("client interface identity (wg-easy's key could not be read for comparison)",
			"public_key", pub, "db", db)
		return true
	}
	theirs, err := wg.PublicKeyOf(priv)
	if err != nil {
		a.log.Info("client interface identity (wg-easy's key is unusable)", "public_key", pub)
		return true
	}
	if theirs == pub {
		a.log.Info("client interface identity matches wg-easy's; existing client configs stay valid",
			"public_key", pub)
		return true
	}
	a.log.Error("CLIENT INTERFACE IDENTITY DIVERGED FROM wg-easy — every client config in the field would stop "+
		"working at the handover. Do not set client_awg.managed until this is resolved: remove the agent's key "+
		"file so it re-adopts wg-easy's, or confirm the clients have already been reissued.",
		"agent_public_key", pub, "wg_easy_public_key", theirs, "key_file", a.masterPaths().ClientWGKey)
	return true
}

// adoptState says what wg-easy's database had to offer.
type adoptState int

const (
	// adoptAbsent: wg-easy was never set up here, so minting a fresh key is right.
	adoptAbsent adoptState = iota
	// adoptOK: a usable key was found and must be adopted verbatim.
	adoptOK
	// adoptUnreadable: the database is here but would not answer. NOT the same as
	// absent — see ensureClientWGKey.
	adoptUnreadable
)

// adoptWGEasyKey reads the interface private key out of wg-easy's database.
func (a *agent) adoptWGEasyKey() (wg.KeyPair, adoptState) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db := a.masterPaths().WGEasyDB
	priv, found, err := wgeasy.ReadInterfacePrivateKey(ctx, db, wgeasy.DefaultInterface)
	switch {
	case err != nil:
		a.log.Warn("wg-easy's database is present but unreadable; deferring rather than minting a new client key",
			"db", db, "err", err)
		return wg.KeyPair{}, adoptUnreadable
	case !found:
		// "Nothing to adopt" is TWO different facts and only one of them justifies
		// minting. ReadInterfacePrivateKey reports found=false with no error for a
		// missing database file AND for a database whose interfaces table or
		// private-key column it could not recognise — the very rename its column
		// discovery exists to survive. Treating the second as "wg-easy was never set
		// up here" mints a fresh identity on a host that HAS one, and because an
		// existing key file wins from then on, nothing ever re-adopts. The divergence
		// stays invisible until the handover, when every config in the field stops
		// handshaking at once.
		if _, statErr := os.Stat(db); statErr == nil {
			a.log.Warn("wg-easy's database is present but yielded no interface key; deferring rather than minting a new client key",
				"db", db, "interface", wgeasy.DefaultInterface)
			return wg.KeyPair{}, adoptUnreadable
		}
		return wg.KeyPair{}, adoptAbsent
	}
	pub, err := wg.PublicKeyOf(priv)
	if err != nil {
		a.log.Warn("wg-easy's stored interface key is unusable; deferring rather than minting a new client key", "err", err)
		return wg.KeyPair{}, adoptUnreadable
	}
	return wg.KeyPair{PrivateKey: priv, PublicKey: pub}, adoptOK
}

// writeKeyFile persists a private key 0600, creating its directory.
func writeKeyFile(path, key string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return fmt.Errorf("persist key %q: %w", path, err)
	}
	return nil
}

// readWARPProfile reads and parses the wgcf-profile.conf produced on-node by
// `wgcf generate`, returning the WARP credentials for the egress interface. It
// returns nil until the profile exists (the warp planner registers + generates
// it first) or if it cannot be parsed (logged; the next pass regenerates).
func (a *agent) readWARPProfile() *egress.WARPConfig {
	data, err := os.ReadFile(filepath.Join(a.paths.WARPDir, "wgcf-profile.conf"))
	if err != nil {
		return nil
	}
	cfg, err := egress.ParseWGCFProfile(data)
	if err != nil {
		a.log.Warn("wgcf profile present but unparseable; will regenerate", "err", err)
		return nil
	}
	return &cfg
}

// reportStatus pushes the computed lifecycle state, self-check results, and any
// reconcile error to the controller (the error becomes the node's LastError).
// egressIP, when known, is the address the node's traffic appears to leave under
// (the WARP IP for warp egress, the node's own IP for direct) — surfaced in the UI.
func (a *agent) reportStatus(ctx context.Context, state domain.NodeState, checks []domain.HealthCheck, reconcileErr error, egressIP string, exitHealth []domain.ExitTunnelHealth) error {
	st := domain.NodeStatus{State: state, Checks: checks, EgressIP: egressIP, ExitHealth: exitHealth, LastHandshake: a.latestHandshake(ctx)}
	// A master reports its live client peers so the controller's client page shows
	// the kernel's view rather than the desired state's. Best-effort by design: an
	// interface that is not up yet (or still wg-easy's) simply contributes none.
	if a.role == domain.RoleMaster {
		st.ClientPeers = health.ClientPeers(ctx, clientIfaceName(a.masterPaths().ClientWGConf))
	}
	if reconcileErr != nil {
		st.ReconcileError = reconcileErr.Error()
	}
	if _, err := a.client.ReportStatus(ctx, st); err != nil {
		return fmt.Errorf("report status: %w", err)
	}
	return nil
}

// latestHandshake reads the node's freshest WireGuard handshake for the status
// report's HANDSHAKE column (data-plane liveness): an exit's master↔exit kernel
// AWG tunnel (awg0), or a master's wg-easy client interface (wg0). It is
// best-effort — zero (shown as "—") when the interface is absent or carries no WG
// handshake (e.g. an exit whose active transport is REALITY, not kernel AWG).
func (a *agent) latestHandshake(ctx context.Context) time.Time {
	iface := "awg0" // exit: master↔exit kernel AWG tunnel (matches DefaultExitProbes)
	if a.role == domain.RoleMaster {
		iface = wgeasy.DefaultInterface
	}
	return health.LatestHandshake(ctx, iface)
}

// wgBestGroupName is the mihomo load-balance group the master routes through; its
// current selection marks the exit carrying traffic.
const wgBestGroupName = "wg-best"

// standbyTransportHealth relabels the tier selector's standby verdicts from the
// mihomo PROXY name it probes ("vn0-reality") to the exit node plus transport an
// operator actually reasons about ("vn0", "reality-xhttp"). The selector keeps
// proxy names because that is what a Clash probe addresses; the metric wants the
// node, because a series keyed by a proxy name reads as an exit that does not
// exist. Returns nil for a non-master or an exit with no standby transport.
func standbyTransportHealth(tier *master.TierSelector, spec domain.NodeSpec) map[metrics.StandbyTransport]bool {
	if spec.Master == nil {
		return nil
	}
	verdicts := tier.StandbyTransportHealth()
	if len(verdicts) == 0 {
		return nil
	}
	out := make(map[metrics.StandbyTransport]bool, len(verdicts))
	for _, st := range mihomo.StandbyTransports(*spec.Master) {
		if usable, ok := verdicts[st.Proxy]; ok {
			out[metrics.StandbyTransport{Exit: st.Exit, Transport: string(st.Transport)}] = usable
		}
	}
	return out
}

// exitHealthForMaster parses per-exit tunnel health from a Clash /proxies payload
// using the master spec's exit names. It returns nil for a non-master or when the
// payload cannot be parsed — collection is best-effort and never fails the report.
func exitHealthForMaster(proxiesJSON []byte, spec domain.NodeSpec) []domain.ExitTunnelHealth {
	if spec.Role != domain.RoleMaster || spec.Master == nil {
		return nil
	}
	names := make([]string, 0, len(spec.Master.ExitTunnels))
	for _, t := range spec.Master.ExitTunnels {
		names = append(names, t.Name)
	}
	if len(names) == 0 {
		return nil
	}
	h, err := mihomo.ParseProxyHealth(proxiesJSON, wgBestGroupName, names)
	if err != nil {
		return nil
	}
	return h
}

// collectExitHealth fetches the master's mihomo /proxies snapshot and parses it.
// On any error it logs and returns nil so the status report still sends.
func (a *agent) collectExitHealth(ctx context.Context, spec domain.NodeSpec) []domain.ExitTunnelHealth {
	if spec.Role != domain.RoleMaster || spec.Master == nil || spec.Master.ExternalController == "" {
		return nil
	}
	// domain.MasterSpec.Custom is a VALUE (domain.CustomConfig), not a pointer — a
	// nil Overrides map is fine, the lookup just yields "".
	js, err := mihomo.FetchProxies(ctx, spec.Master.ExternalController, clashAPISecret(spec.Master.Custom.Overrides))
	if err != nil {
		a.log.Warn("could not fetch mihomo proxy health", "err", err)
		return nil
	}
	return exitHealthForMaster(js, spec)
}

// clashAPISecret reads the mihomo Clash API secret from the operator's mihomo
// overrides — the same key the running mihomo enforces, so the fetch authenticates
// exactly like the master health probe (mirrors internal/agent/health/probes.go
// clashSecret, which reads overrides["secret"]). Missing/non-string ⇒ "" (no auth
// header). Defined locally because that helper is package-private to `health`.
func clashAPISecret(overrides map[string]any) string {
	if s, ok := overrides["secret"].(string); ok {
		return s
	}
	return ""
}

// egressEchoURLs are the off-Cloudflare IP-echo endpoints the warp-egress probe
// hits, in order, to learn the address client traffic leaves under. They MUST NOT be
// fronted by Cloudflare: WARP routes Cloudflare-bound traffic out a different
// "on-net" egress IP than general-internet traffic, so a Cloudflare endpoint reports
// an address that never matches what clients actually appear under. checkip.amazonaws.com
// (AWS) and ifconfig.me are off-Cloudflare and return the bare egress IP; the second
// covers a transient rate-limit/outage of the first.
var egressEchoURLs = []string{
	"https://checkip.amazonaws.com",
	"https://ifconfig.me",
}

// egressTraceURL is the last-resort fallback: Cloudflare's own trace endpoint is the
// authoritative WARP source (it can't return a captive page or stale CDN body), but
// it reports the on-net egress IP — only correct for Cloudflare-bound traffic, so it
// is used ONLY when every off-Cloudflare echo above is unreachable. Its body is
// key=value lines (the IP is on the `ip=` line), not a bare address.
const egressTraceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// egressIP reports the address the exit's client traffic leaves under: the
// Cloudflare WARP IP for warp egress (observed via an off-Cloudflare IP echo through
// the egress interface), or the node's own public IP for direct egress. Best-effort —
// "" when it cannot be determined. Masters have no egress and return "".
func (a *agent) egressIP(ctx context.Context, spec domain.NodeSpec, active domain.EgressMethod) string {
	if a.role == domain.RoleMaster {
		return ""
	}
	if active != domain.EgressWARP {
		return a.publicIP // direct egress leaves under the node's own IP
	}
	iface := spec.Routing.EgressInterface
	if iface == "" {
		iface = "wgcf"
	}
	for _, url := range egressEchoURLs {
		// The echoes return the bare IP (plus a trailing newline); validate it so a
		// captive page or error body never lands in the store as an "egress IP".
		if ip := curlEgressIP(ctx, iface, url, ""); ip != "" {
			return ip
		}
	}
	// All off-Cloudflare echoes failed: fall back to Cloudflare's trace (on-net IP).
	return curlEgressIP(ctx, iface, egressTraceURL, "ip=")
}

// curlEgressIP curls url through iface and extracts a valid IP from the response. With
// an empty linePrefix the whole (trimmed) body must be the IP; otherwise the IP is
// read from the line carrying that prefix (e.g. "ip=" in Cloudflare's trace output).
// Returns "" on any curl error or when no valid IP is found.
func curlEgressIP(ctx context.Context, iface, url, linePrefix string) string {
	out, err := exec.CommandContext(ctx, "curl", "-s", "--max-time", "5",
		"--interface", iface, url).Output()
	if err != nil {
		return ""
	}
	if linePrefix == "" {
		if ip := net.ParseIP(strings.TrimSpace(string(out))); ip != nil {
			return ip.String()
		}
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, linePrefix); ok {
			if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

// ensureWGKey returns the node's WG key pair. With persist=true it loads or
// creates+persists the key (apply mode). With persist=false it loads an existing
// key or, if none exists, generates an ephemeral in-memory key (plan mode) and
// reports ephemeral=true.
func (a *agent) ensureWGKey(persist bool) (kp wg.KeyPair, ephemeral bool, err error) {
	if persist {
		kp, created, err := wg.LoadOrCreateKey(a.paths.WGKey)
		return kp, created, err
	}
	data, rerr := os.ReadFile(a.paths.WGKey)
	if rerr == nil {
		priv := strings.TrimSpace(string(data))
		pub, perr := wg.PublicKeyOf(priv)
		if perr != nil {
			return wg.KeyPair{}, false, fmt.Errorf("stored key invalid: %w", perr)
		}
		return wg.KeyPair{PrivateKey: priv, PublicKey: pub}, false, nil
	}
	kp, err = wg.GenerateKeyPair()
	return kp, true, err
}

// ensureWGEasyAdmin returns the wg-easy admin credentials that seed unattended
// setup. With persist=true (apply mode) it loads or generates+persists the
// password (0600, on-node only). With persist=false (plan mode) it loads an
// existing password or generates an ephemeral one just for rendering, reporting
// ephemeral=true, so dry-run never writes anything. The username is fixed
// (wgeasy.AdminUsername); only the password is secret.
func (a *agent) ensureWGEasyAdmin(persist bool) (user, pass string, ephemeral bool, err error) {
	path := a.masterPaths().WGEasyAdmin
	if persist {
		pass, _, err = wgeasy.LoadOrCreateAdminPassword(path)
		return wgeasy.AdminUsername, pass, false, err
	}
	if p, rerr := wgeasy.ReadAdminPassword(path); rerr == nil {
		return wgeasy.AdminUsername, p, false, nil
	}
	pass, err = wgeasy.GeneratePassword()
	return wgeasy.AdminUsername, pass, true, err
}

func buildClientTLS(cfg *config.AgentConfig) (*tls.Config, error) {
	certPEM, err := os.ReadFile(cfg.Agent.Identity.Cert)
	if err != nil {
		return nil, fmt.Errorf("read node cert: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.Agent.Identity.Key)
	if err != nil {
		return nil, fmt.Errorf("read node key: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.Agent.Identity.CA)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	// Reloadable, because renewal that needs a restart to take effect is renewal
	// that takes effect months late — quite possibly after the certificate it
	// replaced has expired.
	load := func() (tls.Certificate, error) {
		c, err := os.ReadFile(cfg.Agent.Identity.Cert)
		if err != nil {
			return tls.Certificate{}, err
		}
		k, err := os.ReadFile(cfg.Agent.Identity.Key)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(c, k)
	}
	_ = certPEM
	_ = keyPEM
	return pki.ReloadableClientTLS(load, caPEM, serverNameOf(cfg.Agent.Controller))
}

// renewCertificateIfDue rotates this node's control-plane certificate once it is
// past the renewal point (see certrenew.DueAt).
//
// Called from the reconcile loop rather than a timer: the loop already runs every
// 30 seconds with a live controller connection, which is exactly what renewal needs,
// and a node that cannot reconcile cannot renew anyway.
//
// A failure BACKS OFF rather than retrying at the loop's cadence. The renewal window
// is ~110 days wide, so at one attempt per pass a controller below wire 10, or one
// with no CA loaded, produced roughly 316 thousand identical WARN lines and as many
// P-256 keygens and RPCs before the certificate finally lapsed — on the same node
// whose Register path was rewritten specifically to stop emitting 59k lines a day.
// The condition that most needs to be visible was drowning itself. Doubling from one
// pass up to an hour keeps the first few failures prompt (a controller restart
// recovers within a pass) and turns a stuck node into roughly 24 lines a day.
func (a *agent) renewCertificateIfDue(ctx context.Context) {
	cfg := a.cfg
	notBefore, notAfter, err := certrenew.NotBeforeAfter(cfg.Agent.Identity.Cert)
	if err != nil {
		// The one node that will never renew is the one that would otherwise say
		// nothing: this is the agent's own certificate, and being unable to read it is
		// not a quiet fact.
		a.log.Warn("cannot read this node's own certificate; renewal is not possible",
			"path", cfg.Agent.Identity.Cert, "err", err)
		return
	}
	if !certrenew.Due(cfg.Agent.NodeID, notBefore, notAfter, time.Now()) {
		return
	}
	if now := time.Now(); now.Before(a.renewNotBefore) {
		return
	}
	paths := certrenew.Paths{
		Cert: cfg.Agent.Identity.Cert, Key: cfg.Agent.Identity.Key, CA: cfg.Agent.Identity.CA,
	}
	if err := certrenew.Rotate(ctx, a.client, paths); err != nil {
		a.renewBackoff = nextRenewBackoff(a.renewBackoff)
		a.renewNotBefore = time.Now().Add(a.renewBackoff)
		if time.Now().After(notAfter) {
			// Renewal travels over the mTLS channel this certificate opens, so an
			// EXPIRED one can never renew: the handshake fails before the RPC. "Will
			// retry" is then false, and it is the message an operator reads at the exact
			// moment they need the out-of-band path instead.
			a.log.Error("this node's certificate has EXPIRED and cannot renew itself; "+
				"re-issue it out of band with `wgfleet-controller --certs renew --node "+cfg.Agent.NodeID+"`",
				"expired", notAfter, "err", err)
			return
		}
		a.log.Warn("certificate renewal failed", "expires", notAfter,
			"next_attempt_in", a.renewBackoff, "err", err)
		return
	}
	a.renewBackoff, a.renewNotBefore = 0, time.Time{}
	a.log.Info("control-plane certificate renewed", "previous_expiry", notAfter)
}

// nextRenewBackoff doubles from one reconcile pass up to an hour.
func nextRenewBackoff(current time.Duration) time.Duration {
	const (
		first = 30 * time.Second
		max   = time.Hour
	)
	switch {
	case current <= 0:
		return first
	case current*2 >= max:
		return max
	default:
		return current * 2
	}
}

// serverNameOf returns the host portion of the controller endpoint, which must
// match a SAN on the controller's server certificate during the TLS handshake.
func serverNameOf(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint
	}
	return host
}

func setupLogging(format string) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// clientIfaceName derives the client interface's name from its config path, the
// way awg-quick does.
func clientIfaceName(confPath string) string {
	return strings.TrimSuffix(filepath.Base(confPath), ".conf")
}

// pullSpecOrCache fetches the desired spec, falling back to the last-good one when
// the controller cannot be reached. It sets *fromCache when it did.
//
// A failed pull freezes EVERY subsystem on this node — interfaces, routing,
// nftables, mihomo, blocky, the client leg — because the pass returns before any
// planner runs. It used to do so in total silence: no status, so no state change,
// no health check and no reconcile metric, which made the widest failure mode the
// least visible one. It still reports; it just no longer stands still when there is
// a spec on disk that worked.
func (a *agent) pullSpecOrCache(ctx, base context.Context, plan bool, fromCache *bool) (domain.NodeSpec, error) {
	spec, err := a.client.PullSpec(ctx)
	if err == nil {
		return spec, nil
	}
	// Only when NOTHING ANSWERED. A refusal — NotFound for a node the operator
	// deleted, PermissionDenied for a revoked certificate — is the controller
	// talking, and its answer must win over anything on disk.
	if !plan && controllerUnreachable(err) {
		if cached, age, cerr := loadSpec(specCacheFile); cerr == nil {
			a.log.Warn("controller unreachable; converging on the last-good spec instead of standing still",
				"err", err, "spec_age", age.Round(time.Second), "path", specCacheFile)
			*fromCache = true
			return cached, nil
		}
	}
	if !plan {
		repCtx, repCancel := context.WithTimeout(base, statusReportTimeout)
		defer repCancel()
		check := domain.HealthCheck{Name: domain.CheckSpecValid, OK: false,
			Detail: "could not pull a spec from the controller: " + err.Error()}
		if rerr := a.reportStatus(repCtx, domain.StateError, []domain.HealthCheck{check}, err, "", nil); rerr != nil {
			a.log.Error("failed to report the pull failure", "err", rerr)
		}
	}
	return domain.NodeSpec{}, fmt.Errorf("pull spec: %w", err)
}

// accountedUDPBlackHoles derives the destination ports whose client traffic is
// REFUSED by this node's own ruleset — the ports on which a missing reply socket
// costs nothing, because no client datagram gets that far.
//
// Refused, not held. The first version answered with the ports the node BINDS,
// which is the very set the check examines: the client WG interface's port was
// accounted for by virtue of being the black hole, so `accepted(443)` was true
// forever and the alert could not fire on the one port the August outage was on.
// "This node holds the port" and "a rule refuses traffic to it" are two different
// facts, and only the second one means nobody is sitting there
// waiting for a reply that cannot come.
//
// The set comes from netfw, derived from the same input the ruleset was rendered
// from, so a drop rule that stops being emitted stops being claimed.
func accountedUDPBlackHoles(in netfw.MasterNATInput) map[int]bool {
	known := map[int]bool{}
	for _, p := range netfw.RefusedUDPPorts(in) {
		known[p] = true
	}
	return known
}

// natInputFor rebuilds the master NAT render input as this pass's planner will
// build it, so the ports claimed refused describe the ruleset this node actually
// applies.
func (a *agent) natInputFor(spec domain.NodeSpec) netfw.MasterNATInput {
	attached := a.netnsMove != nil && a.netnsMove.Attached()
	return master.NATInput(spec, clientIfaceName(a.masterPaths().ClientWGConf), attached)
}

// clientUDPReturnProbe builds the master's UDP-return check over the ports the
// kernel actually reports, not a list in the code — the first draft guessed the
// ports and would have missed exactly the case it was written to catch.
func (a *agent) clientUDPReturnProbe(spec domain.NodeSpec) health.Probe {
	ports, err := health.HeldUDPPorts()
	if err != nil {
		// Cannot read the socket table: probe the one port we know by construction
		// rather than nothing, and let the probe report itself blind if that fails too.
		ports = []int{spec.WGServer.ListenPort}
	}
	known := accountedUDPBlackHoles(a.natInputFor(spec))
	return health.ClientUDPReturnProbe(ports, health.UDPReturnBindable, func(p int) bool {
		return known[p]
	})
}

// udpReturnObservations samples, for every UDP port this host holds, whether a
// TPROXY reply socket is still possible there and whether a rule refuses client
// traffic to it. It is the metric behind the udp-return-path check; a port the
// probe cannot answer for is simply left out rather than reported as either state.
func (a *agent) udpReturnObservations(spec domain.NodeSpec) (bindable, known map[int]bool) {
	ports, err := health.HeldUDPPorts()
	if err != nil {
		return nil, nil
	}
	declared := accountedUDPBlackHoles(a.natInputFor(spec))
	bindable, known = map[int]bool{}, map[int]bool{}
	for _, p := range ports {
		ok, perr := health.UDPReturnBindable(p)
		if perr != nil {
			continue
		}
		bindable[p] = ok
		known[p] = declared[p]
	}
	return bindable, known
}

// ensureSynthKeyQuiet resolves the prober's keypair, logging rather than failing
// when it cannot: a master that cannot mint this key must still serve clients, it
// simply goes unmeasured.
func (a *agent) ensureSynthKeyQuiet() wg.KeyPair {
	if a.synthKP.PrivateKey != "" {
		return a.synthKP
	}
	kp, err := a.ensureSynthKey()
	if err != nil {
		a.log.Warn("no synthetic client key; the client path will not be measured", "err", err)
		return wg.KeyPair{}
	}
	a.synthKP = kp
	return kp
}

// ensureSynthKey reads the prober's key or mints it. Unlike the client-facing
// interface key there is no adoption path and no field to invalidate: losing this
// key costs one restarted measurement, so minting a fresh one is always safe.
func (a *agent) ensureSynthKey() (wg.KeyPair, error) {
	path := a.masterPaths().SynthKey
	data, err := os.ReadFile(path)
	if err == nil {
		priv := strings.TrimSpace(string(data))
		pub, perr := wg.PublicKeyOf(priv)
		if perr != nil {
			return wg.KeyPair{}, fmt.Errorf("stored synthetic client key invalid: %w", perr)
		}
		return wg.KeyPair{PrivateKey: priv, PublicKey: pub}, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return wg.KeyPair{}, fmt.Errorf("read synthetic client key %q: %w", path, err)
	}
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		return wg.KeyPair{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return wg.KeyPair{}, err
	}
	if err := os.WriteFile(path, []byte(kp.PrivateKey+"\n"), 0o600); err != nil {
		return wg.KeyPair{}, err
	}
	return kp, nil
}

// publicKeyOrEmpty derives a public key, or returns "" when there is no private
// key to derive one from. Used where a missing key means "this feature is simply
// not configured" rather than an error worth failing a pass over.
func publicKeyOrEmpty(privateKey string) string {
	if privateKey == "" {
		return ""
	}
	pub, err := wg.PublicKeyOf(privateKey)
	if err != nil {
		return ""
	}
	return pub
}

// clientGatewayOf is the master's own address in the client pool: what a client
// sends its DNS to, and what the prober pings to prove the tunnel itself.
func clientGatewayOf(spec domain.NodeSpec) string {
	if spec.Master == nil || spec.Master.ClientWG == nil {
		return ""
	}
	return spec.Master.ClientWG.ServerAddress
}

// clientPathTargets aims the prober at everything a client is supposed to reach,
// not only at what happens to be easy to reach.
//
// The list grew because the first one could not fail on the failures this branch
// introduces: two of its three probes never went through mihomo at all, and none
// of them touched a destination that is supposed to BYPASS the interception. A
// prober that stays green while the thing it guards is broken is worse than no
// prober, because it is also the judge of the automatic revert.
func (a *agent) clientPathTargets(spec domain.NodeSpec) master.ClientPathTargets {
	t := master.ClientPathTargets{
		Gateway:  clientGatewayOf(spec),
		MgmtAddr: a.mgmtAddr,
	}
	if spec.Master != nil {
		t.Direct = spec.Master.DirectCIDRs
	}
	// The UDP probe re-executes this binary inside the prober's namespace. If we
	// cannot name our own path we simply take one fewer probe: a missing probe is
	// an honest gap, a fabricated one is not.
	if self, err := os.Executable(); err == nil {
		t.SelfExec = self
	}
	return t
}

// netnsMoveState is the agent-side handle on the namespace migration decision.
// A thin alias so main.go does not have to name the master package's internals.
type netnsMoveState = master.NetnsMove

// decideNetnsMove advances the migration decision using the evidence this pass
// already gathered.
//
// The decision is taken here, once per pass, rather than inside a planner: it
// needs the namespace's own readiness AND the client-path probes, neither of
// which a planner should be running, and it has to remember its attempts across
// passes — which a planner cannot, because they are rebuilt every time.
//
// It runs AFTER the pass on purpose. The evidence is about the state the pass
// just produced, and rendering on the next pass means nothing ever moves on a
// guess.
func (a *agent) decideNetnsMove(ctx context.Context, spec domain.NodeSpec, probes []master.ClientPathProbe) {
	if a.role != domain.RoleMaster || spec.Master == nil {
		return
	}
	wanted, _, werr := spec.Master.NetnsWanted()
	if werr != nil {
		// The knob was mistyped. Refuse to move rather than guess at what was meant:
		// an unrecognised value used to be read as a canary CIDR, so `"of"` instead of
		// `"off"` turned the migration ON.
		a.log.Warn("client interception knob not understood; staying on the host path", "err", werr)
		wanted = false
	}
	before := a.netnsMove.Attached()
	after := a.netnsMove.Decide(wanted,
		func() error { return master.NamespaceReady(ctx, spec) },
		func() bool { return master.ClientPathOK(probes) })
	if before != after {
		a.log.Warn("client interception moved", "in_namespace", after, "why", a.netnsMove.Reason())
		return
	}
	a.log.Debug("client interception unchanged", "in_namespace", after, "why", a.netnsMove.Reason())
}
