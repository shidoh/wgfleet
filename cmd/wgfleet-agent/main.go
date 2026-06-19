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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/agent/client"
	egressfo "github.com/shidoh/wgfleet/internal/agent/egress"
	"github.com/shidoh/wgfleet/internal/agent/exit"
	"github.com/shidoh/wgfleet/internal/agent/health"
	"github.com/shidoh/wgfleet/internal/agent/master"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/metrics"
	"github.com/shidoh/wgfleet/internal/version"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// metricsMux builds the agent's /metrics HTTP handler.
func metricsMux(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler(reg))
	return mux
}

func main() {
	if err := run(); err != nil {
		slog.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "/etc/wgfleet/agent.yaml", "path to agent config")
		logFormat   = flag.String("log-format", "text", "log format: text | json")
		plan        = flag.Bool("plan", false, "dry-run: show what reconcile would change, apply nothing")
		once        = flag.Bool("once", false, "run a single reconcile pass and exit")
		publicIP    = flag.String("public-ip", "", "this node's public IP to advertise (peer endpoint)")
		mgmtAddr    = flag.String("mgmt-addr", "", "this node's mgmt/ZT address (admin + metrics + DNS bind)")
		stateDir    = flag.String("state-dir", "", "root managed files under this dir instead of /etc (non-root/dev runs)")
		metricsBind = flag.String("metrics", "", "bind address for the agent /metrics endpoint (mgmt/ZT only; empty disables)")
		showVersion = flag.Bool("version", false, "print build version and exit")
	)
	flag.Parse()

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

	tlsCfg, err := buildClientTLS(cfg)
	if err != nil {
		return fmt.Errorf("build mTLS: %w", err)
	}
	conn, err := client.Dial(cfg.Agent.Controller, tlsCfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	paths := exit.DefaultPaths()
	if *stateDir != "" {
		paths = exit.PathsUnder(*stateDir)
	}
	a := &agent{
		cfg:      cfg,
		role:     role,
		publicIP: *publicIP,
		mgmtAddr: *mgmtAddr,
		stateDir: *stateDir,
		paths:    paths,
		client:   conn,
		log:      slog.With("node", cfg.Agent.NodeID, "role", role),
	}

	// Agent /metrics (own reconcile/health counters). Bind mgmt/ZT only: this
	// endpoint is unauthenticated and leaks fleet topology (node id, role, egress
	// IP, health) if exposed publicly, so refuse a public bind like the controller.
	if *metricsBind != "" {
		if err := config.RequireMgmtBind("--metrics", *metricsBind); err != nil {
			return err
		}
		reg := metrics.NewRegistry()
		a.metrics = metrics.NewAgentMetrics(reg, cfg.Agent.NodeID, role, time.Now())
		metricsSrv := &http.Server{Addr: *metricsBind, Handler: metricsMux(reg)}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	client   *client.Client
	log      *slog.Logger

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

	state, err := a.client.Register(ctx, a.role, a.publicIP, "", a.mgmtAddr)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	if !plan {
		if err := a.client.PublishPublicKey(ctx, kp.PublicKey); err != nil {
			return fmt.Errorf("publish public key: %w", err)
		}
	}

	spec, err := a.client.PullSpec(ctx)
	if err != nil {
		return fmt.Errorf("pull spec: %w", err)
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
			if rerr := a.reportStatus(repCtx, domain.StateError, []domain.HealthCheck{check}, err); rerr != nil {
				a.log.Error("failed to report invalid-spec state", "err", rerr)
			}
			return fmt.Errorf("invalid spec, not applied: %w", err)
		}
	}
	if spec.Decommission {
		return a.teardown(ctx, plan)
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

	engine := reconcile.NewEngine(a.log, a.planners(kp.PrivateKey, adminUser, adminPass)...)
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
			probe := health.NewThroughputProbe(spec.Routing.EgressInterface, spec.EgressThroughputProbeURL)
			deg, chk := a.throughput.Observe(ctx, probe)
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
	print := specFingerprint(spec)
	var drifted []string
	if reconcileErr == nil && a.lastSpecPrint != "" && print == a.lastSpecPrint {
		drifted = report.ChangedComponents()
	}
	a.lastSpecPrint = print
	if len(drifted) > 0 {
		a.log.Warn("config drift detected and repaired", "components", drifted, "count", len(drifted))
	}
	if a.metrics != nil {
		a.metrics.ObserveReconcile(elapsed, state, results, reconcileErr)
		a.metrics.ObserveDrift(drifted)
	}
	a.log.Info("reconcile applied",
		"changes", report.ChangeCount(), "drift", len(drifted),
		"state", state, "checks", len(results), "err", reconcileErr)
	// Report on a FRESH context from the parent, never the pass context: a slow or
	// timed-out apply must still report the node's state, or it sticks in Provisioning.
	repCtx, repCancel := context.WithTimeout(base, statusReportTimeout)
	defer repCancel()
	if err := a.reportStatus(repCtx, state, results, reconcileErr); err != nil {
		return err
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
		return health.MasterChecks(spec, health.DefaultMasterProbes(spec))
	}
	return health.ExitChecks(spec, health.DefaultExitProbes(spec))
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
	return a.reportStatus(ctx, domain.StatePending, []domain.HealthCheck{{Name: "decommissioned", OK: true}}, nil)
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
func (a *agent) planners(privateKey, adminUser, adminPass string) []reconcile.Planner {
	if a.role == domain.RoleMaster {
		return master.Planners(master.Input{
			Paths:         a.masterPaths(),
			PrivateKey:    privateKey,
			AdminUsername: adminUser,
			AdminPassword: adminPass,
			OverlayMSS:    a.cfg.Agent.MgmtOverlayMSS,
		})
	}
	in := exit.Input{Paths: a.paths, PrivateKey: privateKey, OverlayMSS: a.cfg.Agent.MgmtOverlayMSS}
	in.WARP = a.readWARPProfile()
	return exit.Planners(in)
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
func (a *agent) reportStatus(ctx context.Context, state domain.NodeState, checks []domain.HealthCheck, reconcileErr error) error {
	st := domain.NodeStatus{State: state, Checks: checks}
	if reconcileErr != nil {
		st.ReconcileError = reconcileErr.Error()
	}
	if _, err := a.client.ReportStatus(ctx, st); err != nil {
		return fmt.Errorf("report status: %w", err)
	}
	return nil
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
	return pki.ClientTLS(certPEM, keyPEM, caPEM, serverNameOf(cfg.Agent.Controller))
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
