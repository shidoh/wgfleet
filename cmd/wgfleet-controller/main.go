// Command wgfleet-controller is the control plane: it holds desired fleet
// state, brokers public keys, provisions nodes, and serves the agent API over
// mutual TLS.
//
// Bootstrap helpers:
//
//	--init-pki            generate a CA and write it to the configured pki paths
//	--issue-node <id>     issue a node mTLS bundle (node.crt/node.key/ca.crt)
//	--issue-out <dir>     directory for --issue-node output (default ./pki/<id>)
//
// Without those flags it loads the CA, serves the NodeService gRPC API, and runs
// until signalled. The provisioner and reconcile orchestration land on top of
// this in later milestones.
package main

import (
	"context"
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

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/grpcapi"
	"github.com/shidoh/wgfleet/internal/controller/keybroker"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provmgr"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/sweeper"
	"github.com/shidoh/wgfleet/internal/controller/web"
	"github.com/shidoh/wgfleet/internal/metrics"
	"github.com/shidoh/wgfleet/internal/version"
)

func main() {
	if err := run(); err != nil {
		slog.Error("controller exited with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath   = flag.String("config", "/etc/wgfleet/controller.yaml", "path to controller config")
		logFormat    = flag.String("log-format", "text", "log format: text | json")
		storePath    = flag.String("store", "", "override controller.store path")
		initPKI      = flag.Bool("init-pki", false, "generate a CA at the configured pki paths and exit")
		issueNode    = flag.String("issue-node", "", "issue an mTLS bundle for the given node ID and exit")
		issueOut     = flag.String("issue-out", "", "output dir for --issue-node (default ./pki/<id>)")
		provision    = flag.String("provision", "", "SSH-bootstrap the named fleet node, then exit")
		upgradeAgent = flag.String("upgrade-agent", "", "roll the named node's agent binary forward (upload + restart) over SSH, then exit")
		plan         = flag.Bool("plan", false, "with --provision/--upgrade-agent: dry-run, show the plan and change nothing")
		agentBin     = flag.String("agent-bin", "", "with --provision/--upgrade-agent: path to the wgfleet-agent binary to install (default controller.agent_bin)")
		ctlEndpoint  = flag.String("controller-endpoint", "", "with --provision: controller mTLS endpoint the agent dials (default controller.listen)")
		showVersion  = flag.Bool("version", false, "print build version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("wgfleet-controller", version.String())
		fmt.Printf("wire-contract version %d (serves v%d..v%d)\n",
			api.WireContractVersion, api.MinSupportedWire, api.WireContractVersion)
		return nil
	}

	setupLogging(*logFormat)

	cfg, err := config.Load(*configPath, &config.ControllerConfig{})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if *storePath != "" { // flag overrides file, per config-driven principle
		cfg.Controller.Store = *storePath
	}

	if *initPKI {
		keyPath, err := caKeyPath(cfg)
		if err != nil {
			return err
		}
		return initCA(cfg.Controller.PKI.CACert, keyPath)
	}

	// Every non-init path needs the CA loaded. Resolve the private key through the
	// secret provider so a secret://-referenced key (SOPS/age) is decrypted in
	// memory and never written to disk.
	provider, err := config.NewSecretProvider(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("init secret provider: %w", err)
	}
	ca, err := loadCA(cfg, provider)
	if err != nil {
		return fmt.Errorf("load CA (run --init-pki first?): %w", err)
	}

	if *issueNode != "" {
		return issueNodeBundle(ca, *issueNode, *issueOut)
	}
	if *provision != "" {
		return provisionNode(cfg, ca, provisionOpts{
			node:        *provision,
			plan:        *plan,
			agentBin:    *agentBin,
			ctlEndpoint: *ctlEndpoint,
		})
	}
	if *upgradeAgent != "" {
		return upgradeAgentNode(cfg, ca, *upgradeAgent, *agentBin, *plan)
	}

	return serve(cfg, ca)
}

// loadCA builds the fleet CA, resolving the private key through the secret
// provider. A bare path or file:// key is read from disk (unchanged); any other
// secret reference (secret://, env://) is resolved in memory via the provider so
// the decrypted CA key never touches disk.
func loadCA(cfg *config.ControllerConfig, provider config.SecretProvider) (*pki.CA, error) {
	keyRef := cfg.Controller.PKI.CAKey
	if !keyRef.IsReference() || strings.HasPrefix(string(keyRef), "file://") {
		keyPath, err := caKeyPath(cfg)
		if err != nil {
			return nil, err
		}
		return pki.LoadCAFromFiles(cfg.Controller.PKI.CACert, keyPath)
	}
	certPEM, err := os.ReadFile(config.ExpandPath(cfg.Controller.PKI.CACert))
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", cfg.Controller.PKI.CACert, err)
	}
	keyPEM, err := keyRef.Resolve(provider)
	if err != nil {
		return nil, fmt.Errorf("resolve CA key: %w", err)
	}
	ca, err := pki.LoadCA(certPEM, []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	return ca, nil
}

func serve(cfg *config.ControllerConfig, ca *pki.CA) error {
	host := hostOf(cfg.Controller.Listen)
	advertiseHost := hostOf(cfg.Controller.Advertise) // "" when advertise unset
	serverKP, err := ca.IssueServerCert("wgfleet-controller", serverSANs(host, advertiseHost))
	if err != nil {
		return fmt.Errorf("issue server cert: %w", err)
	}
	tlsCfg, err := ca.ServerTLSConfig(serverKP)
	if err != nil {
		return fmt.Errorf("build server TLS: %w", err)
	}

	st, err := store.Open(cfg.Controller.Store)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	broker := keybroker.New(st, cfg.Fleet, slog.Default())
	svc := grpcapi.NewService(st, broker, slog.Default())
	server := grpcapi.NewServer(tlsCfg, svc)

	ln, err := net.Listen("tcp", cfg.Controller.Listen)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", cfg.Controller.Listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Staleness sweep: demote silent nodes to Degraded so the dashboard/metrics
	// reflect a dead agent. Disabled when staleness_after is negative.
	if threshold := cfg.Staleness(); threshold > 0 {
		sw := sweeper.New(st, threshold, slog.Default())
		go sw.Run(ctx, sweepInterval(threshold))
	}

	// Prometheus registry + collectors. Built before the provision manager so the
	// provisioning-duration histogram can be wired into it (the manager records
	// every apply-mode Provision through Options.OnProvision). The /metrics server
	// itself is started further down. nil when metrics are disabled.
	var (
		reg      *prometheus.Registry
		provMetr *metrics.ProvisionMetrics
	)
	if cfg.Controller.Metrics != "" {
		reg = metrics.NewRegistry()
		metrics.NewStoreCollector(reg, st)
		metrics.RegisterBuildInfo(reg, "controller", version.Version, version.Commit)
		provMetr = metrics.NewProvisionMetrics(reg)
	}

	// Web UI (read-only dashboard). Binds the mgmt/ZT address only — never expose
	// it on the public interface.
	// Provision manager: lets the Web UI SSH-bootstrap fleet nodes asynchronously.
	provMgr := provmgr.New(st, ca, cfg.Fleet, provmgr.Options{
		AgentBinPath:       cfg.Controller.AgentBin,
		ControllerEndpoint: controllerEndpoint(cfg.Controller),
		OnProvision:        provMetr.ObserveProvision, // method value on a nil *ProvisionMetrics is a safe no-op
	}, slog.Default())
	// Tie async provisioning jobs to the signal context so they abort on shutdown;
	// Wait() (below) drains them before the store is closed.
	provMgr.SetBaseContext(ctx)
	// Let the version gate auto-upgrade a too-old agent by pushing a fresh binary.
	svc.SetUpgradeTrigger(provMgr)

	var webSrv *http.Server
	if cfg.Controller.WebUI != "" {
		webHandler, err := web.New(st, broker, provMgr)
		if err != nil {
			return fmt.Errorf("build web ui: %w", err)
		}
		webSrv = &http.Server{Addr: cfg.Controller.WebUI, Handler: webHandler}
		go func() {
			if err := webSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("web ui server error", "err", err)
			}
		}()
	}

	// Prometheus /metrics — a scrape-time projection of the state store plus the
	// provisioning-duration histogram (registered above on reg). Binds the mgmt/ZT
	// address only.
	var metricsSrv *http.Server
	if cfg.Controller.Metrics != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler(reg))
		metricsSrv = &http.Server{Addr: cfg.Controller.Metrics, Handler: mux}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics server error", "err", err)
			}
		}()
	}

	slog.Info("controller serving",
		"version", version.Version,
		"commit", version.Commit,
		"wire", api.WireContractVersion,
		"listen", cfg.Controller.Listen,
		"webui", cfg.Controller.WebUI,
		"metrics", cfg.Controller.Metrics,
		"store", cfg.Controller.Store,
		"masters", len(cfg.Fleet.Masters),
		"exits", len(cfg.Fleet.Exits),
	)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()

	select {
	case <-ctx.Done():
		slog.Info("controller shutting down")
		server.GracefulStop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if webSrv != nil {
			_ = webSrv.Shutdown(shutdownCtx)
		}
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutdownCtx)
		}
		// Drain in-flight async provisioning jobs (ctx is already cancelled, so they
		// abort promptly) before the deferred st.Close() runs — otherwise a job
		// could write to a closed store.
		provMgr.Wait()
		return nil
	case err := <-serveErr:
		return fmt.Errorf("grpc serve: %w", err)
	}
}

func initCA(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("pki.ca_cert and a resolvable pki.ca_key path are required for --init-pki")
	}
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("CA cert %q already exists; refusing to overwrite", certPath)
	}
	ca, err := pki.NewCA("wgfleet-fleet-ca")
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	if err := pki.SaveCA(ca, certPath, keyPath); err != nil {
		return err
	}
	slog.Info("CA created", "cert", certPath, "key", keyPath)
	return nil
}

func issueNodeBundle(ca *pki.CA, nodeID, outDir string) error {
	if outDir == "" {
		outDir = filepath.Join("pki", nodeID)
	}
	if err := pki.WriteNodeBundle(ca, nodeID, outDir); err != nil {
		return err
	}
	slog.Info("node bundle issued", "node", nodeID, "dir", outDir)
	return nil
}

// caKeyPath resolves the CA private-key path from the pki.ca_key secret
// reference. Only the file:// scheme yields a usable path; other schemes are
// rejected here because the CA key must be a file the CA tooling can read/write.
func caKeyPath(cfg *config.ControllerConfig) (string, error) {
	raw := string(cfg.Controller.PKI.CAKey)
	switch {
	case raw == "":
		return "", fmt.Errorf("controller.pki.ca_key is required")
	case len(raw) > 7 && raw[:7] == "file://":
		return raw[7:], nil
	default:
		// Treat a bare value as a path for dev convenience.
		if cfg.Controller.PKI.CAKey.IsReference() {
			return "", fmt.Errorf("controller.pki.ca_key must be a file:// path for CA tooling, got a non-file reference")
		}
		return raw, nil
	}
}

// sweepInterval picks how often to run the staleness sweep: a fraction of the
// threshold, clamped to a sane range so it neither hammers the store nor lags.
func sweepInterval(threshold time.Duration) time.Duration {
	d := threshold / 3
	if d < 10*time.Second {
		d = 10 * time.Second
	}
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

func serverSANs(hosts ...string) []string {
	sans := []string{"localhost", "127.0.0.1"}
	seen := map[string]struct{}{"localhost": {}, "127.0.0.1": {}}
	for _, host := range hosts {
		if host == "" || host == "0.0.0.0" || host == "::" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		sans = append(sans, host)
	}
	return sans
}

// controllerEndpoint is the address agents dial to reach the controller: the
// advertised address when set (controller reachable through a NAT/gateway that
// differs from its bind), otherwise the bind address.
func controllerEndpoint(c config.ControllerSection) string {
	if c.Advertise != "" {
		return c.Advertise
	}
	return c.Listen
}

func hostOf(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
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
