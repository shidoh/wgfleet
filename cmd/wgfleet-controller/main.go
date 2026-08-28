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
	"golang.org/x/term"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/backup"
	"github.com/shidoh/wgfleet/internal/controller/grpcapi"
	"github.com/shidoh/wgfleet/internal/controller/keybroker"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/portal"
	"github.com/shidoh/wgfleet/internal/controller/provmgr"
	"github.com/shidoh/wgfleet/internal/controller/rollout"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/sweeper"
	"github.com/shidoh/wgfleet/internal/controller/web"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/metrics"
	"github.com/shidoh/wgfleet/internal/version"
)

func main() {
	if err := run(); err != nil {
		// --check-config has already printed its report; logging the error again
		// would bury it under a structured line the operator has to read past.
		if !errors.Is(err, errCheckFailed) {
			slog.Error("controller exited with error", "err", err)
		}
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
		rollingUp    = flag.Bool("rolling-upgrade", false, "roll every outdated EXIT agent forward one node at a time (reserve tier first), then exit")
		plan         = flag.Bool("plan", false, "with --provision/--upgrade-agent/--rolling-upgrade/--import-wg-easy/--restore: dry-run, show the plan and change nothing. It belongs to those subcommands only — on its own it is refused rather than ignored, because serving IS the controller's non-dry-run behaviour")
		agentBin     = flag.String("agent-bin", "", "with --provision/--upgrade-agent/--rolling-upgrade: path to the wgfleet-agent binary to install (default controller.agent_bin)")
		ctlEndpoint  = flag.String("controller-endpoint", "", "with --provision: controller mTLS endpoint the agent dials (default controller.listen)")
		backupOut    = flag.String("backup", "", "snapshot controller (+co-located master) state to an age-encrypted archive at this path, then exit")
		restoreIn    = flag.String("restore", "", "restore controller state from an age-encrypted archive at this path, then exit")
		ageRecipient = flag.String("age-recipient", "", "with --backup: encrypt to this age recipient instead of prompting for a passphrase")
		certs        = flag.String("certs", "", "certificate maintenance, then exit: `check-expiration` prints what this host holds and when it lapses; `renew` re-issues one node's certificate out of band (use with --node), for a node whose certificate has ALREADY expired and can therefore no longer renew itself")
		certsNode    = flag.String("node", "", "with --certs renew: the node to re-issue for")
		ageIdentity  = flag.String("age-identity", "", "with --restore: path to the age identity file for an archive encrypted to a recipient. Omit for a passphrase-encrypted archive, which age prompts for. An archive written with --age-recipient CANNOT be restored without this")
		supportBnd   = flag.Bool("support-bundle", false, "write a read-only diagnostic archive, then exit (requires --fleet)")
		fleetMode    = flag.Bool("fleet", false, "with --support-bundle: also render inventory from the store and walk every exit over SSH")
		supportNote  = flag.String("note", "", "with --support-bundle: free-form description of the problem, embedded in the bundle's manifest")
		showVersion  = flag.Bool("version", false, "print build version and exit")
		checkConfig  = flag.Bool("check-config", false, "validate the manifest and exit: 0 if it would start, 1 with the reasons if not. Changes nothing")
		setAdminPw   = flag.Bool("set-admin-password", false, "set/reset the web panel admin password (run with the controller stopped) and exit")
		importWGEasy = flag.String("import-wg-easy", "", "import the named master's wg-easy client credentials into the controller store, then exit. Safe to run with the controller live; use --plan first")
		wgEasyDB     = flag.String("wg-easy-db", "", "with --import-wg-easy: path to wg-easy's SQLite database (default /etc/wireguard/wg-easy.db, i.e. run this ON the master)")
		adminUser    = flag.String("admin-user", "admin", "username for --set-admin-password")
		passwordFile = flag.String("password-file", "", "with --set-admin-password: read the password from this file instead of prompting")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("wgfleet-controller", version.String())
		fmt.Printf("wire-contract version %d (serves v%d..v%d)\n",
			api.WireContractVersion, api.MinSupportedWire, api.WireContractVersion)
		return nil
	}

	setupLogging(*logFormat)

	// --check-config answers the question a restart otherwise answers destructively.
	// A manifest this binary refuses makes the controller exit at startup, and the
	// unit's Restart=on-failure/RestartSec=5 turns that into a crash loop of the
	// whole control plane. Validating first costs nothing and is the difference
	// between "the edit was wrong" and "the fleet has no control plane".
	//
	// It runs BEFORE the permission self-heal below and touches nothing: a check
	// that modifies the thing it checks is not a check.
	if *checkConfig {
		return checkManifest(*configPath)
	}

	cfg, err := config.Load(*configPath, &config.ControllerConfig{})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// --plan on its own used to fall through to serve(). Every subcommand consults it
	// and none of them was selected, so the flag that means "change nothing" started
	// the control plane: a port conflict on a live master, and a second unsupervised
	// controller on a stopped one. Refusing is the honest answer — there is no dry-run
	// of serving, and configuration.md's advice to "check the dry-run output after an
	// override change" was describing something that never existed.
	if *plan && !anySubcommand(*provision, *upgradeAgent, *importWGEasy, *restoreIn, *backupOut, *certs) && !*rollingUp {
		return fmt.Errorf("--plan is a modifier, not a command: pass it with --provision, --upgrade-agent, " +
			"--rolling-upgrade, --import-wg-easy or --restore. To check the manifest without starting anything, use --check-config")
	}
	if *certs != "" {
		switch *certs {
		case "check-expiration":
			return runCertsCheckExpiration(cfg)
		case "renew":
			provider, perr := config.NewSecretProvider(context.Background(), cfg)
			if perr != nil {
				return perr
			}
			return runCertsRenew(cfg, *certsNode, provider)
		default:
			return fmt.Errorf("--certs %q is not a thing to do (want check-expiration or renew)", *certs)
		}
	}
	// Self-heal the manifest mode: it carries WG/REALITY private keys and the wg-easy
	// admin password, so it must be owner-only. A hand-created or hand-edited
	// controller.yaml is easily left group/other-readable (a 2026-07-25 audit found it
	// 0644); tighten it best-effort on every startup rather than trusting every author.
	if err := os.Chmod(*configPath, 0o600); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not tighten manifest permissions to 0600", "path", *configPath, "err", err)
	}
	if *storePath != "" { // flag overrides file, per config-driven principle
		cfg.Controller.Store = *storePath
	}

	// Backup/restore operate on files (store db, CA, manifest, master state) and
	// do not need a loaded CA — handle them before the secret-provider/CA load.
	if *backupOut != "" {
		if err := runBackup(backup.DefaultSources(cfg, *configPath), *backupOut, *ageRecipient, nil); err != nil {
			return err
		}
		fmt.Printf("backup written to %s\n", *backupOut)
		return nil
	}
	if *restoreIn != "" {
		p, err := runRestore(context.Background(), *restoreIn, *plan, nil, *ageIdentity, int(api.WireContractVersion),
			controllerEndpoint(cfg.Controller), backup.AllowedDestsFor(backup.DefaultSources(cfg, *configPath)))
		if err != nil {
			return err
		}
		printRestorePlan(p, *plan)
		return nil
	}

	// --support-bundle --fleet needs only the store (best-effort) and the fleet
	// manifest already loaded above — not the mandatory CA load below, because a
	// broken/missing CA is itself something a bundle should help diagnose, not
	// something that should block producing one. It attempts the CA best-effort,
	// purely to widen Gate's secret set; see bestEffortCA and
	// gatherControllerSecrets.
	if *supportBnd {
		if !*fleetMode {
			return fmt.Errorf("--support-bundle on the controller requires --fleet (a non-fleet, single-node bundle is not implemented here; run wgfleet-agent --support-bundle on the co-located agent for that)")
		}
		return runFleetSupportBundle(cfg, bestEffortCA(cfg), *supportNote)
	}

	if *setAdminPw {
		st, err := store.Open(cfg.Controller.Store)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer st.Close()
		pw, err := readAdminPassword(*passwordFile)
		if err != nil {
			return err
		}
		if err := setAdminPassword(st, *adminUser, pw); err != nil {
			return err
		}
		fmt.Printf("admin password set for %q\n", *adminUser)
		return nil
	}

	if *importWGEasy != "" {
		st, err := store.Open(cfg.Controller.Store)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer st.Close()
		return runClientImport(context.Background(), st, cfg, *importWGEasy, *wgEasyDB, *plan)
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
	if *rollingUp {
		return rollingUpgrade(cfg, ca, *agentBin, *plan)
	}

	return serve(cfg, ca, provider, *configPath)
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

// resolveAWG3Key resolves fleet.awg3_key and refuses an unusable value whenever
// header protection is actually switched on.
func resolveAWG3Key(cfg *config.ControllerConfig, provider config.SecretProvider) (string, error) {
	key, err := cfg.Fleet.AWG3Key.Resolve(provider)
	if err != nil {
		return "", fmt.Errorf("resolve fleet.awg3_key: %w", err)
	}
	who := config.HeaderProtectionEnabledBy(*cfg)
	if len(who) == 0 {
		return key, nil // header protection off everywhere; nothing will ask for it
	}
	switch {
	case key == "":
		return "", fmt.Errorf("fleet.awg3_key resolved to an empty value, but header protection is enabled by %s — "+
			"check the reference actually points at a secret (an unset-but-present env var and an empty file both "+
			"resolve to nothing)", strings.Join(who, ", "))
	case len(key) < config.MinAWG3KeyLen:
		return "", fmt.Errorf("fleet.awg3_key resolved to %d bytes, but header protection is enabled by %s and "+
			"needs at least %d — generate one with `openssl rand -base64 48`",
			len(key), strings.Join(who, ", "), config.MinAWG3KeyLen)
	}
	return key, nil
}

func serve(cfg *config.ControllerConfig, ca *pki.CA, provider config.SecretProvider, configPath string) error {
	// The digest of the manifest this process actually loaded. Everything below
	// compares against it, so "is the controller running the file on disk" stops
	// being a question answered by trust.
	effective := &config.Effective{}
	if d, derr := config.DigestFile(configPath); derr == nil {
		effective.Set(d)
		if werr := config.WriteEffective(config.EffectiveFile, d, time.Now()); werr != nil {
			slog.Warn("could not record the effective manifest digest; a support bundle will not be able to report drift",
				"path", config.EffectiveFile, "err", werr)
		}
	} else {
		slog.Warn("could not digest the manifest; config drift will not be reported",
			"path", configPath, "err", derr)
	}

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

	// The 3.x header-protection secret, resolved once here rather than per render.
	//
	// Config validation refuses a missing REFERENCE; this refuses a reference that
	// resolves to nothing, which is a different and more dangerous state. An env var
	// set to the empty string, or an empty secret file, passes validation and then
	// yields HMAC keyed on "" — a header-protection key anyone holding this source
	// can recompute, silently, which is precisely the weakness the secret exists to
	// remove. The gate has to be on the VALUE.
	awg3Key, err := resolveAWG3Key(cfg, provider)
	if err != nil {
		return err
	}
	broker := keybroker.New(st, cfg.Fleet, slog.Default(), keybroker.WithAWG3Key(awg3Key))
	svc := grpcapi.NewService(st, broker, slog.Default())
	server := grpcapi.NewServer(tlsCfg, svc)

	ln, err := net.Listen("tcp", cfg.Controller.Listen)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", cfg.Controller.Listen, err)
	}

	// SIGHUP would otherwise terminate the process (Go's default), and the agent
	// catches it on every node — so the reflex is trained everywhere and fatal here.
	defer ignoreSIGHUP(slog.Default())()
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
		metrics.NewConfigCollector(reg, configPath, effective)
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
	// Agent-driven certificate renewal. The node asks over its still-valid mTLS
	// channel and gets a certificate for the identity that channel already proved;
	// there is no approval step because there is nothing left to decide. Without
	// this, node certificates simply run to expiry — one node per provisioning
	// anniversary, first visible as a node that stopped reporting.
	svc.SetCertSigner(ca)

	var webSrv *http.Server
	if cfg.Controller.WebUI != "" {
		persistTransport := func(exitName string, t domain.MasterTransport) error {
			if err := config.SetExitActiveTransport(configPath, exitName, t); err != nil {
				return err
			}
			// The controller just rewrote the manifest itself. Without re-recording the
			// digest this legitimate write would read as drift from here on, and a
			// signal that cries wolf after every transport switch is one nobody heeds.
			if d, derr := config.DigestFile(configPath); derr == nil {
				effective.Set(d)
				_ = config.WriteEffective(config.EffectiveFile, d, time.Now())
			} else {
				slog.Warn("manifest rewritten but could not re-digest it; drift may now read high",
					"path", configPath, "err", derr)
			}
			return nil
		}
		exportBackup := func(ctx context.Context, recipient string) ([]byte, error) {
			return backup.Export(ctx, backup.ExportOptions{
				Sources:     backup.DefaultSources(cfg, configPath),
				WireVersion: int(api.WireContractVersion),
				Encrypt:     backup.AgeEncryptor(recipient),
			})
		}
		webHandler, err := web.New(st, broker, provMgr, persistTransport, exportBackup, cfg.WebUISessionTTL())
		if err != nil {
			return fmt.Errorf("build web ui: %w", err)
		}
		// Fleet-wide rolling agent upgrade. One coordinator per process, so the UI
		// action and any concurrent attempt contend on the same single-rollout lock.
		// Bound to ctx: a rollout aborts (rolling back the node in flight) on SIGTERM
		// rather than outliving the store it reads.
		// The portal's public URL is deployment information the controller cannot
		// derive from its bind, and without it the client page has no link to show.
		webHandler.SetPortalBase(cfg.Controller.ClientPortalURL)
		webHandler.SetRoller(&webRoller{
			co:     rollout.New(provMgr, st, rollout.Config{}, slog.Default()),
			st:     st,
			fleet:  cfg.Fleet,
			binVer: &agentBinVersion{path: cfg.Controller.AgentBin},
			ctx:    ctx,
			log:    slog.Default(),
		})
		webSrv = &http.Server{Addr: cfg.Controller.WebUI, Handler: webHandler}
		go serveWithRetry("web ui", webSrv, slog.Default())
	}

	// Client self-service portal: a separate listener carrying only "your own
	// profile" (see internal/controller/portal for why it is not a page in the UI
	// above). Off unless the operator binds it.
	var portalSrv *http.Server
	if cfg.Controller.ClientPortal != "" {
		masters := func() []string {
			names := make([]string, 0, len(cfg.Fleet.Masters))
			for _, m := range cfg.Fleet.Masters {
				names = append(names, m.Name)
			}
			return names
		}
		portalHandler, err := portal.New(portalSource{st: st, broker: broker}, masters)
		if err != nil {
			return fmt.Errorf("build client portal: %w", err)
		}
		portalSrv = &http.Server{
			Addr:              cfg.Controller.ClientPortal,
			Handler:           portalHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go serveWithRetry("client portal", portalSrv, slog.Default())
	}

	// Prometheus /metrics — a scrape-time projection of the state store plus the
	// provisioning-duration histogram (registered above on reg). Binds the mgmt/ZT
	// address only.
	var metricsSrv *http.Server
	if cfg.Controller.Metrics != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler(reg))
		metricsSrv = &http.Server{Addr: cfg.Controller.Metrics, Handler: mux}
		go serveWithRetry("metrics", metricsSrv, slog.Default())
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
		if portalSrv != nil {
			_ = portalSrv.Shutdown(shutdownCtx)
		}
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

// setAdminPassword sets (or resets) the single web-panel admin credential
// directly in the store. It always rotates the session secret (logging out any
// active session). Intended for the --set-admin-password CLI path, which opens
// the store exclusively — run it with the controller STOPPED.
func setAdminPassword(st store.Store, username, password string) error {
	if len(password) < auth.MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", auth.MinPasswordLen)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	secret, err := auth.NewSecret()
	if err != nil {
		return fmt.Errorf("generate session secret: %w", err)
	}
	if err := st.SetAuthCredential(context.Background(), username, hash, secret); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	return nil
}

// readAdminPassword sources the password: --password-file, then
// WGFLEET_ADMIN_PASSWORD, then an interactive no-echo prompt.
func readAdminPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if env := os.Getenv("WGFLEET_ADMIN_PASSWORD"); env != "" {
		return strings.TrimRight(env, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "New admin password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(b), nil
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

// portalSource adapts the controller's store and keybroker to the portal's
// read-only view of the world.
type portalSource struct {
	st     store.Store
	broker *keybroker.Broker
}

func (s portalSource) GetNode(ctx context.Context, id string) (domain.Node, error) {
	return s.st.GetNode(ctx, id)
}

func (s portalSource) RenderNodeSpec(ctx context.Context, id string) (domain.NodeSpec, error) {
	return s.broker.RenderNodeSpec(ctx, id)
}

func (s portalSource) ListWGClients(ctx context.Context, id string) ([]domain.WGClient, error) {
	return s.broker.ListWGClients(ctx, id)
}

// anySubcommand reports whether any of these string flags selected a subcommand.
func anySubcommand(vals ...string) bool {
	for _, v := range vals {
		if v != "" {
			return true
		}
	}
	return false
}
