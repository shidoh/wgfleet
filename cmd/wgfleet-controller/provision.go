package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/provmgr"
	"github.com/shidoh/wgfleet/internal/controller/store"
)

type provisionOpts struct {
	node        string
	plan        bool
	agentBin    string
	ctlEndpoint string
}

// provisionNode SSH-bootstraps a fleet node from the CLI. It loads the CA and
// runs the provision manager (the same path the Web UI uses) in plan or apply
// mode synchronously.
func provisionNode(cfg *config.ControllerConfig, caKeyPath string, opts provisionOpts) error {
	ca, err := pki.LoadCAFromFiles(cfg.Controller.PKI.CACert, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA (run --init-pki first?): %w", err)
	}
	endpoint := opts.ctlEndpoint
	if endpoint == "" {
		endpoint = controllerEndpoint(cfg.Controller)
	}

	// Open the store so apply-mode provisioning persists the node's inventory
	// (mgmt_addr, public_ip) — the keybroker renders the master↔exit endpoint from
	// it. Plan mode does not write, but opening is cheap and keeps both paths the
	// same. (If a controller is already serving, sqlite WAL handles the brief
	// concurrent open of this one-shot.)
	st, err := store.Open(cfg.Controller.Store)
	if err != nil {
		return fmt.Errorf("open store %q: %w", cfg.Controller.Store, err)
	}
	defer func() { _ = st.Close() }()

	mgr := provmgr.New(st, ca, cfg.Fleet, provmgr.Options{
		AgentBinPath:       opts.agentBin,
		ControllerEndpoint: endpoint,
	}, slog.Default())

	mode := provisioner.ModeApply
	if opts.plan {
		mode = provisioner.ModePlan
	}
	report, err := mgr.Provision(context.Background(), opts.node, mode)
	if err != nil {
		return fmt.Errorf("provision %q: %w", opts.node, err)
	}
	if opts.plan {
		fmt.Print(report.String())
	} else {
		slog.Info("provisioning applied", "node", opts.node, "steps", len(report.Plan.Steps))
	}
	return nil
}
