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

// provisionNode SSH-bootstraps a fleet node from the CLI. It runs the provision
// manager (the same path the Web UI uses) in plan or apply mode synchronously.
func provisionNode(cfg *config.ControllerConfig, ca *pki.CA, opts provisionOpts) error {
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

// upgradeAgentNode rolls a node's agent binary forward in place (upload +
// restart) over SSH from the CLI, in plan or apply mode. The binary comes from
// --agent-bin or, when unset, controller.agent_bin.
func upgradeAgentNode(cfg *config.ControllerConfig, ca *pki.CA, node, agentBin string, plan bool) error {
	if agentBin == "" {
		agentBin = cfg.Controller.AgentBin
	}

	st, err := store.Open(cfg.Controller.Store)
	if err != nil {
		return fmt.Errorf("open store %q: %w", cfg.Controller.Store, err)
	}
	defer func() { _ = st.Close() }()

	mgr := provmgr.New(st, ca, cfg.Fleet, provmgr.Options{AgentBinPath: agentBin}, slog.Default())

	mode := provisioner.ModeApply
	if plan {
		mode = provisioner.ModePlan
	}
	report, err := mgr.UpgradeAgent(context.Background(), node, mode)
	if err != nil {
		return fmt.Errorf("upgrade %q: %w", node, err)
	}
	if plan {
		fmt.Print(report.String())
	} else {
		slog.Info("agent upgrade applied", "node", node, "steps", len(report.Plan.Steps))
	}
	return nil
}
