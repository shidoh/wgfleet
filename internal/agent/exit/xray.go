package exit

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// --- REALITY/XHTTP inbound (xray, ADR-0025) ---

type xrayPlanner struct {
	configPath  string
	composePath string
	privateKey  string                 // REALITY x25519 private key (exit-local)
	up          func(file string) bool // nil ⇒ real `docker compose ps` probe
}

func (xrayPlanner) Component() string { return "reality inbound (xray)" }

func (p xrayPlanner) isUp(ctx context.Context) bool {
	if p.up == nil {
		return compose.StackUp(ctx, p.composePath)
	}
	return p.up(p.composePath)
}

func (p xrayPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.HasTransport(domain.TransportRealityXHTTP) || spec.Reality == nil {
		// Exit no longer runs the reality transport. If xray is still up (the operator
		// removed reality-xhttp from the transport set, or switched the node AWG-only),
		// stop the now-unused container so it does not linger listening; idempotent —
		// a no-op once it is down. Full file wipe happens on decommission (teardown.go).
		if p.isUp(ctx) {
			return []reconcile.Action{reconcile.ExecAction("stop reality inbound (transport disabled)",
				"docker", "compose", "-f", p.composePath, "down")}, nil
		}
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
		NetAdmin:   true, // exit freedom outbound sets SO_MARK for the WARP egress path
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
	case !p.isUp(ctx):
		actions = append(actions, reconcile.ExecAction("bring xray stack up (was down)",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	default:
		actions = append(actions, reconcile.NoChangeAction("reality inbound", "xray already up"))
	}
	return actions, nil
}
