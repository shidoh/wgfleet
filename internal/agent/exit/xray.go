package exit

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/agent/camoplan"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/camouflage"
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
	// gate says whether the node's own site is the REALITY target (ADR-0039).
	gate *camouflage.Gate
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
	var cfg string
	if b := spec.Reality.Bridge; b != nil {
		// Exit-initiated (ADR-0038): xray dials every master's portal and listens on
		// nothing. With no master ready there is nothing to dial — stop rather than
		// fall back to listening, which is the flow the filter kills.
		if len(b.Portals) == 0 {
			if p.isUp(ctx) {
				return []reconcile.Action{reconcile.ExecAction("stop reality bridge (no master ready to dial)",
					"docker", "compose", "-f", p.composePath, "down")}, nil
			}
			return []reconcile.Action{reconcile.NoChangeAction("reality bridge", "no master ready to dial")}, nil
		}
		// Validated here so one bad portal keeps the last-good bridge running.
		if err := b.Validate(); err != nil {
			return []reconcile.Action{reconcile.NoChangeAction("reality bridge",
				"spec rejected, keeping the last-good bridge: "+err.Error())}, nil
		}
		rendered, err := xray.RenderBridgeConfig(xray.BridgeRenderInput{Spec: *spec.Reality, EgressMark: xray.EgressMark})
		if err != nil {
			return nil, fmt.Errorf("render reality bridge: %w", err)
		}
		cfg = rendered
	} else {
		if p.privateKey == "" {
			return []reconcile.Action{reconcile.NoChangeAction("reality inbound",
				"pending: REALITY private key not yet available")}, nil
		}
		rendered, err := xray.RenderConfig(xray.RenderInput{
			Spec:       *spec.Reality,
			PrivateKey: p.privateKey,
			EgressMark: xray.EgressMark,
			Camouflage: camoplan.XrayCamouflage(p.gate, spec.Camouflage),
		})
		if err != nil {
			return nil, fmt.Errorf("render reality inbound: %w", err)
		}
		cfg = rendered
	}
	composeYAML, err := compose.RenderXrayCompose(compose.XrayInput{
		Image:      spec.Reality.Image,
		ConfigPath: p.configPath,
		NetAdmin:   true,                    // exit freedom outbound sets SO_MARK for the WARP egress path
		ListenPort: spec.Reality.ListenPort, // 443 is privileged → needs NET_BIND_SERVICE
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
	case composeFile.Changes() || !reconcile.ComposeApplied(p.composePath, []byte(composeYAML)):
		// Also a file no `up -d` ever applied (killed mid-pass, image not pulled):
		// the running containers may still be the previous definition.
		actions = append(actions, reconcile.ComposeUpAction("bring xray stack up", p.composePath, []byte(composeYAML)))
		if cfgFile.Changes() && !composeFile.Changes() && p.isUp(ctx) {
			// An unchanged definition makes `up -d` a no-op for a running container,
			// so it would not reread the config. A stopped one starts with it.
			actions = append(actions, reconcile.ExecAction("restart reality inbound",
				"docker", "compose", "-f", p.composePath, "restart", "xray"))
		}
	case cfgFile.Changes() && p.isUp(ctx):
		// Only a running container: compose restart leaves a stopped one stopped,
		// and the case below brings it up instead.
		actions = append(actions, reconcile.ExecAction("restart reality inbound",
			"docker", "compose", "-f", p.composePath, "restart", "xray"))
	case !p.isUp(ctx):
		actions = append(actions, reconcile.ComposeUpAction("bring xray stack up (was down)", p.composePath, []byte(composeYAML)))
	default:
		actions = append(actions, reconcile.NoChangeAction("reality inbound", "xray already up"))
	}
	return actions, nil
}
