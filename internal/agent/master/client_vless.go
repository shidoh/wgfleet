package master

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// --- client-facing VLESS+REALITY+XHTTP inbound (xray) ---
//
// The master mirror of the exit's reality inbound: a VLESS+REALITY+XHTTP inbound
// serving END USERS (an alternative to the client AWG on DPI-throttled paths).
// Unlike the exit's, its outbound forwards decrypted traffic to mihomo's loopback
// SOCKS listener (not freedom→WARP), so VLESS clients share the AWG clients'
// routing. The container runs on the host network, so 127.0.0.1 reaches mihomo.

type clientVlessPlanner struct {
	configPath  string
	composePath string
	privateKey  string                 // master's client-facing REALITY x25519 private key
	up          func(file string) bool // nil ⇒ real `docker compose ps` probe
}

func (clientVlessPlanner) Component() string { return "client vless inbound (xray)" }

func (p clientVlessPlanner) isUp(ctx context.Context) bool {
	if p.up == nil {
		return compose.StackUp(ctx, p.composePath)
	}
	return p.up(p.composePath)
}

func (p clientVlessPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	cv := clientVLESSSpec(spec)
	if cv == nil {
		// The master does not run the client VLESS inbound. If xray is still up (the
		// operator disabled client_vless), stop the now-unused container; idempotent —
		// a no-op once it is down. Full file wipe happens on decommission.
		if p.isUp(ctx) {
			return []reconcile.Action{reconcile.ExecAction("stop client vless inbound (disabled)",
				"docker", "compose", "-f", p.composePath, "down")}, nil
		}
		return []reconcile.Action{reconcile.NoChangeAction("client vless inbound", "disabled")}, nil
	}
	if p.privateKey == "" {
		return []reconcile.Action{reconcile.NoChangeAction("client vless inbound",
			"pending: REALITY private key not yet available")}, nil
	}
	cfg, err := xray.RenderClientConfig(xray.ClientRenderInput{
		Spec:       *cv,
		PrivateKey: p.privateKey,
	})
	if err != nil {
		return nil, fmt.Errorf("render client vless inbound: %w", err)
	}
	composeYAML, err := compose.RenderXrayCompose(compose.XrayInput{
		Image:      cv.Image,
		ConfigPath: p.configPath,
		ListenPort: cv.ListenPort, // adds NET_BIND_SERVICE only if the operator chose a privileged port
	})
	if err != nil {
		return nil, fmt.Errorf("render client vless compose: %w", err)
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
		actions = append(actions, reconcile.ExecAction("bring client vless stack up",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	case cfgFile.Changes():
		// The clients list / camouflage changed (issue/revoke). A config restart is
		// cheap and only drops this inbound's connections, not the whole master stack.
		actions = append(actions, reconcile.ExecAction("restart client vless inbound",
			"docker", "compose", "-f", p.composePath, "restart", "xray"))
	case !p.isUp(ctx):
		actions = append(actions, reconcile.ExecAction("bring client vless stack up (was down)",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	default:
		actions = append(actions, reconcile.NoChangeAction("client vless inbound", "xray already up"))
	}
	return actions, nil
}

// clientVLESSSpec extracts the master's client-facing VLESS server spec from a
// NodeSpec, or nil when the node is not a master or the transport is disabled.
func clientVLESSSpec(spec domain.NodeSpec) *domain.ClientVLESSServerSpec {
	if spec.Master == nil {
		return nil
	}
	return spec.Master.ClientVLESS
}
