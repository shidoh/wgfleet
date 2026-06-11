package master

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// Input is everything the master planners need beyond the NodeSpec. PrivateKey
// is the master's WireGuard key (real persisted key in apply mode, ephemeral in
// plan mode), shared across all mihomo exit-tunnel proxies.
type Input struct {
	Paths      Paths
	PrivateKey string
	// ClientInterface / EgressInterface are the host interfaces the NAT rules
	// reference. Defaults are applied when empty.
	ClientInterface string
	EgressInterface string
}

const (
	defaultClientInterface = "wg0"
	defaultEgressInterface = "ens3"
)

// Planners returns the ordered master reconcilers: mihomo config + its included
// files + operator extra files, then the NAT rules that wire clients into mihomo.
func Planners(in Input) []reconcile.Planner {
	if in.ClientInterface == "" {
		in.ClientInterface = defaultClientInterface
	}
	if in.EgressInterface == "" {
		in.EgressInterface = defaultEgressInterface
	}
	return []reconcile.Planner{
		composePlanner{path: in.Paths.Compose},
		wgEasyPlanner{dbPath: in.Paths.WGEasyDB, iface: wgeasy.DefaultInterface, compose: in.Paths.Compose},
		mihomoPlanner{paths: in.Paths, privateKey: in.PrivateKey},
		extraFilesPlanner{dir: in.Paths.ExtraFilesDir},
		masterNATPlanner{path: in.Paths.NFT, clientIface: in.ClientInterface, egressIface: in.EgressInterface},
	}
}

// composeStart is the idempotent "bring the stack up" action: docker compose up
// -d is a no-op when nothing changed.
func composeStart(file string) reconcile.Action {
	return reconcile.ExecAction("ensure the container stack is up",
		"docker", "compose", "-f", file, "up", "-d")
}

func composeRestart(file, service string) reconcile.Action {
	return reconcile.ExecAction("restart "+service,
		"docker", "compose", "-f", file, "restart", service)
}

// --- container stack (docker-compose.yml + up -d) ---

type composePlanner struct{ path string }

func (composePlanner) Component() string { return "container stack (docker compose)" }

func (p composePlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("compose: node has no master spec")
	}
	yamlText, err := compose.RenderMasterCompose(compose.RenderInput{
		Compose:          spec.Master.Compose,
		ClientListenPort: spec.WGServer.ListenPort,
		ClientPool:       spec.WGServer.AddressPool,
		MgmtAddr:         masterMgmtAddr(spec),
	})
	if err != nil {
		return nil, err
	}
	file, err := reconcile.FileAction(p.path, []byte(yamlText), 0o644, nil)
	if err != nil {
		return nil, err
	}
	// Always ensure the stack is up (idempotent); a compose-file change pulls
	// the new definition on the same up -d.
	return []reconcile.Action{file, composeStart(p.path)}, nil
}

// masterMgmtAddr derives the master's mgmt address from the Clash external
// controller (host:9090) so the compose render can bind wg-easy's UI to it.
func masterMgmtAddr(spec domain.NodeSpec) string {
	ec := spec.Master.ExternalController
	if i := indexByte(ec, ':'); i > 0 {
		return ec[:i]
	}
	return ec
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// --- wg-easy client-facing AWG obfuscation (SQLite-backed, ADR-0008) ---

type wgEasyPlanner struct {
	dbPath  string
	iface   string
	compose string
}

func (wgEasyPlanner) Component() string { return "wg-easy client AWG" }

func (p wgEasyPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.WGServer.AWG == nil {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy AWG", "no client AWG params")}, nil
	}
	desired := wgeasy.ColumnsFromParams(*spec.WGServer.AWG)
	display := wgeasy.RenderUpdateSQL(p.iface, desired)

	// wg-easy must be set up first; if its DB is absent, surface a pending notice
	// rather than failing the whole pass (the DB appears once wg-easy runs).
	if _, err := os.Stat(p.dbPath); os.IsNotExist(err) {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy AWG",
			"pending: wg-easy DB not found at "+p.dbPath+" (set up wg-easy first)")}, nil
	}

	current, found, err := wgeasy.ReadAWG(ctx, p.dbPath, p.iface)
	if err != nil {
		return nil, err
	}
	if !found {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy AWG",
			"pending: wg-easy interface row not created yet")}, nil
	}
	if current == desired {
		return []reconcile.Action{reconcile.NoChangeAction("wg-easy AWG", "interface obfuscation already current")}, nil
	}

	dbPath, iface := p.dbPath, p.iface
	update := reconcile.CustomAction(reconcile.ActionUpdate, "wg-easy interface AWG",
		"set client-facing obfuscation in wg-easy DB", display,
		func(ctx context.Context) error { return wgeasy.UpdateAWG(ctx, dbPath, iface, desired) })

	// wg-easy regenerates its .conf from the DB on (re)start.
	return []reconcile.Action{update, composeRestart(p.compose, "wg-easy")}, nil
}

// --- mihomo config + included direct-networks ---

type mihomoPlanner struct {
	paths      Paths
	privateKey string
}

func (mihomoPlanner) Component() string { return "mihomo (data plane)" }

func (p mihomoPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo: node has no master spec")
	}
	cfg, err := mihomo.RenderConfig(mihomo.RenderInput{Spec: *spec.Master, PrivateKey: p.privateKey})
	if err != nil {
		return nil, err
	}
	configAction, err := reconcile.FileAction(p.paths.MihomoConfig, []byte(cfg), 0o644, mihomo.RedactConfig)
	if err != nil {
		return nil, err
	}

	direct, err := mihomo.RenderDirectNetworks(*spec.Master)
	if err != nil {
		return nil, err
	}
	directAction, err := reconcile.FileAction(p.paths.DirectNetworks, []byte(direct), 0o644, nil)
	if err != nil {
		return nil, err
	}

	actions := []reconcile.Action{configAction, directAction}
	// Restart the mihomo container only when its config changed.
	if configAction.Changes() || directAction.Changes() {
		actions = append(actions, composeRestart(p.paths.Compose, "mihomo"))
	} else {
		actions = append(actions, reconcile.NoChangeAction("mihomo", "config already current"))
	}
	return actions, nil
}

// --- operator extra files (CustomConfig.Files) ---

type extraFilesPlanner struct{ dir string }

func (extraFilesPlanner) Component() string { return "mihomo extra files" }

func (p extraFilesPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil || len(spec.Master.Custom.Files) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("extra files", "none")}, nil
	}
	var actions []reconcile.Action
	for _, f := range spec.Master.Custom.Files {
		target := f.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(p.dir, target)
		}
		var redact reconcile.Redactor
		if f.Secret {
			redact = func(string) string { return "<redacted: operator secret file>" }
		}
		a, err := reconcile.FileAction(target, []byte(f.Content), 0o644, redact)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}
	return actions, nil
}

// --- master NAT (DNAT clients → mihomo, MASQUERADE, drop QUIC) ---

type masterNATPlanner struct {
	path        string
	clientIface string
	egressIface string
}

func (masterNATPlanner) Component() string { return "master NAT (nftables)" }

func (p masterNATPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("master NAT: node has no master spec")
	}
	redir := spec.Master.RedirPort
	if redir == 0 {
		redir = mihomo.DefaultRedirPort
	}
	ruleset, err := netfw.RenderMasterNAT(netfw.MasterNATInput{
		ClientInterface: p.clientIface,
		ClientCIDR:      spec.WGServer.AddressPool,
		RedirAddr:       fmt.Sprintf("%s:%d", spec.Master.BindAddress, redir),
		EgressInterface: p.egressIface,
		PrivateCIDRs:    spec.Master.DirectCIDRs,
	})
	if err != nil {
		return nil, err
	}
	file, err := reconcile.FileAction(p.path, []byte(ruleset), 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}
	if file.Changes() {
		actions = append(actions, reconcile.ExecAction("apply master NAT atomically", "nft", "-f", p.path))
	} else {
		actions = append(actions, reconcile.NoChangeAction("nft -f", "ruleset already loaded"))
	}
	return actions, nil
}
