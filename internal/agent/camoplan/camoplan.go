// Package camoplan runs a node's own-domain camouflage site (ADR-0039) and
// decides, through the agent's camouflage.Gate, whether the node's REALITY
// inbounds use it as their target. Shared by both roles: a master's client
// inbound and portal and an exit's inbound read the same gate.
package camoplan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/camouflage"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

const component = "camouflage site (caddy)"

// Paths is where the site lives on the node.
type Paths struct {
	Dir  string // compose file, Caddyfile, page, Caddy's autosave dir, gate state
	Data string // certificate storage; survives a stop and a re-enable
}

// DefaultPaths are the production locations.
func DefaultPaths() Paths {
	return Paths{Dir: "/etc/wgfleet/camouflage", Data: "/var/lib/wgfleet/camouflage"}
}

// PathsUnder roots the site under dir (dev runs, tests).
func PathsUnder(dir string) Paths {
	return Paths{Dir: filepath.Join(dir, "camouflage"), Data: filepath.Join(dir, "camouflage-data")}
}

func (p Paths) compose() string   { return filepath.Join(p.Dir, "docker-compose.yml") }
func (p Paths) caddyfile() string { return filepath.Join(p.Dir, "Caddyfile") }
func (p Paths) siteDir() string   { return filepath.Join(p.Dir, "site") }
func (p Paths) configDir() string { return filepath.Join(p.Dir, "config") }

// StatePath is where the gate persists its decision.
func (p Paths) StatePath() string { return filepath.Join(p.Dir, "active") }

// Planner reconciles the site and evaluates the gate once per pass. It runs
// before the planners that render REALITY inbounds, so they read this pass's
// decision.
type Planner struct {
	Paths Paths
	Gate  *camouflage.Gate
	// Up reports whether the compose stack runs; nil ⇒ `docker compose ps`.
	Up func(ctx context.Context, file string) bool
	// Inspect finds a container named compose.CamouflageContainer: its compose
	// file (empty when compose did not start it) and the host path of its /data.
	// nil ⇒ `docker inspect`.
	Inspect func(ctx context.Context) (configFile, dataDir string, found bool)
	// Probe overrides the site probe (tests); nil ⇒ a real camouflage.Prober.
	Probe func(ctx context.Context, s domain.CamouflageSpec) camouflage.Result
	// PortHolder names what listens on a TCP port; nil ⇒ `ss`.
	PortHolder func(ctx context.Context, port int) string
}

// Component implements reconcile.Planner.
func (Planner) Component() string { return component }

func (p Planner) up(ctx context.Context) bool {
	if p.Up == nil {
		return compose.StackUp(ctx, p.Paths.compose())
	}
	return p.Up(ctx, p.Paths.compose())
}

// Plan implements reconcile.Planner.
func (p Planner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if p.Gate == nil {
		p.Gate = camouflage.NewGate("") // no agent-owned gate: decide this pass alone
	}
	if p.Paths.Dir == "" {
		return []reconcile.Action{reconcile.NoChangeAction(component, "no site directory configured")}, nil
	}
	c := spec.Camouflage
	if c == nil {
		if _, err := p.Gate.Observe(nil, camouflage.Result{}); err != nil {
			return nil, err
		}
		return p.planOff(ctx), nil
	}
	if err := c.Validate(); err != nil {
		return []reconcile.Action{reconcile.NoChangeAction(component,
			"spec rejected, keeping the last-good site: "+err.Error())}, nil
	}
	actions, err := p.planSite(ctx, spec, *c)
	if err != nil {
		return nil, err
	}
	return append(actions, p.evaluate(ctx, *c)), nil
}

// planOff stops a site the spec no longer asks for. Its certificate storage
// stays: turning camouflage back on must not cost a new certificate.
func (p Planner) planOff(ctx context.Context) []reconcile.Action {
	if _, err := os.Stat(p.Paths.compose()); err != nil {
		return []reconcile.Action{reconcile.NoChangeAction(component, "not used")}
	}
	if p.up(ctx) {
		return []reconcile.Action{reconcile.ExecAction("stop camouflage site (camouflage off)",
			"docker", "compose", "-f", p.Paths.compose(), "down")}
	}
	return []reconcile.Action{reconcile.NoChangeAction(component, "not used")}
}

func (p Planner) planSite(ctx context.Context, spec domain.NodeSpec, c domain.CamouflageSpec) ([]reconcile.Action, error) {
	caddyfile, err := camouflage.RenderCaddyfile(camouflage.CaddyInput{Spec: c, HTTPSOn443: realityOn443(spec)})
	if err != nil {
		return nil, fmt.Errorf("render camouflage Caddyfile: %w", err)
	}
	composeYAML, err := compose.RenderCamouflageCompose(compose.CamouflageInput{
		Image: c.Image, Caddyfile: p.Paths.caddyfile(), SiteDir: p.Paths.siteDir(),
		DataDir: p.Paths.Data, ConfigDir: p.Paths.configDir(),
	})
	if err != nil {
		return nil, fmt.Errorf("render camouflage compose: %w", err)
	}
	page, err := reconcile.FileAction(filepath.Join(p.Paths.siteDir(), "index.html"), []byte(camouflage.IndexHTML(c.Domain)), 0o644, nil)
	if err != nil {
		return nil, err
	}
	cfgFile, err := reconcile.FileAction(p.Paths.caddyfile(), []byte(caddyfile), 0o644, nil)
	if err != nil {
		return nil, err
	}
	composeFile, err := reconcile.FileAction(p.Paths.compose(), []byte(composeYAML), 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{page, cfgFile, composeFile}
	if a, ok := p.dirsAction(); ok {
		actions = append(actions, a)
	}
	if a, ok := p.adoptAction(ctx); ok {
		actions = append(actions, a)
	}
	up := p.up(ctx)
	switch {
	case composeFile.Changes() || !reconcile.ComposeApplied(p.Paths.compose(), []byte(composeYAML)):
		actions = append(actions, reconcile.ComposeUpAction("bring camouflage site up", p.Paths.compose(), []byte(composeYAML)))
		if cfgFile.Changes() && !composeFile.Changes() && up {
			actions = append(actions, restartAction(p.Paths.compose()))
		}
	case cfgFile.Changes() && up:
		// Caddy runs without its admin API, so a new Caddyfile needs a restart.
		// Live REALITY sessions survive it; new ones wait about a second.
		actions = append(actions, restartAction(p.Paths.compose()))
	case !up:
		actions = append(actions, reconcile.ComposeUpAction("bring camouflage site up (was down)", p.Paths.compose(), []byte(composeYAML)))
	default:
		actions = append(actions, reconcile.NoChangeAction(component, "camouflage site already up"))
	}
	return actions, nil
}

func restartAction(file string) reconcile.Action {
	return reconcile.ExecAction("restart camouflage site (new Caddyfile)", "docker", "compose", "-f", file, "restart", "caddy")
}

// dirsAction creates the mount sources docker would otherwise create as root-owned
// empty directories on its own — harmless, but then nothing records them.
func (p Planner) dirsAction() (reconcile.Action, bool) {
	var missing []string
	for _, d := range []string{p.Paths.Data, p.Paths.configDir()} {
		if _, err := os.Stat(d); err != nil {
			missing = append(missing, d)
		}
	}
	if len(missing) == 0 {
		return reconcile.Action{}, false
	}
	return reconcile.CustomAction(reconcile.ActionExec, "mkdir", "create camouflage directories",
		"mkdir -p "+strings.Join(missing, " "), func(context.Context) error {
			for _, d := range missing {
				if err := os.MkdirAll(d, 0o700); err != nil {
					return fmt.Errorf("mkdir %s: %w", d, err)
				}
			}
			return nil
		}), true
}

// adoptAction takes over a container named like the managed one that compose did
// not start from our file — a site built by hand before this feature existed. Its
// certificates move into the managed storage when that is still empty, so the
// node keeps its certificate instead of asking the CA for a new one, and the
// container goes, freeing the name and the ports.
func (p Planner) adoptAction(ctx context.Context) (reconcile.Action, bool) {
	inspect := p.Inspect
	if inspect == nil {
		inspect = dockerInspect
	}
	cfgFile, dataDir, found := inspect(ctx)
	if !found || slices.Contains(strings.Split(cfgFile, ","), p.Paths.compose()) {
		return reconcile.Action{}, false
	}
	copyData := dataDir != "" && dataDir != p.Paths.Data && storageEmpty(p.Paths.Data)
	display := "docker rm -f " + compose.CamouflageContainer
	if copyData {
		display = "cp -a " + dataDir + "/. " + p.Paths.Data + "/ && " + display
	}
	return reconcile.CustomAction(reconcile.ActionExec, "docker", "adopt the hand-built camouflage container",
		display, func(ctx context.Context) error {
			if copyData {
				if err := os.MkdirAll(p.Paths.Data, 0o700); err != nil {
					return fmt.Errorf("mkdir %s: %w", p.Paths.Data, err)
				}
				if out, err := exec.CommandContext(ctx, "cp", "-a", dataDir+"/.", p.Paths.Data+"/").CombinedOutput(); err != nil {
					return fmt.Errorf("copy certificates from %s: %w: %s", dataDir, err, strings.TrimSpace(string(out)))
				}
			}
			if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", compose.CamouflageContainer).CombinedOutput(); err != nil {
				return fmt.Errorf("remove %s: %w: %s", compose.CamouflageContainer, err, strings.TrimSpace(string(out)))
			}
			return nil
		}), true
}

// storageEmpty reports whether Caddy has stored nothing under dir yet.
func storageEmpty(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "caddy"))
	return err != nil
}

func dockerInspect(ctx context.Context) (string, string, bool) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format",
		`{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}`,
		compose.CamouflageContainer).Output()
	if err != nil {
		return "", "", false
	}
	cfg, data, _ := strings.Cut(strings.TrimSpace(string(out)), "|")
	return cfg, data, true
}

// evaluate probes the site and feeds the gate. The verdict is reported as a
// no-op action so a dry run shows it.
func (p Planner) evaluate(ctx context.Context, c domain.CamouflageSpec) reconcile.Action {
	var r camouflage.Result
	if p.Probe != nil {
		r = p.Probe(ctx, c)
	} else {
		pr := camouflage.Prober{}
		if c.ACMECA == domain.CamouflageCAInternal {
			pr.RootsFile = camouflage.LocalCARoot(p.Paths.Data)
		}
		r = pr.Probe(ctx, c)
	}
	if !r.TLSOK {
		if who := p.holder(ctx, 80); who != "" {
			r.Reason += "; TCP/80 is held by " + who
		}
	}
	changed, err := p.Gate.Observe(&c, r)
	verdict := "target: the fleet default"
	if p.Gate.ActiveDomain() == c.Domain {
		verdict = "target: the own site " + c.LocalTarget()
	}
	if changed {
		verdict = "switched — " + verdict
	}
	if r.Reason != "" {
		verdict += " (" + r.Reason + ")"
	}
	if err != nil {
		verdict += "; " + err.Error()
	}
	return reconcile.NoChangeAction("camouflage gate", verdict)
}

// holder names the process on a TCP port unless it is our Caddy.
func (p Planner) holder(ctx context.Context, port int) string {
	f := p.PortHolder
	if f == nil {
		f = ssHolder
	}
	who := f(ctx, port)
	if strings.Contains(who, "caddy") {
		return ""
	}
	return who
}

func ssHolder(ctx context.Context, port int) string {
	out, err := exec.CommandContext(ctx, "ss", "-Htlnp", fmt.Sprintf("sport = :%d", port)).Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if _, users, ok := strings.Cut(line, "users:"); ok {
		return strings.TrimSpace(users)
	}
	return ""
}

// realityOn443 reports whether a REALITY inbound on the node listens on public
// TCP/443 — its probes reach the site, so port 80 may redirect there.
func realityOn443(spec domain.NodeSpec) bool {
	if r := spec.Reality; r != nil && r.Bridge == nil && r.ListenPort == 443 {
		return true
	}
	if m := spec.Master; m != nil {
		if m.ClientVLESS != nil && m.ClientVLESS.ListenPort == 443 {
			return true
		}
		if m.RealityPortal != nil && m.RealityPortal.ListenPort == 443 {
			return true
		}
	}
	return false
}

// XrayCamouflage is the switch the REALITY inbound renderers take from the gate:
// nil when the node has no camouflage.
func XrayCamouflage(g *camouflage.Gate, spec *domain.CamouflageSpec) *xray.Camouflage {
	if spec == nil || spec.Validate() != nil {
		return nil // a rejected spec changes no inbound
	}
	d, target := g.Target(spec)
	if d == "" {
		return nil
	}
	return &xray.Camouflage{Domain: d, Target: target}
}

// Teardown stops the site and removes it, certificates included, when the node
// is decommissioned. Best-effort, like every teardown step.
func Teardown(p Paths) reconcile.Planner { return teardown{paths: p} }

type teardown struct{ paths Paths }

func (teardown) Component() string { return "camouflage site teardown" }

func (t teardown) Plan(context.Context, domain.NodeSpec) ([]reconcile.Action, error) {
	if _, err := os.Stat(t.paths.compose()); err != nil {
		return []reconcile.Action{reconcile.NoChangeAction(component, "no site on this node")}, nil
	}
	return []reconcile.Action{
		reconcile.BestEffortExecAction("stop camouflage site", "docker", "compose", "-f", t.paths.compose(), "down"),
		reconcile.BestEffortExecAction("remove camouflage site", "rm", "-rf", t.paths.Dir, t.paths.Data),
	}, nil
}
