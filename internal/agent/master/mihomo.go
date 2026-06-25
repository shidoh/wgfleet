package master

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
)

// --- mihomo config + included direct-networks ---

type mihomoPlanner struct {
	paths      Paths
	privateKey string
	// reload hot-applies the config via the Clash API (nil ⇒ the real mihomo.Reload);
	// injected in tests. Preferred over a container restart so a routine change like
	// draining one exit does not drop every client's connection.
	reload func(ctx context.Context, controllerAddr, secret string, cfgYAML []byte) error
	// restart bounces the container (nil ⇒ real `docker compose restart mihomo`);
	// injected in tests. Used when a wireguard-proxy change can't be hot-reloaded.
	restart func(ctx context.Context) error
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
	// Snapshot the on-disk config BEFORE the FileAction overwrites it, so we can tell
	// whether the wireguard proxies (AmneziaWG params) changed and a hot reload would
	// silently no-op (see applyConfigAction / mihomo.ProxiesChanged).
	oldCfg, _ := os.ReadFile(p.paths.MihomoConfig)
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
	if configAction.Changes() || directAction.Changes() {
		// A wireguard-proxy change (AmneziaWG params/keys/endpoint/MTU) needs a full
		// container restart — a Clash API hot reload does not re-init the proxy's
		// device. Routine changes (drain, rules, DNS, direct-networks) hot-reload so
		// existing client connections survive.
		forceRestart := mihomo.ProxiesChanged(oldCfg, []byte(cfg))
		actions = append(actions, p.applyConfigAction(spec, []byte(cfg), forceRestart))
	} else {
		actions = append(actions, reconcile.NoChangeAction("mihomo", "config already current"))
	}
	return actions, nil
}

// applyConfigAction makes a running mihomo pick up the freshly written config. It
// prefers an in-process hot reload via the Clash API (no container restart, so
// existing client connections survive — draining one exit must not disconnect
// everyone), and falls back to `docker compose restart mihomo` only when the API is
// unreachable (mihomo down / mid-start). A config the controller actively REJECTS is
// surfaced as an error WITHOUT a restart, so the previous good config keeps running.
func (p mihomoPlanner) applyConfigAction(spec domain.NodeSpec, cfgYAML []byte, forceRestart bool) reconcile.Action {
	reload := p.reload
	if reload == nil {
		reload = mihomo.Reload
	}
	addr := spec.Master.ExternalController
	secret := clashSecret(spec.Master)
	compose := p.paths.Compose

	restart := p.restart
	if restart == nil {
		restart = func(ctx context.Context) error {
			c := exec.CommandContext(ctx, "docker", "compose", "-f", compose, "restart", "mihomo")
			if out, rerr := c.CombinedOutput(); rerr != nil {
				return fmt.Errorf("mihomo restart failed: %w: %s", rerr, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}

	// A wireguard-proxy change must restart the container: a hot reload cannot
	// re-init an existing AmneziaWG device, so new S/H params silently never apply.
	if forceRestart {
		return reconcile.CustomAction(reconcile.ActionUpdate, "mihomo",
			"restart mihomo (wireguard-proxy AmneziaWG params changed — hot reload can't re-init the device)",
			"docker compose restart mihomo", restart)
	}

	display := fmt.Sprintf("PUT http://%s/configs (hot reload; fallback: docker compose restart mihomo)",
		orPlaceholder(addr, "<external-controller>"))
	apply := func(ctx context.Context) error {
		err := reload(ctx, addr, secret, cfgYAML)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, mihomo.ErrUnreachable):
			// Not reachable (down / mid-start): restart so it reads the fresh file.
			// Heavier (drops connections) but rare — the compose planner already
			// brought the stack up earlier in the same pass.
			if rerr := restart(ctx); rerr != nil {
				return fmt.Errorf("mihomo reload unreachable (%v) and %w", err, rerr)
			}
			return nil
		default:
			// Reachable but rejected the config: leave the old config running.
			return err
		}
	}
	return reconcile.CustomAction(reconcile.ActionUpdate, "mihomo",
		"reload mihomo config in place (Clash API; existing connections preserved)", display, apply)
}

// clashSecret extracts the Clash API secret from the operator's mihomo overrides
// (where it is configured), so the agent can authenticate its reload call. Empty
// when no secret is set (the API is then bound to mgmt only and unauthenticated).
func clashSecret(ms *domain.MasterSpec) string {
	if ms == nil || ms.Custom.Overrides == nil {
		return ""
	}
	if s, ok := ms.Custom.Overrides["secret"].(string); ok {
		return s
	}
	return ""
}

func orPlaceholder(s, placeholder string) string {
	if s == "" {
		return placeholder
	}
	return s
}

// --- mihomo redirect-listener self-heal ---

// mihomoRedirPlanner verifies that mihomo is actually listening on its transparent
// redirect port (<BindAddress>:<RedirPort>) — the target masterNATPlanner DNATs all
// client TCP to. mihomo binds that listener to the client gateway IP (e.g.
// 10.73.0.1, the wg0 address); if the client interface is recreated under a running
// mihomo (a wg-easy restart flaps the address), mihomo silently loses the bind and
// does NOT re-bind on its own. The container still reports "up" and its config is
// unchanged, so neither composePlanner nor mihomoPlanner notices — but every DNAT'd
// client TCP connection now black-holes (pings and the WG handshake keep working,
// which makes it look healthy). When the listener is down we restart mihomo to
// rebind. Guarded by a local-address check so we never thrash while wg0 itself is
// still down (the wg-easy/compose planners bring it back first).
type mihomoRedirPlanner struct {
	compose string
	// listening reports whether a TCP socket is LISTENing on addr; nil ⇒ a passive
	// socket-table read (socketListening). It must never open a connection to addr.
	listening func(addr string) bool
	// localUp reports whether host is assigned to a local interface; nil ⇒ real check.
	localUp func(host string) bool
}

func (mihomoRedirPlanner) Component() string { return "mihomo redirect listener" }

func (p mihomoRedirPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo redir: node has no master spec")
	}
	bindHost := strings.TrimSpace(spec.Master.BindAddress)
	if bindHost == "" {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
			"no bind address in spec")}, nil
	}
	redir := mihomo.DefaultRedirPort
	if spec.Master.RedirPort != 0 {
		redir = spec.Master.RedirPort
	}
	addr := net.JoinHostPort(bindHost, strconv.Itoa(redir))

	localUp := p.localUp
	if localUp == nil {
		localUp = localAddrPresent
	}
	// If the bind address isn't up on a local interface yet (wg0/wg-easy down or
	// mid-recreate), restarting mihomo can't bind it and would loop — defer to the
	// wg-easy/compose planners and re-check next pass.
	if !localUp(bindHost) {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
			"deferred: bind address "+bindHost+" not up locally yet")}, nil
	}

	listening := p.listening
	if listening == nil {
		listening = socketListening
	}
	if listening(addr) {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo redirect listener",
			"listening on "+addr)}, nil
	}

	compose := p.compose
	restart := reconcile.CustomAction(reconcile.ActionUpdate, "mihomo redirect listener",
		"redir listener down on "+addr+" — restart mihomo to rebind",
		"docker compose -f "+compose+" restart mihomo",
		func(ctx context.Context) error {
			c := exec.CommandContext(ctx, "docker", "compose", "-f", compose, "restart", "mihomo")
			if out, err := c.CombinedOutput(); err != nil {
				return fmt.Errorf("restart mihomo: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		})
	return []reconcile.Action{restart}, nil
}

// socketListening reports whether a TCP socket is LISTENing on addr (host:port),
// read passively from the kernel socket table.
//
// It MUST NOT open a connection to addr. The redir port is a transparent proxy: a
// probe connection to it gets proxied by mihomo, and because the probe is not DNAT'd
// its original destination is the redir address itself, which the direct-networks
// rule matches — so mihomo dials DIRECT back into its own redir port, igniting a
// self-amplifying connection storm that pins the master's CPU. A passive socket-table
// read avoids that entirely. Fails safe to true (an unreadable probe must never
// trigger a needless mihomo restart).
func socketListening(addr string) bool {
	out, err := exec.Command("ss", "-ltnH").CombinedOutput()
	if err != nil {
		return true // can't tell → assume up; never falsely restart mihomo
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		switch f[3] { // ss "Local Address:Port" column
		case addr, "0.0.0.0:" + port, "*:" + port, "[::]:" + port:
			return true
		}
	}
	return false
}

// localAddrPresent reports whether host is currently assigned to a local interface.
func localAddrPresent(host string) bool {
	target, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	target = target.Unmap()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if got, ok := netip.AddrFromSlice(ipnet.IP); ok && got.Unmap() == target {
			return true
		}
	}
	return false
}
