package master

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// --- reality portal (ADR-0038) ---
//
// The inbound exits in the exit-initiated REALITY mode dial: a second xray on
// the master, next to the client-facing one and independent of it. Bridges keep
// mux flows up to it; mihomo reaches each exit through its SOCKS inbound, one
// user per exit.

// portalContainer names the portal's container; its compose service stays
// "xray" in its own project (the reality-portal directory).
const portalContainer = "xray-portal"

type realityPortalPlanner struct {
	configPath  string
	composePath string
	privateKey  string                 // master's portal REALITY x25519 private key
	up          func(file string) bool // nil ⇒ real `docker compose ps` probe
	// netnsAttached decides where mihomo is, and so where the SOCKS inbound must
	// listen for mihomo to reach it.
	netnsAttached func() bool
	// addrExists reports whether ip is on a host interface; nil ⇒ the real check.
	addrExists func(ip string) bool
}

func (realityPortalPlanner) Component() string { return "reality portal (xray)" }

func (p realityPortalPlanner) isUp(ctx context.Context) bool {
	if p.up == nil {
		return compose.StackUp(ctx, p.composePath)
	}
	return p.up(p.composePath)
}

func (p realityPortalPlanner) hasAddr(ip string) bool {
	if p.addrExists == nil {
		return hostHasAddr(ip)
	}
	return p.addrExists(ip)
}

func (p realityPortalPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	var portal *domain.RealityPortalSpec
	if spec.Master != nil {
		portal = spec.Master.RealityPortal
	}
	if portal == nil {
		// No exit dials this master. A portal still up — the last exit left the
		// mode, or an older agent left it running — is stopped. The key and the
		// files stay until decommission. No compose file: it never ran here, and
		// docker need not be asked on every pass of every master.
		if _, err := os.Stat(p.composePath); err != nil {
			return []reconcile.Action{reconcile.NoChangeAction("reality portal", "not used")}, nil
		}
		if p.isUp(ctx) {
			return []reconcile.Action{reconcile.ExecAction("stop reality portal (no exit dials this master)",
				"docker", "compose", "-f", p.composePath, "down")}, nil
		}
		return []reconcile.Action{reconcile.NoChangeAction("reality portal", "not used")}, nil
	}
	// Validated here, not in NodeSpec.Validate: one bad field keeps the last-good
	// portal serving and leaves the rest of the node converging.
	if err := portal.Validate(); err != nil {
		return []reconcile.Action{reconcile.NoChangeAction("reality portal",
			"spec rejected, keeping the last-good portal: "+err.Error())}, nil
	}
	if p.privateKey == "" {
		return []reconcile.Action{reconcile.NoChangeAction("reality portal",
			"pending: portal REALITY key not yet available")}, nil
	}
	attached := p.netnsAttached != nil && p.netnsAttached()
	socks := PortalSocksAddr(spec, attached)
	// The compose restart policy is "no": the agent, not docker, brings the portal
	// back, and only once the SOCKS address exists. At boot the namespace link
	// comes up later than docker, and xray bound to a missing address would
	// crash-loop until it did.
	if socks == "" || !p.hasAddr(socks) {
		return []reconcile.Action{reconcile.NoChangeAction("reality portal",
			"pending: SOCKS address "+socks+" is not on this host yet")}, nil
	}
	_, passwords := portalSocksFor(spec, attached, p.privateKey)
	cfg, err := xray.RenderPortalConfig(xray.PortalRenderInput{
		Spec: *portal, PrivateKey: p.privateKey, SocksAddr: socks, SocksPasswords: passwords,
	})
	if err != nil {
		return nil, fmt.Errorf("render reality portal: %w", err)
	}
	composeYAML, err := compose.RenderXrayCompose(compose.XrayInput{
		Image:         portal.Image,
		ConfigPath:    p.configPath,
		ListenPort:    portal.ListenPort,
		ContainerName: portalContainer,
		Restart:       "no",
	})
	if err != nil {
		return nil, fmt.Errorf("render reality portal compose: %w", err)
	}
	// The config holds the portal private key and every SOCKS password.
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
		actions = append(actions, reconcile.ExecAction("bring reality portal up",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	case cfgFile.Changes() && p.isUp(ctx):
		// xray has no hot reload: every bridge redials, ~7 s. Only a running
		// container: compose restart leaves a stopped one stopped.
		actions = append(actions, reconcile.ExecAction("restart reality portal",
			"docker", "compose", "-f", p.composePath, "restart", "xray"))
	case !p.isUp(ctx):
		actions = append(actions, reconcile.ExecAction("bring reality portal up (was down)",
			"docker", "compose", "-f", p.composePath, "up", "-d"))
	default:
		actions = append(actions, reconcile.NoChangeAction("reality portal", "xray-portal already up"))
	}
	return actions, nil
}

// PortalSocksAddr is where the portal's SOCKS inbound listens and mihomo dials
// it: the host end of the namespace link while mihomo lives there, the loopback
// otherwise. The portal and mihomo both take it from here, so they cannot
// disagree (the client VLESS bridge once did, for three hours).
func PortalSocksAddr(spec domain.NodeSpec, attached bool) string {
	if attached {
		return NetnsHostIP(spec)
	}
	return "127.0.0.1"
}

// portalSocksFor is the SOCKS address and per-exit passwords mihomo dials the
// portal with — the same values the portal planner renders on the other end.
// Empty when the master runs no portal or has no key yet.
func portalSocksFor(spec domain.NodeSpec, attached bool, portalKey string) (string, map[string]string) {
	if spec.Master == nil || spec.Master.RealityPortal == nil || portalKey == "" {
		return "", nil
	}
	pw := make(map[string]string, len(spec.Master.RealityPortal.Clients))
	for _, c := range spec.Master.RealityPortal.Clients {
		pw[c.Exit] = PortalSocksPassword(portalKey, c.Exit)
	}
	return PortalSocksAddr(spec, attached), pw
}

// portalSocksFirewall is the SOCKS address the host firewall admits from
// mihomo's namespace: the host end of the link, whenever the master runs a
// portal. It does not depend on where mihomo is right now — the rule only
// renders beside the namespace's own accepts, and it must already be there the
// pass mihomo moves.
func portalSocksFirewall(spec domain.NodeSpec) netip.AddrPort {
	if spec.Master == nil || spec.Master.RealityPortal == nil {
		return netip.AddrPort{}
	}
	addr, err := netip.ParseAddr(NetnsHostIP(spec))
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr, uint16(spec.Master.RealityPortal.ResolvedSocksPort()))
}

// ephemeralPortRange reads the host's ip_local_port_range, which xray picks its
// SOCKS UDP relay ports from; zero when unreadable (the renderer then assumes
// Linux's default).
func ephemeralPortRange() [2]uint16 {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return [2]uint16{}
	}
	f := strings.Fields(string(data))
	if len(f) != 2 {
		return [2]uint16{}
	}
	lo, err1 := strconv.ParseUint(f[0], 10, 16)
	hi, err2 := strconv.ParseUint(f[1], 10, 16)
	if err1 != nil || err2 != nil || lo == 0 || hi < lo {
		return [2]uint16{}
	}
	return [2]uint16{uint16(lo), uint16(hi)}
}

// PortalSocksPassword derives an exit's SOCKS password from the portal private
// key. A client's DIRECT traffic leaves from mihomo and can reach the SOCKS
// address, so the password is a real secret; it never leaves the master, and
// rotating the portal key rotates every password with it.
func PortalSocksPassword(portalPrivateKey, exit string) string {
	m := hmac.New(sha256.New, []byte(portalPrivateKey))
	m.Write([]byte("wgfleet/reality-portal/socks\x00" + exit))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// hostHasAddr reports whether ip is assigned to an interface of this host.
func hostHasAddr(ip string) bool {
	want, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if want.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if got, ok := netip.AddrFromSlice(n.IP); ok && got.Unmap() == want {
				return true
			}
		}
	}
	return false
}
