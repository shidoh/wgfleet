package keybroker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Automatic rotation of an exit-initiated tunnel's pinned port.
//
// Measured on the stand 2026-09-30: once a path filter poisons or freezes the
// pinned flow — it lost its state mid-flow, it forgot an idle flow and saw the
// master speak first, it froze the flow on volume — the flow never recovers,
// because every keepalive on the same tuple keeps the bad state alive. A new
// port is a new flow, and the exit opens it. Rotation is the only way back.
const (
	// AWGRotateAfter is how long a confirmed tunnel may go without a handshake,
	// while both ends keep reporting, before its port moves. A live tunnel
	// handshakes every two minutes under persistent keepalive.
	AWGRotateAfter = 5 * time.Minute
	// AWGRotateMinInterval spaces rotations out: a path that cuts every new port
	// too is not fixed by moving faster, only made noisier.
	AWGRotateMinInterval = 10 * time.Minute
	// awgReportFresh is how recent a node's report must be for its silence to be
	// read as the path's fault rather than the node's.
	awgReportFresh = 2 * time.Minute
)

// pinConfirmation is the address an exit last confirmed holding for one master,
// since when, and which of the master's peers the confirmation is about (see
// speakingKey). The silence clock is that peer's: a confirmation earned by one
// peer says nothing about how long another has been quiet.
type pinConfirmation struct {
	addr  string
	since time.Time
	key   string
}

// pinKey names one master↔exit tunnel in the broker's in-memory state. Every
// master has its own pinned address on every exit, so nothing here may be keyed
// by the exit alone.
func pinKey(master, exit string) string { return master + "|" + exit }

// masterTunnelKey is the public key master dials exit with in the exit's current
// per-tunnel-key phase — the key of the one peer that carries its traffic, and so
// the one whose endpoint and handshake speak for this tunnel. "" when that key
// has not been published yet.
func (b *Broker) masterTunnelKey(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, masterNode domain.Node) (string, error) {
	if exit.PerTunnelKeyPhase().MasterUsesPerTunnelKey() {
		return b.tunnelPubKey(ctx, master.Name, exit.Name)
	}
	return masterNode.PublicKey, nil
}

// tunnelPeer is what the exit last said about ONE master's tunnel, and whether
// it said anything usable.
//
// How to read the status is decided by the exit's WIRE VERSION, never by whether
// the peer list is empty. Below api.WireMasterPeers the exit reports one endpoint
// and its freshest handshake; exitCarries renders such an exit the base master
// alone, so both describe the base master. At or above it the peer list is the
// answer, and an empty one is a pass that could not read the interface — not a
// tunnel gone silent, and not a reason to fall back to fields that describe
// somebody else.
func (b *Broker) tunnelPeer(ctx context.Context, st domain.NodeStatus, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node) (domain.MasterPeerStatus, bool) {
	if exitNode.WireVersion < api.WireMasterPeers {
		if !master.IsBase() {
			return domain.MasterPeerStatus{}, false
		}
		return domain.MasterPeerStatus{Endpoint: st.AWGMasterEndpoint, LastHandshake: st.LastHandshake}, true
	}
	key, err := b.masterTunnelKey(ctx, exit, master, masterNode)
	if err != nil || key == "" {
		return domain.MasterPeerStatus{}, false
	}
	return st.MasterPeer(key)
}

// speakingKey identifies the peer tunnelPeer reads for this pair: the master's
// key in the exit's current phase, or "" for an exit below api.WireMasterPeers,
// whose single field has no per-peer identity (and for a key not published yet).
func (b *Broker) speakingKey(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node) string {
	if exitNode.WireVersion < api.WireMasterPeers {
		return ""
	}
	key, err := b.masterTunnelKey(ctx, exit, master, masterNode)
	if err != nil {
		return ""
	}
	return key
}

// exitInitiatedAddr is the master's pinned "ip:port" the exit knocks on when the
// exit starts the master↔exit AWG flow, or ok=false when the feature is not live
// for this pair: the flag is off, the exit does not carry this master yet (see
// exitCarries), either agent is below wire 12, or the master has no public IPv4
// the exit could reach. Every refusal leaves the tunnel as it
// is today — the master opens the flow — which is the safe side of each case.
// It also moves the port when the current one is judged poisoned.
func (b *Broker) exitInitiatedAddr(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) (string, bool) {
	if !exit.Transports.AWG.ExitInitiated {
		return "", false
	}
	if !b.exitCarries(exit, exitNode, master) {
		return "", false
	}
	if exitNode.WireVersion < api.WireAWGExitInitiated || masterNode.WireVersion < api.WireAWGExitInitiated {
		b.warnOnce("exit-initiated-wire:"+pinKey(master.Name, exit.Name), fmt.Sprintf("%d|%d", masterNode.WireVersion, exitNode.WireVersion),
			"exit-initiated AWG flow not rendered: an agent is too old to hold its half",
			"exit", exit.Name, "master", master.Name, "master_wire", masterNode.WireVersion, "exit_wire", exitNode.WireVersion,
			"need_wire", api.WireAWGExitInitiated)
		return "", false
	}
	ip, ok := masterRoutableIP(master, masterNode)
	if !ok || !config.IsKnockableIPv4(ip) {
		b.warnOnce("exit-initiated-no-public-ip:"+pinKey(master.Name, exit.Name), master.PublicIP+"|"+masterNode.PublicIP,
			"exit-initiated AWG flow not rendered: the master has no public IPv4 the exit could knock on",
			"exit", exit.Name, "master", master.Name, "public_ip", master.PublicIP, "stored", masterNode.PublicIP)
		return "", false
	}
	gen, rotatedAt, err := b.store.GetAWGPortRotation(ctx, master.Name, exit.Name)
	if err != nil {
		b.warnOnce("exit-initiated-rotation-read:"+pinKey(master.Name, exit.Name), err.Error(),
			"exit-initiated AWG: port generation unreadable, using the base port",
			"exit", exit.Name, "master", master.Name, "err", err)
		gen, rotatedAt = 0, time.Time{}
	}
	addr := pinnedAddr(exit, master, ip, gen)
	if awgCarries(exit, exitNode) && b.pinPoisoned(ctx, exit, exitNode, master, masterNode, addr, rotatedAt) {
		now := b.now()
		if err := b.store.SetAWGPortRotation(ctx, master.Name, exit.Name, gen+1, now); err != nil {
			b.log.Warn("exit-initiated AWG: could not record a port rotation; keeping the port",
				"exit", exit.Name, "master", master.Name, "err", err)
			return addr, true
		}
		next := pinnedAddr(exit, master, ip, gen+1)
		b.log.Warn("exit-initiated AWG: tunnel silent on its pinned port, moving to a new one",
			"exit", exit.Name, "master", master.Name, "from", addr, "to", next, "generation", gen+1)
		addr = next
	}
	return addr, true
}

// awgCarries reports whether the exit's AWG tunnel is the one carrying its
// traffic. A standby transport or a drained exit sees no traffic, so a stale
// handshake there says nothing about the path: rotating it every ten minutes
// was pure noise on the live fleet 2026-09-30.
func awgCarries(exit config.ExitConfig, node domain.Node) bool {
	if exit.Drain || node.Drain {
		return false
	}
	return resolveActiveTransport(exit, node).OrDefault() == domain.TransportAWG
}

// pinnedAddr is the master's pinned address in generation gen. Generation 0 is
// the operator's master_port or the derived port; later ones are drawn afresh.
func pinnedAddr(exit config.ExitConfig, master config.MasterConfig, ip netip.Addr, gen int) string {
	port := exit.AWGMasterPort(master.Name, master.IsBase())
	if gen > 0 {
		port = wg.MasterPortForGen(master.Name, exit.Name, gen)
	}
	return netip.AddrPortFrom(ip, uint16(port)).String()
}

// pinPoisoned reports whether the tunnel on addr is dead in the way only a new
// port can fix: the exit confirmed this address long enough ago, both ends are
// alive and reporting, the last rotation is not recent, and still no handshake.
// A node that stopped reporting is down, not filtered, and is left alone. The
// judgement is of one master's tunnel: its own confirmation, its own peer's
// handshake — another master's healthy flow on the same exit says nothing here.
func (b *Broker) pinPoisoned(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node, addr string, rotatedAt time.Time) bool {
	now := b.now()
	c := b.confirmation(pinKey(master.Name, exit.Name))
	if c.addr != addr || now.Sub(c.since) < AWGRotateAfter {
		return false
	}
	// The peer that speaks for the tunnel changed (a per-tunnel-key phase change)
	// and armedMasterAddr has not restarted the clock for it yet — the exit's
	// render can get here first. The confirmation's age is the old peer's.
	if c.key != b.speakingKey(ctx, exit, exitNode, master, masterNode) {
		return false
	}
	if !rotatedAt.IsZero() && now.Sub(rotatedAt) < AWGRotateMinInterval {
		return false
	}
	st, err := b.store.GetStatus(ctx, exit.Name)
	if err != nil || now.Sub(st.ReportedAt) > awgReportFresh {
		return false
	}
	peer, ok := b.tunnelPeer(ctx, st, exit, exitNode, master, masterNode)
	if !ok {
		return false
	}
	if !peer.LastHandshake.IsZero() && now.Sub(peer.LastHandshake) < AWGRotateAfter {
		return false
	}
	mst, err := b.store.GetStatus(ctx, master.Name)
	return err == nil && now.Sub(mst.ReportedAt) <= awgReportFresh
}

// armedMasterAddr is the pinned address the master's spec carries for this
// tunnel, or "" while the gate must stay unarmed. The gate arms once the exit
// has reported holding the address and STAYS armed while it is the current one:
// a later report of another endpoint is WireGuard roaming, which the exit's
// watchdog undoes; disarming on it flapped the gate on the stand.
func (b *Broker) armedMasterAddr(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) string {
	addr, ok := b.exitInitiatedAddr(ctx, exit, master, exitNode, masterNode)
	if !ok {
		return ""
	}
	key := b.speakingKey(ctx, exit, exitNode, master, masterNode)
	reports := b.exitReports(ctx, exit, exitNode, master, masterNode, addr)
	pk := pinKey(master.Name, exit.Name)
	b.pinMu.Lock()
	c := b.pinConfirmed[pk]
	// A new address is confirmed when the exit reports holding it. The same
	// address with another peer speaking for the tunnel is the exit's phase
	// changing: the address the exit knocks on has not moved, so the gate stays
	// armed — disarming would have the master open the flow, the direction a path
	// filter cuts. But the new peer has never handshaken, and judged on the old
	// peer's clock it would look poisoned at once; it gets a full AWGRotateAfter
	// of its own.
	if (reports && c.addr != addr) || (c.addr == addr && c.key != key) {
		c = pinConfirmation{addr: addr, since: b.now(), key: key}
		b.pinConfirmed[pk] = c
	}
	b.pinMu.Unlock()
	if c.addr != addr {
		return ""
	}
	return addr
}

func (b *Broker) confirmation(key string) pinConfirmation {
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	return b.pinConfirmed[key]
}

// exitReports reports whether the exit's last status says its awg0 holds addr
// for THIS master. A store error confirms nothing — the master keeps opening the
// flow, as before.
func (b *Broker) exitReports(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node, addr string) bool {
	st, err := b.store.GetStatus(ctx, exit.Name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		b.warnOnce("exit-initiated-status:"+pinKey(master.Name, exit.Name), err.Error(),
			"exit-initiated AWG gate not armed: the exit's last status is unreadable",
			"exit", exit.Name, "master", master.Name, "err", err)
		return false
	}
	peer, ok := b.tunnelPeer(ctx, st, exit, exitNode, master, masterNode)
	return ok && peer.Endpoint == addr
}
