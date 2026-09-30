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

// pinConfirmation is the address an exit last confirmed holding, and since when.
type pinConfirmation struct {
	addr  string
	since time.Time
}

// exitInitiatedAddr is the master's pinned "ip:port" the exit knocks on when the
// exit starts the master↔exit AWG flow, or ok=false when the feature is not live
// for this pair: the flag is off, either agent is below wire 12, or the master
// has no public IPv4 the exit could reach. Every refusal leaves the tunnel as it
// is today — the master opens the flow — which is the safe side of each case.
// It also moves the port when the current one is judged poisoned.
func (b *Broker) exitInitiatedAddr(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) (string, bool) {
	if !exit.Transports.AWG.ExitInitiated {
		return "", false
	}
	if exitNode.WireVersion < api.WireAWGExitInitiated || masterNode.WireVersion < api.WireAWGExitInitiated {
		b.warnOnce("exit-initiated-wire:"+exit.Name, fmt.Sprintf("%d|%d", masterNode.WireVersion, exitNode.WireVersion),
			"exit-initiated AWG flow not rendered: an agent is too old to hold its half",
			"exit", exit.Name, "master_wire", masterNode.WireVersion, "exit_wire", exitNode.WireVersion,
			"need_wire", api.WireAWGExitInitiated)
		return "", false
	}
	ip, ok := masterRoutableIP(master, masterNode)
	if !ok || !config.IsKnockableIPv4(ip) {
		b.warnOnce("exit-initiated-no-public-ip:"+exit.Name, master.PublicIP+"|"+masterNode.PublicIP,
			"exit-initiated AWG flow not rendered: the master has no public IPv4 the exit could knock on",
			"exit", exit.Name, "master", master.Name, "public_ip", master.PublicIP, "stored", masterNode.PublicIP)
		return "", false
	}
	gen, rotatedAt, err := b.store.GetAWGPortRotation(ctx, exit.Name)
	if err != nil {
		b.warnOnce("exit-initiated-rotation-read:"+exit.Name, err.Error(),
			"exit-initiated AWG: port generation unreadable, using the base port", "exit", exit.Name, "err", err)
		gen, rotatedAt = 0, time.Time{}
	}
	addr := pinnedAddr(exit, master, ip, gen)
	if b.pinPoisoned(ctx, exit.Name, master.Name, addr, rotatedAt) {
		now := b.now()
		if err := b.store.SetAWGPortRotation(ctx, exit.Name, gen+1, now); err != nil {
			b.log.Warn("exit-initiated AWG: could not record a port rotation; keeping the port",
				"exit", exit.Name, "err", err)
			return addr, true
		}
		next := pinnedAddr(exit, master, ip, gen+1)
		b.log.Warn("exit-initiated AWG: tunnel silent on its pinned port, moving to a new one",
			"exit", exit.Name, "from", addr, "to", next, "generation", gen+1)
		addr = next
	}
	return addr, true
}

// pinnedAddr is the master's pinned address in generation gen. Generation 0 is
// the operator's master_port or the derived port; later ones are drawn afresh.
func pinnedAddr(exit config.ExitConfig, master config.MasterConfig, ip netip.Addr, gen int) string {
	port := exit.AWGMasterPort(master.Name)
	if gen > 0 {
		port = wg.MasterPortForGen(master.Name, exit.Name, gen)
	}
	return netip.AddrPortFrom(ip, uint16(port)).String()
}

// pinPoisoned reports whether the tunnel on addr is dead in the way only a new
// port can fix: the exit confirmed this address long enough ago, both ends are
// alive and reporting, the last rotation is not recent, and still no handshake.
// A node that stopped reporting is down, not filtered, and is left alone.
func (b *Broker) pinPoisoned(ctx context.Context, exit, master, addr string, rotatedAt time.Time) bool {
	now := b.now()
	c := b.confirmation(exit)
	if c.addr != addr || now.Sub(c.since) < AWGRotateAfter {
		return false
	}
	if !rotatedAt.IsZero() && now.Sub(rotatedAt) < AWGRotateMinInterval {
		return false
	}
	st, err := b.store.GetStatus(ctx, exit)
	if err != nil || now.Sub(st.ReportedAt) > awgReportFresh {
		return false
	}
	if !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) < AWGRotateAfter {
		return false
	}
	mst, err := b.store.GetStatus(ctx, master)
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
	if b.exitReports(ctx, exit.Name, addr) {
		b.pinMu.Lock()
		if b.pinConfirmed[exit.Name].addr != addr {
			b.pinConfirmed[exit.Name] = pinConfirmation{addr: addr, since: b.now()}
		}
		b.pinMu.Unlock()
	}
	if b.confirmation(exit.Name).addr != addr {
		return ""
	}
	return addr
}

func (b *Broker) confirmation(exit string) pinConfirmation {
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	return b.pinConfirmed[exit]
}

// exitReports reports whether the exit's last status says its awg0 holds addr
// for the master. A store error confirms nothing — the master keeps opening the
// flow, as before.
func (b *Broker) exitReports(ctx context.Context, exit, addr string) bool {
	st, err := b.store.GetStatus(ctx, exit)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		b.warnOnce("exit-initiated-status:"+exit, err.Error(),
			"exit-initiated AWG gate not armed: the exit's last status is unreadable", "exit", exit, "err", err)
		return false
	}
	return st.AWGMasterEndpoint == addr
}
