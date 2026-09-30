package keybroker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// exitInitiatedAddr is the master's pinned "ip:port" the exit knocks on when the
// exit starts the master↔exit AWG flow, or ok=false when the feature is not live
// for this pair: the flag is off, either agent is below wire 12, or the master
// has no public IPv4 the exit could reach. Every refusal leaves the tunnel as it
// is today — the master opens the flow — which is the safe side of each case.
func (b *Broker) exitInitiatedAddr(exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) (string, bool) {
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
	return netip.AddrPortFrom(ip, uint16(exit.AWGMasterPort(master.Name))).String(), true
}

// exitConfirmedEndpoint reports whether the exit's last status says its awg0
// holds addr for the master. The master's gate is armed only then: armed any
// earlier, the master stops answering an exit that is still knocking elsewhere.
// A store error arms nothing — the master keeps opening the flow, as before.
func (b *Broker) exitConfirmedEndpoint(ctx context.Context, exit, addr string) bool {
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

// armedMasterAddr is the pinned address the master's spec carries for this
// tunnel, or "" while the gate must stay unarmed.
func (b *Broker) armedMasterAddr(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) string {
	addr, ok := b.exitInitiatedAddr(exit, master, exitNode, masterNode)
	if !ok || !b.exitConfirmedEndpoint(ctx, exit.Name, addr) {
		return ""
	}
	return addr
}
