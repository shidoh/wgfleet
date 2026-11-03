package keybroker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Automatic rotation of an exit-initiated tunnel's pinned port.
//
// Once a path filter poisons or freezes the
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
//
// It also names the tunnel's AmneziaWG generation. Switching a tunnel to 3.x
// rebuilds the exit's interface, and the rebuilt peer reports no handshake at
// all; judged on a confirmation earned under 2.0, that zero read as minutes of
// silence and moved the pinned port of every exit-initiated tunnel seconds after
// the switch. A generation change is a new peer for the silence clock, exactly
// like a phase change.
func (b *Broker) speakingKey(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node) string {
	if exitNode.WireVersion < api.WireMasterPeers {
		return ""
	}
	key, err := b.masterTunnelKey(ctx, exit, master, masterNode)
	if err != nil {
		return ""
	}
	if iface, ok, err := b.exitInterface(ctx, exit, exitNode); err == nil && ok && iface.awg3 {
		key += awg3GenerationTag
	}
	return key
}

// awg3GenerationTag marks a speakingKey whose tunnel runs AmneziaWG 3.x. It is
// stored with the confirmation, so a key without it is a 2.0 confirmation.
const awg3GenerationTag = "|awg3"

// exitInitiatedAddr is the master's pinned "ip:port" the exit knocks on when the
// exit starts the master↔exit AWG flow, or ok=false when the feature is not live
// for this pair: the flag is off, the exit does not carry this master yet (see
// exitCarries), either agent is below wire 12, or the master has no public IPv4
// the exit could reach. Every refusal leaves the tunnel as it
// is today — the master opens the flow — which is the safe side of each case.
// It also moves the port when the current one is judged poisoned.
//
// A refusal is ("", false) with no error. An error is something else: the store could not
// say which generation the port is in, or what the exit confirmed. Rendering on
// regardless would hand out generation 0 — the port already judged poisoned — and
// disarm the master's gate for the pass, so the render fails instead and the node
// keeps its last-good spec. Same rule as tunnelPubKey.
//
// Every refusal also forgets what the exit confirmed for the pair (see
// forgetConfirmation): a confirmation exists only while the pinned flow is being
// asked for. While it is not, the master dials from an ephemeral port and the
// exit's endpoint follows it; a confirmation kept across that would arm the gate
// the moment the flow is asked for again, on an address the exit is not knocking
// on yet. Both renderers come through here, so they cannot disagree about it.
func (b *Broker) exitInitiatedAddr(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) (string, bool, error) {
	refuse := func() (string, bool, error) {
		// Not asked for is not carrying: asked for again, the tunnel starts its
		// silence clock afresh (see carryingSince).
		b.carryingSince(pinKey(master.Name, exit.Name), false)
		return "", false, b.forgetConfirmation(ctx, master.Name, exit.Name)
	}
	if !exit.Transports.AWG.ExitInitiated || !slices.Contains(exit.EnabledTransports(), domain.TransportAWG) {
		return refuse()
	}
	if !b.exitCarries(exit, exitNode, master) {
		return refuse()
	}
	// The master holds no peer on this exit under the key it dials with — an
	// earlier master presents the same one (see keyOwners). There is no tunnel to
	// pin, and nothing here may judge or move a port for it.
	if peered, err := b.peeredOn(ctx, exit, exitNode, master, masterNode); err != nil {
		return "", false, err
	} else if !peered {
		return refuse()
	}
	if exitNode.WireVersion < api.WireAWGExitInitiated || masterNode.WireVersion < api.WireAWGExitInitiated {
		b.warnOnce("exit-initiated-wire:"+pinKey(master.Name, exit.Name), fmt.Sprintf("%d|%d", masterNode.WireVersion, exitNode.WireVersion),
			"exit-initiated AWG flow not rendered: an agent is too old to hold its half",
			"exit", exit.Name, "master", master.Name, "master_wire", masterNode.WireVersion, "exit_wire", exitNode.WireVersion,
			"need_wire", api.WireAWGExitInitiated)
		return refuse()
	}
	ip, ok := masterRoutableIP(master, masterNode)
	if !ok || !config.IsKnockableIPv4(ip) {
		b.warnOnce("exit-initiated-no-public-ip:"+pinKey(master.Name, exit.Name), master.PublicIP+"|"+masterNode.PublicIP,
			"exit-initiated AWG flow not rendered: the master has no public IPv4 the exit could knock on",
			"exit", exit.Name, "master", master.Name, "public_ip", master.PublicIP, "stored", masterNode.PublicIP)
		return refuse()
	}
	gen, rotatedAt, err := b.store.GetAWGPortRotation(ctx, master.Name, exit.Name)
	if err != nil {
		return "", false, fmt.Errorf("exit %q: pinned port generation for master %q: %w: %w", exit.Name, master.Name, store.ErrUnreadable, err)
	}
	addr := pinnedAddr(exit, master, ip, gen)
	poisoned := false
	// Silence means something only on a tunnel the master has been dialling for a
	// full AWGRotateAfter. One that just started carrying — the operator switched
	// the exit back from REALITY, an auto-suspension ended — has a handshake as
	// stale as its idle time, and is judged on its own clock.
	// The stored suspensions have to be in memory before one is asked about: the
	// exit's render can run first after a restart. Unreadable, the tunnel is not
	// judged this pass — an exit's own spec does not hang on them, only the
	// master's render, whose output is the balancer's membership, fails.
	carries := awgCarries(exit, exitNode)
	if err := b.loadSuspensions(ctx); err != nil {
		b.warnOnce("auto-suspend-unreadable", err.Error(),
			"exit-initiated AWG: stored suspensions unreadable; no tunnel is judged silent until they can be read", "err", err)
		carries = false
	} else if b.exitSuspended(exit.Name) {
		carries = false
	}
	since := b.carryingSince(pinKey(master.Name, exit.Name), carries)
	if carries && b.now().Sub(since) >= AWGRotateAfter {
		if poisoned, err = b.pinPoisoned(ctx, exit, exitNode, master, masterNode, addr, rotatedAt); err != nil {
			return "", false, err
		}
	}
	if poisoned {
		now := b.now()
		if err := b.store.SetAWGPortRotation(ctx, master.Name, exit.Name, gen+1, now); err != nil {
			b.log.Warn("exit-initiated AWG: could not record a port rotation; keeping the port",
				"exit", exit.Name, "master", master.Name, "err", err)
			return addr, true, nil
		}
		next := pinnedAddr(exit, master, ip, gen+1)
		b.log.Warn("exit-initiated AWG: tunnel silent on its pinned port, moving to a new one",
			"exit", exit.Name, "master", master.Name, "from", addr, "to", next, "generation", gen+1)
		addr = next
	}
	return addr, true, nil
}

// awgCarries reports whether the exit's AWG tunnel is the one carrying its
// traffic. A standby transport or a drained exit sees no traffic, so a stale
// handshake there says nothing about the path: rotating it every ten minutes
// would be pure noise.
func awgCarries(exit config.ExitConfig, node domain.Node) bool {
	if exit.Drain || node.Drain {
		return false
	}
	return resolveActiveTransport(exit, node).OrDefault() == domain.TransportAWG
}

// exitSuspended reports whether the throughput watchdog currently holds the exit
// out of the load balancer (see trackSuspensions).
func (b *Broker) exitSuspended(exit string) bool {
	b.suspendMu.Lock()
	defer b.suspendMu.Unlock()
	t := b.suspend[exit]
	// Under the last-healthy-exit guard the set is overridden and the exit is in
	// the balancer, carrying traffic.
	return t != nil && t.suspended && !b.suspendGuard
}

// carryingSince returns when the master↔exit AWG tunnel was last SEEN to start
// carrying traffic — the pass on which it carries after a pass on which it did
// not. The zero time means no such start was seen by this process: the tunnel
// has carried for as long as the controller has been up, and its silence is
// judged on the stored clocks alone. That is what keeps a restart from handing a
// dead tunnel a fresh clock (TestTheSilenceClockSurvivesAControllerRestart).
func (b *Broker) carryingSince(pair string, carries bool) time.Time {
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	if b.pinCarrying == nil {
		b.pinCarrying = make(map[string]carryTrack)
	}
	was, seen := b.pinCarrying[pair]
	switch {
	case !carries:
		b.pinCarrying[pair] = carryTrack{}
		return time.Time{}
	case seen && !was.carrying:
		was = carryTrack{carrying: true, since: b.now()}
	case !seen:
		was = carryTrack{carrying: true}
	}
	b.pinCarrying[pair] = was
	return was.since
}

// carryTrack is whether a tunnel carried traffic on the last pass and, when this
// process saw it start, since when.
type carryTrack struct {
	carrying bool
	since    time.Time
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
//
// The only error is a confirmation the store could not read (see confirmation).
func (b *Broker) pinPoisoned(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node, addr string, rotatedAt time.Time) (bool, error) {
	now := b.now()
	c, err := b.confirmation(ctx, master.Name, exit.Name)
	if err != nil {
		return false, err
	}
	if c.addr != addr || now.Sub(c.since) < AWGRotateAfter {
		return false, nil
	}
	// The peer that speaks for the tunnel changed (a per-tunnel-key phase change)
	// and armedMasterAddr has not restarted the clock for it yet — the exit's
	// render can get here first. The confirmation's age is the old peer's.
	if c.key != b.speakingKey(ctx, exit, exitNode, master, masterNode) {
		return false, nil
	}
	if !rotatedAt.IsZero() && now.Sub(rotatedAt) < AWGRotateMinInterval {
		return false, nil
	}
	st, err := b.store.GetStatus(ctx, exit.Name)
	if err != nil || now.Sub(st.ReportedAt) > awgReportFresh {
		return false, nil
	}
	peer, ok := b.tunnelPeer(ctx, st, exit, exitNode, master, masterNode)
	if !ok {
		return false, nil
	}
	if !peer.LastHandshake.IsZero() && now.Sub(peer.LastHandshake) < AWGRotateAfter {
		return false, nil
	}
	mst, err := b.store.GetStatus(ctx, master.Name)
	return err == nil && now.Sub(mst.ReportedAt) <= awgReportFresh, nil
}

// armedMasterAddr is the pinned address the master's spec carries for this
// tunnel, or "" while the gate must stay unarmed. The gate arms once the exit
// has reported holding the address and STAYS armed while it is the current one:
// a later report of another endpoint is WireGuard roaming, which the exit's
// watchdog undoes; disarming on it flapped the gate on the stand.
//
// "" with a nil error is an unarmed gate. An error is a store that could not be
// read, and fails the master's render (see exitInitiatedAddr).
func (b *Broker) armedMasterAddr(ctx context.Context, exit config.ExitConfig, master config.MasterConfig, exitNode, masterNode domain.Node) (string, error) {
	addr, ok, err := b.exitInitiatedAddr(ctx, exit, master, exitNode, masterNode)
	if err != nil || !ok {
		return "", err
	}
	key := b.speakingKey(ctx, exit, exitNode, master, masterNode)
	reports := b.exitReports(ctx, exit, exitNode, master, masterNode, addr)
	c, err := b.confirmation(ctx, master.Name, exit.Name)
	if err != nil {
		return "", err
	}
	// A new address is confirmed when the exit reports holding it. The same
	// address with another peer speaking for the tunnel is the exit's phase
	// changing: the address the exit knocks on has not moved, so the gate stays
	// armed — disarming would have the master open the flow, the direction a path
	// filter cuts. But the new peer has never handshaken, and judged on the old
	// peer's clock it would look poisoned at once; it gets a full AWGRotateAfter
	// of its own.
	if (reports && c.addr != addr) || (c.addr == addr && c.key != key) {
		c = pinConfirmation{addr: addr, since: b.now(), key: key}
		b.confirm(ctx, master.Name, exit.Name, c)
	}
	if c.addr != addr {
		return "", nil
	}
	return addr, nil
}

// confirmation is what the exit last confirmed for one master↔exit tunnel. The
// map is a cache over the store: the confirmation has to outlive the process (a
// manifest edit restarts the controller, and a wire-13 exit's per-peer report is
// not sticky, so a pass with no peer list would otherwise find the gate
// disarmed), and a render must not pay a query per tunnel for it. Each tunnel is
// read once; "nothing confirmed" is cached like any other answer.
//
// An unreadable store is an error, never "nothing confirmed": that would disarm
// a gate nobody disproved. pinMu is not held across the read.
func (b *Broker) confirmation(ctx context.Context, master, exit string) (pinConfirmation, error) {
	pk := pinKey(master, exit)
	b.pinMu.Lock()
	c, cached := b.pinConfirmed[pk]
	b.pinMu.Unlock()
	if cached {
		return c, nil
	}
	addr, key, since, err := b.store.GetAWGPinConfirmation(ctx, master, exit)
	if err != nil {
		return pinConfirmation{}, fmt.Errorf("exit %q: pinned address confirmed for master %q: %w: %w", exit, master, store.ErrUnreadable, err)
	}
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	// A render that confirmed while this one was reading knows more than the store did.
	if c, cached := b.pinConfirmed[pk]; cached {
		return c, nil
	}
	c = pinConfirmation{addr: addr, since: since, key: key}
	b.pinConfirmed[pk] = c
	return c, nil
}

// confirm records a new confirmation, in memory first and then in the store. A
// failed write must not disarm the gate — the exit did confirm, and this process
// saw it — so it is logged and the in-memory value stands; what is lost is only
// what a restart would have read back. pinMu is not held across the write.
func (b *Broker) confirm(ctx context.Context, master, exit string, c pinConfirmation) {
	b.pinMu.Lock()
	b.pinConfirmed[pinKey(master, exit)] = c
	b.pinMu.Unlock()
	if err := b.store.SetAWGPinConfirmation(ctx, master, exit, c.addr, c.key, c.since); err != nil {
		b.log.Warn("exit-initiated AWG: could not record the confirmed address; it will not survive a controller restart",
			"exit", exit, "master", master, "addr", c.addr, "err", err)
	}
}

// forgetConfirmation drops what the exit confirmed for a pair whose pinned flow
// the controller is not rendering: the flag is off, the exit has no AmneziaWG
// transport, an agent is too old, the master has no address to knock on, the
// exit does not carry the master, or holds no peer for it. A confirmation is
// about a pinned flow that exists. Kept across a gap it does two wrong things on
// return: it arms the gate before the exit has reported the pinned endpoint, and
// its age is read as that long of silence — the returning peer, which has rightly
// never handshaken there, judged a poisoned flow and its port moved on the first
// render (seen on the stand). The pair confirms afresh on return.
//
// Every render of such a pair comes through here, so it must cost nothing
// when there is nothing to forget: the cache answers, and the store is written
// only when a confirmation is actually dropped. pinMu is not held across I/O. A
// failed delete is logged, not fatal — this process has already forgotten; the
// row would matter only to a controller restarted inside the gap.
func (b *Broker) forgetConfirmation(ctx context.Context, master, exit string) error {
	c, err := b.confirmation(ctx, master, exit)
	if err != nil {
		return err
	}
	if c == (pinConfirmation{}) {
		return nil
	}
	b.pinMu.Lock()
	b.pinConfirmed[pinKey(master, exit)] = pinConfirmation{}
	b.pinMu.Unlock()
	if err := b.store.DeleteAWGPinConfirmation(ctx, master, exit); err != nil {
		b.log.Warn("exit-initiated AWG: could not drop the confirmation of a tunnel the exit no longer carries",
			"exit", exit, "master", master, "err", err)
	}
	return nil
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
