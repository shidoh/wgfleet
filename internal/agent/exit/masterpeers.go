package exit

import (
	"context"
	"log/slog"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// liveDump is one read of an interface's peers as the kernel holds them.
// ok=false when it could not be read.
type liveDump func(iface string) ([]wg.DumpPeer, bool)

func readLiveDump(iface string) ([]wg.DumpPeer, bool) {
	return readLiveDumpWith(awgShowDump, iface)
}

func awgShowDump(iface string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), awgShowTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "awg", "show", iface, "dump").Output()
}

// readLiveDumpWith reads the interface through show and says so when it cannot.
// The callers carry on without the reading — peers are restated blind, the
// status report goes out with no peer list — and both look, from the controller,
// like an exit that simply has nothing to say. One line per failed pass is the
// only place the cause is written down.
func readLiveDumpWith(show func(iface string) ([]byte, error), iface string) ([]wg.DumpPeer, bool) {
	out, err := show(iface)
	if err != nil {
		slog.Warn("could not read the interface's peers from the kernel", "iface", iface, "err", err)
		return nil, false
	}
	peers := wg.ParseShowDump(string(out))
	if !dumpReadable(string(out), peers) {
		slog.Warn("could not read the interface's peers from the kernel",
			"iface", iface, "err", "unparseable dump: peer lines present and none understood")
		return nil, false
	}
	return peers, true
}

// dumpReadable says whether a dump was understood. Peer lines that all failed to
// parse would read as "the kernel holds no peers" — and every pass would then
// restate every peer and remove nothing. More than the interface line with no
// peer out of it is a dump we cannot read, not an empty one.
func dumpReadable(out string, peers []wg.DumpPeer) bool {
	if len(peers) > 0 {
		return true
	}
	lines := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	return lines <= 1
}

// MasterPeers is what an exit reports as StatusReport.master_peers: for every
// master peer of the spec, the endpoint and latest handshake awg0 holds — or
// nothing, when the kernel does not hold that peer at all. Peers the spec does
// not name are left out; the controller could not map them to a master.
// ok=false means the interface could not be read, and the caller then reports
// none: a list that outlives its reading would be taken for live handshakes.
func MasterPeers(confPath string, peers []domain.PeerSpec) ([]domain.MasterPeerStatus, bool) {
	return masterPeersFrom(peers, readLiveDump, ifaceName(confPath))
}

func masterPeersFrom(peers []domain.PeerSpec, read liveDump, iface string) ([]domain.MasterPeerStatus, bool) {
	live, ok := read(iface)
	if !ok {
		return nil, false
	}
	byKey := make(map[string]wg.DumpPeer, len(live))
	for _, p := range live {
		byKey[p.PublicKey] = p
	}
	out := make([]domain.MasterPeerStatus, 0, len(peers))
	for _, p := range peers {
		l := byKey[p.PublicKey]
		out = append(out, domain.MasterPeerStatus{
			PublicKey: p.PublicKey, Endpoint: l.Endpoint, LastHandshake: l.LatestHandshake,
		})
	}
	return out, true
}

// masterPeerEdits brings the kernel's master peers to the spec with `awg set`.
//
// It compares the SPEC with the KERNEL, never file with file. The config is
// written before any command runs and the engine stops a component at its first
// failed action, so after one failed `awg set` the file matches the spec and the
// interface does not — and a file comparison would call that converged for good.
// On a re-slotted fleet that is a peer whose /32 another peer took: it handshakes
// and carries nothing until someone restarts awg0 by hand.
//
// A peer is restated whole — allowed-ips, keepalive, and its endpoint when the
// spec gives one — because `awg set` is idempotent and a half-set peer is the
// failure this exists to repair. Removals come first, so an address moving from
// a departed peer is free before its new owner claims it. A live peer the spec
// does not name is removed.
//
// rebuild=true says the live list has nothing in common with the spec's on an
// interface that has peers: an entirely foreign set is better recreated than
// emptied one `remove` at a time.
func masterPeerEdits(iface string, want []domain.PeerSpec, live []wg.DumpPeer) (edits []reconcile.Action, rebuild bool) {
	have := make(map[string]wg.DumpPeer, len(live))
	for _, p := range live {
		have[p.PublicKey] = p
	}
	wanted := make(map[string]struct{}, len(want))
	overlap := 0
	var sets []reconcile.Action
	for _, p := range want {
		wanted[p.PublicKey] = struct{}{}
		l, present := have[p.PublicKey]
		if present {
			overlap++
		}
		ips := append([]string(nil), p.AllowedIPs...)
		sort.Strings(ips)
		if present && slices.Equal(ips, l.AllowedIPs) && p.Keepalive == l.Keepalive {
			continue // endpoints are restoreRoamedEndpoints' business
		}
		// A zero keepalive is written as 0: AmneziaWG 3.x tools reject the word
		// `off` that wg(8) documents, and take 0 for the same thing.
		cmd := []string{"awg", "set", iface, "peer", p.PublicKey,
			"allowed-ips", strings.Join(p.AllowedIPs, ","), "persistent-keepalive", strconv.Itoa(max(p.Keepalive, 0))}
		if p.Endpoint != "" {
			cmd = append(cmd, "endpoint", p.Endpoint)
		}
		sets = append(sets, reconcile.ExecAction("set master peer "+p.Name+" on the running interface", cmd...))
	}
	if len(live) > 0 && len(want) > 0 && overlap == 0 {
		return nil, true
	}
	for _, l := range live {
		if _, keep := wanted[l.PublicKey]; !keep {
			edits = append(edits, reconcile.ExecAction("remove a master peer the spec no longer names",
				"awg", "set", iface, "peer", l.PublicKey, "remove"))
		}
	}
	return append(edits, sets...), false
}
