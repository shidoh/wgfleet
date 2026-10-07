package exit

import (
	"context"
	"os/exec"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// liveDump is one read of an interface's peers as the kernel holds them.
// ok=false when it could not be read.
type liveDump func(iface string) ([]wg.DumpPeer, bool)

func readLiveDump(iface string) ([]wg.DumpPeer, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), awgShowTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "awg", "show", iface, "dump").Output()
	if err != nil {
		return nil, false
	}
	return wg.ParseShowDump(string(out)), true
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
