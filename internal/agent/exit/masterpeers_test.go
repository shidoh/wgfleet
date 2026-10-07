package exit

import (
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func TestMasterPeersReportsEveryPeerOfTheSpec(t *testing.T) {
	peers := []domain.PeerSpec{
		{Name: "master-xa-1", PublicKey: "keyA", Endpoint: "203.0.113.1:23456", AllowedIPs: []string{"10.81.0.2/32"}},
		{Name: "master-xa-2", PublicKey: "keyB", AllowedIPs: []string{"10.81.0.4/32"}},
	}
	read := func(string) ([]wg.DumpPeer, bool) {
		return []wg.DumpPeer{
			{PublicKey: "keyA", Endpoint: "203.0.113.1:23456", LatestHandshake: time.Unix(1_800_000_000, 0)},
			{PublicKey: "keyB", Endpoint: "203.0.113.2:40001"},
			{PublicKey: "stranger", Endpoint: "192.0.2.9:1"},
		}, true
	}
	got, ok := masterPeersFrom(peers, read, "awg0")
	if !ok || len(got) != 2 {
		t.Fatalf("got %+v, %v; want the two peers of the spec and nothing else", got, ok)
	}
	if got[0].PublicKey != "keyA" || got[0].Endpoint != "203.0.113.1:23456" || got[0].LastHandshake.IsZero() {
		t.Errorf("first peer = %+v", got[0])
	}
	if got[1].PublicKey != "keyB" || got[1].Endpoint != "203.0.113.2:40001" || !got[1].LastHandshake.IsZero() {
		t.Errorf("second peer = %+v", got[1])
	}
}

// A spec peer the kernel does not hold is still reported — with nothing in it.
// "The exit has no such peer" is what the controller needs to hear.
func TestMasterPeersReportsASpecPeerMissingFromTheKernel(t *testing.T) {
	peers := []domain.PeerSpec{{PublicKey: "keyA", AllowedIPs: []string{"10.81.0.2/32"}}}
	read := func(string) ([]wg.DumpPeer, bool) { return nil, true }
	got, ok := masterPeersFrom(peers, read, "awg0")
	if !ok || len(got) != 1 || got[0].PublicKey != "keyA" || got[0].Endpoint != "" {
		t.Errorf("got %+v, %v", got, ok)
	}
}

func TestMasterPeersSaysWhenItCannotRead(t *testing.T) {
	peers := []domain.PeerSpec{{PublicKey: "keyA", AllowedIPs: []string{"10.81.0.2/32"}}}
	read := func(string) ([]wg.DumpPeer, bool) { return nil, false }
	if got, ok := masterPeersFrom(peers, read, "awg0"); ok || got != nil {
		t.Errorf("unreadable interface: got %+v, %v; want nil, false", got, ok)
	}
}
