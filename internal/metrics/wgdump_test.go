package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// errNoIface stands in for a down/absent interface in the dump fixture.
var errNoIface = errors.New("no such interface")

// newTestWGCollector builds a WGCollector over a fresh registry with an injected
// dump func, returning both so tests can override the clock and gather series.
func newTestWGCollector(t *testing.T, ifaces []string, dump DumpFunc) (*prometheus.Registry, *WGCollector) {
	t.Helper()
	reg := prometheus.NewRegistry()
	c := NewWGCollector(reg, "exit-de-1", "exit", ifaces, dump)
	return reg, c
}

// realistic `wg show <iface> dump` fixtures. The first line is always the
// interface (private-key, public-key, listen-port, fwmark); peer lines follow.
const (
	// awg0 on an exit: one master peer with a fresh handshake + transfer.
	wgDumpExit = "aPrivKeyBase64xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\tifacePubKeyBase64xxxxxxxxxxxxxxxxxxxxxxxxxx=\t51820\toff\n" +
		"masterPubKeyBase64AAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t198.51.100.7:51820\t10.81.0.0/24\t1699999940\t10485760\t20971520\t25\n"

	// two peers: one with a recent handshake, one that never handshook (epoch 0).
	wgDumpTwoPeers = "priv=\tpub=\t51820\toff\n" +
		"peerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t1.2.3.4:5\t10.0.0.2/32\t1699999900\t1000\t2000\t0\n" +
		"peerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\t0\n"
)

func TestParseWGDump(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		// indexed assertions on the parsed peers
		check func(t *testing.T, peers []wgPeer)
	}{
		{
			name:      "exit awg0 single peer",
			input:     wgDumpExit,
			wantCount: 1,
			check: func(t *testing.T, peers []wgPeer) {
				p := peers[0]
				if p.publicKey != "masterPubKeyBase64AAAAAAAAAAAAAAAAAAAAAAAA=" {
					t.Errorf("publicKey = %q", p.publicKey)
				}
				if p.latestHandshake != 1699999940 {
					t.Errorf("latestHandshake = %d, want 1699999940", p.latestHandshake)
				}
				if p.rxBytes != 10485760 || p.txBytes != 20971520 {
					t.Errorf("rx/tx = %v/%v, want 10485760/20971520", p.rxBytes, p.txBytes)
				}
			},
		},
		{
			name:      "two peers including never-handshook",
			input:     wgDumpTwoPeers,
			wantCount: 2,
			check: func(t *testing.T, peers []wgPeer) {
				if peers[1].latestHandshake != 0 {
					t.Errorf("peer B handshake = %d, want 0 (never)", peers[1].latestHandshake)
				}
			},
		},
		{
			name:      "interface-only output (no peers)",
			input:     "priv=\tpub=\t51820\toff\n",
			wantCount: 0,
		},
		{
			name:      "empty output",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "malformed peer line skipped, valid kept",
			input:     "priv=\tpub=\t51820\toff\ntooFewFields\tonly\nokPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(none)\t1.2.3.4:5\t10.0.0.2/32\t1699999900\t1000\t2000\t0\n",
			wantCount: 1,
			check: func(t *testing.T, peers []wgPeer) {
				if peers[0].publicKey != "okPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" {
					t.Errorf("publicKey = %q", peers[0].publicKey)
				}
			},
		},
		{
			name:      "non-numeric handshake skipped",
			input:     "priv=\tpub=\t51820\toff\npeerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=\t(none)\t1.2.3.4:5\t10.0.0.2/32\tnotanumber\t1000\t2000\t0\n",
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers := parseWGDump(tt.input)
			if len(peers) != tt.wantCount {
				t.Fatalf("parsed %d peers, want %d: %+v", len(peers), tt.wantCount, peers)
			}
			if tt.check != nil {
				tt.check(t, peers)
			}
		})
	}
}

func TestShortPeerID(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"masterPubKeyBase64AAAA=", "masterPu"},
		{"short", "short"},
		{"", ""},
		{"12345678", "12345678"},
		{"123456789", "12345678"},
	}
	for _, tt := range tests {
		if got := shortPeerID(tt.in); got != tt.want {
			t.Errorf("shortPeerID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestWGCollectorSeries exercises the full Collector path with an injected dump
// fixture and a fixed clock, asserting the emitted series + the active-peer count.
func TestWGCollectorSeries(t *testing.T) {
	dump := func(_ context.Context, iface string) (string, error) {
		if iface == "awg0" {
			return wgDumpTwoPeers, nil
		}
		return "", errNoIface // a down/absent interface fails soft
	}
	// Build with a fixed clock so handshake_age is deterministic.
	reg, c := newTestWGCollector(t, []string{"awg0", "wgcf"}, dump)
	c.now = func() time.Time { return time.Unix(1699999960, 0) } // 60s after peer A's handshake

	// peer A handshook at 1699999900 → age 60s (active); peer B never (age absent).
	want := `
# HELP wgfleet_wg_peers_active Number of peers on an interface with a handshake within the recent window.
# TYPE wgfleet_wg_peers_active gauge
wgfleet_wg_peers_active{iface="awg0",node="exit-de-1",role="exit"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_wg_peers_active"); err != nil {
		t.Error(err)
	}

	wantAge := `
# HELP wgfleet_wg_handshake_age_seconds Seconds since a WireGuard/AmneziaWG peer's last handshake (absent if it never handshook).
# TYPE wgfleet_wg_handshake_age_seconds gauge
wgfleet_wg_handshake_age_seconds{iface="awg0",node="exit-de-1",peer="peerAAAA",role="exit"} 60
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantAge), "wgfleet_wg_handshake_age_seconds"); err != nil {
		t.Error(err)
	}
}
