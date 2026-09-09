package wgiface

import (
	"errors"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// liveReader returns an injected live-peer reader for the named interface.
func liveReader(t *testing.T, iface string, peers []string, err error) func(string) ([]string, error) {
	t.Helper()
	return func(name string) ([]string, error) {
		if name != iface {
			t.Fatalf("live reader asked about %q, want %q", name, iface)
		}
		return peers, err
	}
}

const (
	ifaceCfg = "[Interface]\nAddress = 10.9.0.1/24\nListenPort = 443\n\n"
	peerA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0="
	peerB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0="
	peerC    = "cccccccccccccccccccccccccccccccccccccccccc0="
)

func TestNameStripsDirectoryAndSuffix(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/etc/amnezia/amneziawg/awg0.conf", "awg0"},
		{"awgl0.conf", "awgl0"},
		{"/tmp/wg0", "wg0"},
	} {
		if got := Name(tc.path); got != tc.want {
			t.Fatalf("Name(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestPeerDeltaAddsOneMissingPeer(t *testing.T) {
	want := []domain.WGClientPeer{
		{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"},
		{Name: "bob", PublicKey: peerB, Address: "10.9.0.3/32"},
	}
	actions := PeerDelta("awg0", want, ifaceCfg+"[Peer]\nPublicKey = "+peerA+"\n",
		ifaceCfg+"[Peer]\nPublicKey = "+peerA+"\n[Peer]\nPublicKey = "+peerB+"\n",
		liveReader(t, "awg0", []string{peerA}, nil))
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want exactly 1: %+v", len(actions), actions)
	}
	const wantCmd = "awg set awg0 peer " + peerB + " allowed-ips 10.9.0.3/32"
	if actions[0].Display != wantCmd {
		t.Fatalf("action display = %q, want %q", actions[0].Display, wantCmd)
	}
}

func TestPeerDeltaAddsHostPrefixToBareAddress(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", nil, nil))
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want exactly 1", len(actions))
	}
	const wantCmd = "awg set awg0 peer " + peerA + " allowed-ips 10.9.0.2/32"
	if actions[0].Display != wantCmd {
		t.Fatalf("action display = %q, want %q", actions[0].Display, wantCmd)
	}
}

// Every credential the controller issues carries a preshared key (a derived one,
// per exit, on the lifeline — ADR-0034). A peer delta that refuses them is a
// delta that never runs in production: adding one client would bounce the device
// and drop every other session on it. The key goes to `awg set` in a file.
func TestPeerDeltaPatchesAPeerCarryingAPresharedKey(t *testing.T) {
	want := []domain.WGClientPeer{
		{Name: "alice", PublicKey: peerA, Address: "10.9.0.2", PresharedKey: "c2VjcmV0"},
	}
	actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg, liveReader(t, "awg0", nil, nil))
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want exactly 1: %+v", len(actions), actions)
	}
	const wantCmd = "awg set awg0 peer " + peerA + " preshared-key <file> allowed-ips 10.9.0.2/32"
	if actions[0].Display != wantCmd {
		t.Fatalf("action display = %q, want %q", actions[0].Display, wantCmd)
	}
}

// The plan line is shown to an operator and may be journalled, so the secret must
// not be anywhere in it — neither on a command line nor in the summary.
func TestPeerDeltaNeverShowsThePresharedKey(t *testing.T) {
	const secret = "dGhpcy1pcy1hLXNlY3JldC1wcmVzaGFyZWQta2V5ISE="
	want := []domain.WGClientPeer{
		{Name: "alice", PublicKey: peerA, Address: "10.9.0.2", PresharedKey: secret},
	}
	actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg, liveReader(t, "awg0", nil, nil))
	for _, a := range actions {
		if strings.Contains(a.Display, secret) || strings.Contains(a.Summary, secret) {
			t.Fatalf("the preshared key leaked into the plan: %+v", a)
		}
	}
}

// Pausing or revoking ONE credential must cost that credential its session and
// nobody else theirs. It used to cost everybody: an unwanted live peer sent the
// whole device through down/up, and on the lifeline the people on it are there
// precisely because their normal path is already gone.
func TestPeerDeltaRemovesARevokedPeerWithoutBouncing(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", []string{peerA, peerB}, nil))
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want exactly 1: %+v", len(actions), actions)
	}
	const wantCmd = "awg set awg0 peer " + peerB + " remove"
	if actions[0].Display != wantCmd {
		t.Fatalf("action display = %q, want %q", actions[0].Display, wantCmd)
	}
}

// One pass may both onboard and revoke; neither is a reason to touch the device.
func TestPeerDeltaAddsAndRemovesInOnePass(t *testing.T) {
	want := []domain.WGClientPeer{
		{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"},
		{Name: "carol", PublicKey: peerC, Address: "10.9.0.4"},
	}
	actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", []string{peerA, peerB}, nil))
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want exactly 2: %+v", len(actions), actions)
	}
	var got []string
	for _, a := range actions {
		got = append(got, a.Display)
	}
	joined := strings.Join(got, "\n")
	for _, wantCmd := range []string{
		"awg set awg0 peer " + peerC + " allowed-ips 10.9.0.4/32",
		"awg set awg0 peer " + peerB + " remove",
	} {
		if !strings.Contains(joined, wantCmd) {
			t.Fatalf("missing %q in:\n%s", wantCmd, joined)
		}
	}
}

func TestPeerDeltaRefusesPeerWithoutAddress(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA}}
	if actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", nil, nil)); actions != nil {
		t.Fatalf("a peer with no address must fall back to a bring-up, got %+v", actions)
	}
}

// A live peer list with NOTHING in common with the wanted one is not our list at
// all — it is how a wg-easy container that recreated wg0 after a reboot presents
// itself, and its interface parameters are wg-easy's too. Emptying it one `awg
// set … remove` at a time would leave the kernel serving the right people with
// the wrong obfuscation; only a rebuild puts that right.
func TestPeerDeltaRebuildsOnAnEntirelyForeignPeerList(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	if actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", []string{peerB}, nil)); actions != nil {
		t.Fatalf("somebody else's peer list must rebuild the device, got %+v", actions)
	}
}

func TestPeerDeltaRefusesChangedInterfaceSection(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	changed := "[Interface]\nAddress = 10.9.0.1/24\nListenPort = 51820\n\n"
	if actions := PeerDelta("awg0", want, ifaceCfg, changed,
		liveReader(t, "awg0", nil, nil)); actions != nil {
		t.Fatalf("a moved [Interface] section cannot be applied with awg set, got %+v", actions)
	}
}

func TestPeerDeltaRefusesEmptyPreviousConfig(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	if actions := PeerDelta("awg0", want, "", ifaceCfg,
		liveReader(t, "awg0", nil, nil)); actions != nil {
		t.Fatalf("no previous config means nothing to diff against, got %+v", actions)
	}
}

func TestPeerDeltaNilWhenNothingToAdd(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	if actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", []string{peerA}, nil)); actions != nil {
		t.Fatalf("a converged peer list needs no actions, got %+v", actions)
	}
}

func TestPeerDeltaNilWhenLivePeersUnreadable(t *testing.T) {
	want := []domain.WGClientPeer{{Name: "alice", PublicKey: peerA, Address: "10.9.0.2"}}
	if actions := PeerDelta("awg0", want, ifaceCfg, ifaceCfg,
		liveReader(t, "awg0", nil, errors.New("no such device"))); actions != nil {
		t.Fatalf("an unreadable interface cannot be patched, got %+v", actions)
	}
}

func TestServesPeersMatchesExactSet(t *testing.T) {
	want := []domain.WGClientPeer{{PublicKey: peerA}, {PublicKey: peerB}}
	matches, known := ServesPeers("awg0", want, liveReader(t, "awg0", []string{peerB, peerA}, nil))
	if !matches || !known {
		t.Fatalf("matches=%v known=%v, want true/true", matches, known)
	}
}

func TestServesPeersReportsMismatch(t *testing.T) {
	want := []domain.WGClientPeer{{PublicKey: peerA}}
	matches, known := ServesPeers("awg0", want, liveReader(t, "awg0", []string{peerB}, nil))
	if matches || !known {
		t.Fatalf("matches=%v known=%v, want false/true", matches, known)
	}
}

func TestServesPeersFailsOpenOnProbeError(t *testing.T) {
	want := []domain.WGClientPeer{{PublicKey: peerA}}
	matches, known := ServesPeers("awg0", want, liveReader(t, "awg0", nil, errors.New("boom")))
	if !matches || known {
		t.Fatalf("matches=%v known=%v, want true/false (fail open, but say so)", matches, known)
	}
}

func TestQuickActionUserspaceCarriesTheImplementationEnv(t *testing.T) {
	a := QuickAction(domain.ClientWGBackendUserspace, "up", "/etc/amnezia/amneziawg/awg0.conf", false, "bring up")
	const wantCmd = "sh -c WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up '/etc/amnezia/amneziawg/awg0.conf'"
	if a.Display != wantCmd {
		t.Fatalf("display = %q, want %q", a.Display, wantCmd)
	}
	if a.NonFatal {
		t.Fatal("a non best-effort action must be fatal on failure")
	}
	k := QuickAction(domain.ClientWGBackendKernel, "down", "/etc/awg0.conf", true, "bring down")
	if k.Display != "awg-quick down /etc/awg0.conf" {
		t.Fatalf("kernel display = %q", k.Display)
	}
	if !k.NonFatal {
		t.Fatal("a best-effort action must be non-fatal")
	}
}
