package datapath

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/shidoh/wgfleet/internal/netfw"
)

// The leak this rehearsal is about is not the one the ruleset used to guard.
//
// `egress_leak_guard` hooks postrouting AFTER srcnat, so it sees a client address
// only when NAT failed to translate one — a real failure, and it catches it. The
// failure it cannot see is the one an empty namespace routing table produces:
// client traffic falls through to `main`, leaves by the uplink, and IS masqueraded
// on the way, so by the time that chain runs it is indistinguishable from the
// master's own traffic. That state is not exotic — the namespace holder is
// `restart: unless-stopped`, and every recreation empties the table until the next
// pass.
//
// So this drives one packet of exactly that shape on a live kernel and asserts
// both halves: that the ruleset as it was lets it through, and that the ruleset as
// it is stops it. The first half is why the second exists; without it the fix is a
// rule nobody has watched fail.
const (
	guardNS      = "wgf-guardtest"
	guardPool    = "10.73.0.0/24"
	guardClient  = "10.73.0.5" // a client address, not the gateway
	guardLeakDst = "203.0.113.5"
	guardDirect  = "198.51.100.0/24"
	guardDirect1 = "198.51.100.5"
)

func TestThePathGuardDropsTrafficThatEscapesTheNamespaceTable(t *testing.T) {
	requirePrivileges(t)
	requireNFT(t)
	ruleset := renderGuardRuleset(t)

	t.Run("as it was, the packet leaves and the old guard never sees it", func(t *testing.T) {
		before := withoutChain(t, ruleset, "egress_path_guard")
		got := runGuardProbe(t, before, guardLeakDst)
		if got["egress_leak_guard"] != 0 {
			t.Fatalf("the pre-fix ruleset was supposed to be blind to this packet and counted %d — "+
				"the rehearsal is not reproducing the defect", got["egress_leak_guard"])
		}
	})

	t.Run("as it is, the packet is dropped, and by the new chain", func(t *testing.T) {
		got := runGuardProbe(t, ruleset, guardLeakDst)
		if got["egress_path_guard"] != 1 {
			t.Errorf("a client packet leaving by the uplink was not caught by the path guard (counted %d)",
				got["egress_path_guard"])
		}
		if got["egress_leak_guard"] != 0 {
			t.Errorf("the packet survived to the post-NAT guard, so the path guard did not drop it")
		}
	})

	t.Run("the declared split tunnel still passes", func(t *testing.T) {
		// A direct destination leaves by the same uplink with the same client source
		// and is masqueraded the same way. The only thing separating it from a leak is
		// that the operator declared it — so a guard that drops it has traded a leak
		// for an outage.
		got := runGuardProbe(t, ruleset, guardDirect1)
		if got["egress_path_guard"] != 0 {
			t.Errorf("a declared direct destination was dropped as a leak (counted %d)",
				got["egress_path_guard"])
		}
	})
}

// TestGuardProbeSender is not a test of its own: it is the sender, re-entered
// inside the namespace by the test above, and it skips unless asked.
func TestGuardProbeSender(t *testing.T) {
	src, dst := os.Getenv("WGF_GUARD_SRC"), os.Getenv("WGF_GUARD_DST")
	if src == "" || dst == "" {
		t.Skip("not the sender")
	}
	// EPERM is not a failure here: for a LOCALLY generated packet the kernel reports
	// an nftables drop back to the sender as "operation not permitted". That is one
	// of the two outcomes under test, and it is not the verdict — the chain counter
	// is, because a forwarded client packet gets no such report and a test that read
	// the send result would be measuring the wrong thing in the real case.
	if err := sendSpoofed(src, dst); err != nil && !errors.Is(err, syscall.EPERM) {
		t.Fatalf("send %s -> %s: %v", src, dst, err)
	}
}

// renderGuardRuleset renders the real master ruleset rather than a hand-written
// stand-in, so a renderer change that breaks this is caught here and not in a file
// that merely resembles the product.
func renderGuardRuleset(t *testing.T) string {
	t.Helper()
	out, err := netfw.RenderMasterNAT(netfw.MasterNATInput{
		ClientInterface: "cli",
		ClientCIDR:      guardPool,
		RedirAddr:       "10.73.0.1:7895",
		TProxyAddr:      "10.73.0.1:7896",
		PrivateCIDRs:    []string{guardDirect},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// runGuardProbe builds a namespace holding the ruleset, sends ONE spoofed packet
// from a client address to dst, and returns each guard chain's packet counter.
func runGuardProbe(t *testing.T, ruleset, dst string) map[string]int {
	t.Helper()
	newGuardNS(t)

	// Two dummies: the client interface the guard exempts, and an uplink standing in
	// for ens3. A dummy swallows what it is handed, which is all this needs — the
	// verdict is in the counter, not in a reply.
	for _, argv := range [][]string{
		{"ip", "link", "add", "cli", "type", "dummy"},
		{"ip", "addr", "add", "10.73.0.1/24", "dev", "cli"},
		{"ip", "link", "set", "cli", "up"},
		{"ip", "link", "add", "up0", "type", "dummy"},
		{"ip", "addr", "add", "192.0.2.1/24", "dev", "up0"},
		{"ip", "link", "set", "up0", "up"},
		{"ip", "route", "add", "default", "dev", "up0"},
	} {
		inGuardNS(t, nil, argv...)
	}

	path := t.TempDir() + "/guard.nft"
	if err := os.WriteFile(path, []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	inGuardNS(t, nil, "nft", "-f", path)

	// The sender runs INSIDE the namespace: `ip netns exec` re-executes this binary,
	// which opens the raw socket where the ruleset is.
	inGuardNS(t, []string{"WGF_GUARD_SRC=" + guardClient, "WGF_GUARD_DST=" + dst},
		os.Args[0], "-test.run", "^TestGuardProbeSender$")

	return map[string]int{
		"egress_leak_guard": chainCounter(t, "egress_leak_guard"),
		"egress_path_guard": chainCounter(t, "egress_path_guard"),
	}
}

// sendSpoofed writes one IP+UDP packet through a raw socket with IP_HDRINCL, so the
// SOURCE is ours to choose. That is the point: a forwarded client packet has exactly
// that shape, and a locally generated one would be exempt for the wrong reason. The
// kernel fills the IP id and checksum; a zero UDP checksum is legal on IPv4.
func sendSpoofed(src, dst string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()

	s, d := parse4(src), parse4(dst)
	pkt := make([]byte, 28) // 20 IP + 8 UDP
	pkt[0] = 0x45
	pkt[3] = byte(len(pkt))
	pkt[8] = 64
	pkt[9] = syscall.IPPROTO_UDP
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	pkt[20], pkt[21] = 0x30, 0x39 // source port 12345
	pkt[22], pkt[23] = 0x00, 0x35 // destination port 53
	pkt[25] = 0x08                // UDP length

	return syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: d})
}

func parse4(s string) [4]byte {
	var out [4]byte
	for i, part := range strings.Split(s, ".") {
		if i > 3 {
			break
		}
		n, _ := strconv.Atoi(part)
		out[i] = byte(n)
	}
	return out
}

// chainCounter reads one chain's packet counter. A chain the ruleset does not have
// counts nothing, which is a fact about that ruleset rather than a failure.
//
// Scope: it returns the FIRST counter in the chain. Both guard chains hold exactly
// one rule, so that is the whole answer here — but a chain with two counted rules
// would silently report only the first, so do not reuse this for one.
func chainCounter(t *testing.T, chain string) int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", guardNS,
		"nft", "list", "chain", "ip", "wgfleet_master", chain).CombinedOutput()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "packets" && i+1 < len(fields) {
				n, _ := strconv.Atoi(fields[i+1])
				return n
			}
		}
	}
	return 0
}

// withoutChain returns the ruleset with one chain removed: the file as it was
// before that chain existed.
func withoutChain(t *testing.T, ruleset, chain string) string {
	t.Helper()
	start := strings.Index(ruleset, "\n\tchain "+chain+" {")
	if start < 0 {
		t.Fatalf("ruleset has no chain %q to remove", chain)
	}
	end := strings.Index(ruleset[start+1:], "\n\t}\n")
	if end < 0 {
		t.Fatalf("chain %q does not close", chain)
	}
	return ruleset[:start] + ruleset[start+1+end+len("\n\t}"):]
}

func newGuardNS(t *testing.T) {
	t.Helper()
	_ = exec.Command("ip", "netns", "del", guardNS).Run()
	if out, err := exec.Command("ip", "netns", "add", guardNS).CombinedOutput(); err != nil {
		t.Skipf("cannot create a network namespace here (%v): %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", guardNS).Run() })
	inGuardNS(t, nil, "ip", "link", "set", "lo", "up")
}

func inGuardNS(t *testing.T, env []string, argv ...string) {
	t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", guardNS}, argv...)...)
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", argv, err, out)
	}
}

func requireNFT(t *testing.T) {
	t.Helper()
	if err := exec.Command("nft", "--version").Run(); err != nil {
		t.Skipf("no usable nft here: %v", err)
	}
}
