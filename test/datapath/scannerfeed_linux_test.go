package datapath

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netfw"
)

// The scanner feed on a master is only safe if it matches connections someone
// else opens TOWARD the node and nothing else. The feed is full of Russian
// networks; if it matched replies, every client would lose every site hosted in
// them. So this drives real TCP across a veth pair on a live kernel:
//
//	feed-node (the master, with the rendered ruleset)  ⟷  feed-net (the internet)
//	10.99.0.1                                              10.99.0.2 (unlisted)
//	                                                       198.51.100.7 (listed)
const (
	feedNodeNS   = "wgf-feed-node"
	feedNetNS    = "wgf-feed-net"
	feedNodeAddr = "10.99.0.1"
	feedPlain    = "10.99.0.2"
	feedListed   = "198.51.100.7"
	feedPrefix   = "198.51.100.0/24"
	feedSSHPort  = 22
	feedWebPort  = 8080
	feedDialWait = 2 * time.Second
)

func TestScannerFeedOnALiveKernel(t *testing.T) {
	requirePrivileges(t)
	requireNFT(t)

	t.Run("observe counts a listed source and lets it in", func(t *testing.T) {
		newFeedLab(t, domain.FirewallSpec{ASBlacklistObserve: true})
		if !feedDial(t, feedNetNS, feedListed, feedNodeAddr, feedSSHPort) {
			t.Fatal("observe dropped a connection from a listed source")
		}
		if n := feedHits(t); n == 0 {
			t.Error("observe let the connection in but did not count it")
		}
	})

	t.Run("enforce drops a listed source and counts it", func(t *testing.T) {
		newFeedLab(t, domain.FirewallSpec{ASBlacklist: true})
		if feedDial(t, feedNetNS, feedListed, feedNodeAddr, feedSSHPort) {
			t.Fatal("enforce let a listed source open a connection")
		}
		if n := feedHits(t); n == 0 {
			t.Error("enforce dropped the connection without counting it")
		}
	})

	t.Run("enforce leaves an unlisted source alone", func(t *testing.T) {
		newFeedLab(t, domain.FirewallSpec{ASBlacklist: true})
		if !feedDial(t, feedNetNS, feedPlain, feedNodeAddr, feedSSHPort) {
			t.Fatal("enforce dropped a source that is not in the feed")
		}
		if n := feedHits(t); n != 0 {
			t.Errorf("an unlisted source was counted %d times", n)
		}
	})

	// The case the whole design rests on: the node dials a listed network and the
	// replies come back. A client reaching a site in a listed network is this.
	t.Run("enforce passes replies to a connection the node opened", func(t *testing.T) {
		newFeedLab(t, domain.FirewallSpec{ASBlacklist: true})
		if !feedDial(t, feedNodeNS, feedNodeAddr, feedListed, feedWebPort) {
			t.Fatal("enforce cut the replies to a connection the node opened to a listed network")
		}
		if n := feedHits(t); n != 0 {
			t.Errorf("replies were counted as scanner hits %d times", n)
		}
	})

	t.Run("enforce never catches a whitelisted source", func(t *testing.T) {
		newFeedLab(t, domain.FirewallSpec{ASBlacklist: true, Whitelist: []string{feedListed + "/32"}})
		if !feedDial(t, feedNetNS, feedListed, feedNodeAddr, feedSSHPort) {
			t.Fatal("a whitelisted source inside the feed was dropped")
		}
	})
}

// TestFeedHelper is not a test: the lab re-executes this binary inside a
// namespace to listen or dial there. It does nothing when run directly.
func TestFeedHelper(t *testing.T) {
	switch os.Getenv("WGF_FEED_ROLE") {
	case "listen":
		ln, err := net.Listen("tcp", os.Getenv("WGF_FEED_ADDR"))
		if err != nil {
			t.Fatal(err)
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok\n"))
			_ = c.Close()
		}
	case "dial":
		d := net.Dialer{
			Timeout:   feedDialWait,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(os.Getenv("WGF_FEED_SRC"))},
		}
		c, err := d.Dial("tcp", os.Getenv("WGF_FEED_ADDR"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(feedDialWait))
		buf := make([]byte, 3)
		if _, err := c.Read(buf); err != nil || string(buf) != "ok\n" {
			t.Fatalf("no answer over the connection: %v %q", err, buf)
		}
	}
}

// newFeedLab builds both namespaces, applies the master ruleset rendered for fw
// with a one-prefix feed, and starts a listener on each side.
func newFeedLab(t *testing.T, fw domain.FirewallSpec) {
	t.Helper()
	for _, ns := range []string{feedNodeNS, feedNetNS} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Skipf("cannot create a network namespace here (%v): %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		feedIn(t, ns, "ip", "link", "set", "lo", "up")
	}
	feedRun(t, "ip", "link", "add", "fn0", "netns", feedNodeNS, "type", "veth", "peer", "name", "fi0", "netns", feedNetNS)
	feedIn(t, feedNodeNS, "ip", "addr", "add", feedNodeAddr+"/24", "dev", "fn0")
	feedIn(t, feedNodeNS, "ip", "link", "set", "fn0", "up")
	feedIn(t, feedNodeNS, "ip", "route", "add", feedPrefix, "dev", "fn0")
	feedIn(t, feedNetNS, "ip", "addr", "add", feedPlain+"/24", "dev", "fi0")
	feedIn(t, feedNetNS, "ip", "addr", "add", feedListed+"/32", "dev", "fi0")
	feedIn(t, feedNetNS, "ip", "link", "set", "fi0", "up")

	fw.WGPort = 443
	ruleset, err := netfw.RenderRuleset(netfw.RenderInput{
		Role:          domain.RoleMaster,
		Firewall:      fw,
		ASBlacklistV4: []string{feedPrefix},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	path := t.TempDir() + "/feed.nft"
	if err := os.WriteFile(path, []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	feedIn(t, feedNodeNS, "nft", "-f", path)

	feedListen(t, feedNodeNS, net.JoinHostPort(feedNodeAddr, strconv.Itoa(feedSSHPort)))
	feedListen(t, feedNetNS, net.JoinHostPort(feedListed, strconv.Itoa(feedWebPort)))
}

func feedListen(t *testing.T, ns, addr string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run", "^TestFeedHelper$")
	cmd.Env = append(os.Environ(), "WGF_FEED_ROLE=listen", "WGF_FEED_ADDR="+addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	// Wait for the listener rather than racing the first dial against it.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("ip", "netns", "exec", ns, "ss", "-Htln", "src", addr).Output()
		if strings.TrimSpace(string(out)) != "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("listener on %s in %s never came up", addr, ns)
}

// feedDial reports whether a TCP connection from src (inside ns) to dst:port
// opens and carries the listener's greeting.
func feedDial(t *testing.T, ns, src, dst string, port int) bool {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run", "^TestFeedHelper$")
	cmd.Env = append(os.Environ(), "WGF_FEED_ROLE=dial", "WGF_FEED_SRC="+src,
		"WGF_FEED_ADDR="+net.JoinHostPort(dst, strconv.Itoa(port)))
	return cmd.Run() == nil
}

// feedHits reads the named counter on the feed rule.
func feedHits(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", feedNodeNS,
		"nft", "list", "counter", "inet", netfw.ExitTable, netfw.ASBlacklistHitsCounter).CombinedOutput()
	if err != nil {
		t.Fatalf("read counter: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			n, _ := strconv.Atoi(fields[i+1])
			return n
		}
	}
	t.Fatalf("no packet count in:\n%s", out)
	return 0
}

func feedIn(t *testing.T, ns string, argv ...string) {
	t.Helper()
	feedRun(t, append([]string{"ip", "netns", "exec", ns}, argv...)...)
}

func feedRun(t *testing.T, argv ...string) {
	t.Helper()
	if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", argv, err, out)
	}
}
