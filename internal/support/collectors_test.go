package support

import (
	"context"
	"strings"
	"testing"
)

// The design's central correction: three of six real diagnoses were about things
// wgfleet does not own — a third-party unit in a busy loop, a stale listening
// socket, a failing third-party timer. Scoping collection to our own components
// loses exactly the cases that cannot be diagnosed any other way.
func TestNodeCollectorsReachBeyondWgfleetsOwnSurface(t *testing.T) {
	cmds := allCmds(NodeCollectors("exit"))
	for _, want := range []struct{ needle, why string }{
		{"--state=failed", "failed units fleet-wide, not just ours"},
		{"ss -", "listening sockets, to compare against ip addr"},
		{"ip addr", "addresses, to compare against listening sockets"},
		{"--disk-usage", "journal volume — a log-spewing unit is invisible without it"},
		{"df ", "disk headroom"},
		{"date ", "UTC clock, or logs from several nodes cannot be stitched"},
		{"uniq -c", "per-unit journal volume — the busy-loop-unit diagnosis this task exists for"},
	} {
		if !strings.Contains(cmds, want.needle) {
			t.Errorf("no collector runs %q — needed for %s", want.needle, want.why)
		}
	}
}

// awg showconf prints the private key. It must not appear anywhere.
func TestNodeCollectorsNeverRunShowconf(t *testing.T) {
	for _, role := range []string{"exit", "master"} {
		if strings.Contains(allCmds(NodeCollectors(role)), "showconf") {
			t.Errorf("role %s runs a showconf variant — that prints the private key", role)
		}
	}
}

// The manifest's boundary list is what makes "you can see what you send" true in
// both directions. It must name the files a reader would most fear were taken.
func TestNotCollectedNamesTheSecretBearingFiles(t *testing.T) {
	got := strings.Join(NotCollected(), "\n")
	for _, want := range []string{
		"controller.yaml", "agent.yaml", "mihomo", "xray", "awg0.conf", "wgcf.conf",
		"wg-easy", "node.key", "ca.key", "sops",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("NotCollected() does not mention %q", want)
		}
	}
}

func TestNodeCollectorsRunAgainstAFakeRunner(t *testing.T) {
	r := fakeRunner{out: map[string]string{}}
	n, err := Collect(context.Background(), r, NodeCollectors("exit"), Options{Node: "e1", Role: "exit"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Every collector fails against an empty fake runner; the bundle must still
	// be produced, with each failure recorded.
	if len(n.Entries) == 0 {
		t.Fatal("no manifest entries")
	}
	for _, f := range []string{"identity.txt", "network.txt", "services.txt", "logs.txt"} {
		if _, ok := n.Files[f]; !ok {
			t.Errorf("no %s section produced", f)
		}
	}
}

func allCmds(cs []Collector) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(c.Cmd)
		b.WriteString("\n")
	}
	return b.String()
}
