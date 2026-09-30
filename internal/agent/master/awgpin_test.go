package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Lines as `conntrack -L -p udp -d <exit> --dport <awg>` prints them.
const (
	ctStaleAssured = "udp      17 117 src=100.127.255.2 dst=198.51.100.7 sport=48310 dport=30670 src=198.51.100.7 dst=203.0.113.1 sport=30670 dport=48310 [ASSURED] mark=0 use=1"
	ctFreshWaiting = "udp      17 28 src=100.127.255.2 dst=198.51.100.7 sport=50446 dport=30670 [UNREPLIED] src=198.51.100.7 dst=203.0.113.1 sport=30670 dport=48310 mark=0 use=1"
	ctUnpinned     = "udp      17 117 src=100.127.255.2 dst=198.51.100.7 sport=50446 dport=30670 src=198.51.100.7 dst=203.0.113.1 sport=30670 dport=50446 [ASSURED] mark=0 use=1"
	ctLive         = "udp      17 117 src=100.127.255.2 dst=198.51.100.7 sport=50446 dport=30670 src=198.51.100.7 dst=203.0.113.1 sport=30670 dport=48310 [ASSURED] mark=0 use=1"
)

func TestParseConntrackUDP(t *testing.T) {
	got := parseConntrackUDP(ctFreshWaiting + "\nconntrack v1.4.8 (conntrack-tools): 1 flow entries have been shown.\n")
	if len(got) != 1 {
		t.Fatalf("parsed %d entries, want 1: %+v", len(got), got)
	}
	e := got[0]
	if e.origSrc != "100.127.255.2" || e.origSport != 50446 || e.replyDport != 48310 || !e.unreplied {
		t.Fatalf("parsed entry = %+v", e)
	}
}

func TestStaleAWGPinEntries(t *testing.T) {
	cases := []struct {
		name      string
		lines     []string
		wantPorts []int // origSport of the entries to delete
	}{
		{"one live entry is left alone", []string{ctLive}, nil},
		{"a lone fresh attempt is left alone", []string{ctFreshWaiting}, nil},
		// The flag came on over a flow NAT had already mapped elsewhere: NAT is
		// decided once per flow, so it keeps its old port until it is deleted.
		{"a flow mapped to another port", []string{ctUnpinned}, []int{50446}},
		// mihomo restarted: the old entry keeps taking the exit's replies (its
		// keepalives refresh it forever) while the new one waits unreplied.
		{"stale entry beside mihomo's new attempt", []string{ctStaleAssured, ctFreshWaiting}, []int{48310}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stale := staleAWGPinEntries(parseConntrackUDP(strings.Join(tc.lines, "\n")), 48310)
			if len(stale) != len(tc.wantPorts) {
				t.Fatalf("stale = %+v, want sports %v", stale, tc.wantPorts)
			}
			for i, p := range tc.wantPorts {
				if stale[i].origSport != p {
					t.Fatalf("stale[%d].origSport = %d, want %d", i, stale[i].origSport, p)
				}
			}
		})
	}
}

// Several attempts and none answered: nothing tells which one mihomo is using,
// so all go and the next packet starts one clean entry.
func TestStaleAWGPinEntriesClearsCompetingAttempts(t *testing.T) {
	second := strings.Replace(ctFreshWaiting, "sport=50446", "sport=50999", 1)
	stale := staleAWGPinEntries(parseConntrackUDP(ctFreshWaiting+"\n"+second), 48310)
	if len(stale) != 2 {
		t.Fatalf("stale = %+v, want both unreplied attempts", stale)
	}
}

func TestAWGPinPlannerDeletesStaleAndTheManualTable(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "vn0", Endpoint: "198.51.100.7:30670", Transport: domain.TransportAWG, MasterAddr: "203.0.113.1:48310"},
	}}}
	p := awgPinPlanner{
		list:        func(context.Context, string, int) (string, error) { return ctStaleAssured + "\n" + ctFreshWaiting, nil },
		tableExists: func(string) bool { return true },
	}
	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var shown []string
	for _, a := range actions {
		if a.Changes() {
			shown = append(shown, a.Display)
		}
	}
	joined := strings.Join(shown, "\n")
	for _, want := range []string{
		"nft delete table ip " + legacyAWGPinTable,
		"conntrack -D -p udp -s 100.127.255.2 -d 198.51.100.7 --sport 48310 --dport 30670",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, shown)
		}
	}
	if strings.Contains(joined, "--sport 50446") {
		t.Errorf("deleted mihomo's live attempt: %v", shown)
	}
}

// With no armed tunnel there is no pin to protect, and the manual table is the
// only thing keeping a tunnel like vn0 alive until the controller arms it.
func TestAWGPinPlannerDoesNothingWithoutAnArmedTunnel(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{}}
	p := awgPinPlanner{
		list:        func(context.Context, string, int) (string, error) { t.Fatal("listed conntrack"); return "", nil },
		tableExists: func(string) bool { return true },
	}
	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range actions {
		if a.Changes() {
			t.Fatalf("acted without an armed tunnel: %+v", a)
		}
	}
	var _ reconcile.DependentPlanner = p
	if p.DependsOn() != (masterNATPlanner{}).Component() {
		t.Fatalf("DependsOn = %q: conntrack must only be cleared once the pin is in the kernel", p.DependsOn())
	}
}
