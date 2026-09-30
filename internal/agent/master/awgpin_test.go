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
	ctStaleAssured = "udp      17 117 src=100.127.255.2 dst=198.51.100.7 sport=41234 dport=35555 src=198.51.100.7 dst=203.0.113.1 sport=35555 dport=41234 [ASSURED] mark=0 use=1"
	ctFreshWaiting = "udp      17 28 src=100.127.255.2 dst=198.51.100.7 sport=50446 dport=35555 [UNREPLIED] src=198.51.100.7 dst=203.0.113.1 sport=35555 dport=41234 mark=0 use=1"
	ctUnpinned     = "udp      17 117 src=100.127.255.2 dst=198.51.100.7 sport=50446 dport=35555 src=198.51.100.7 dst=203.0.113.1 sport=35555 dport=50446 [ASSURED] mark=0 use=1"
	ctLive         = "udp      17 117 src=100.127.255.2 dst=198.51.100.7 sport=50446 dport=35555 src=198.51.100.7 dst=203.0.113.1 sport=35555 dport=41234 [ASSURED] mark=0 use=1"
)

func TestParseConntrackUDP(t *testing.T) {
	got := parseConntrackUDP(ctFreshWaiting + "\nconntrack v1.4.8 (conntrack-tools): 1 flow entries have been shown.\n")
	if len(got) != 1 {
		t.Fatalf("parsed %d entries, want 1: %+v", len(got), got)
	}
	e := got[0]
	if e.origSrc != "100.127.255.2" || e.origSport != 50446 || e.replyDport != 41234 || !e.unreplied {
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
		{"stale entry beside mihomo's new attempt", []string{ctStaleAssured, ctFreshWaiting}, []int{41234}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stale := staleAWGPinEntries(parseConntrackUDP(strings.Join(tc.lines, "\n")), 41234)
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
	stale := staleAWGPinEntries(parseConntrackUDP(ctFreshWaiting+"\n"+second), 41234)
	if len(stale) != 2 {
		t.Fatalf("stale = %+v, want both unreplied attempts", stale)
	}
}

func TestAWGPinPlannerDeletesStaleAndTheManualTable(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "exit-a", Endpoint: "198.51.100.7:35555", Transport: domain.TransportAWG, MasterAddr: "203.0.113.1:41234"},
	}}}
	p := awgPinPlanner{
		list:        func(context.Context, string, int) (string, error) { return ctStaleAssured + "\n" + ctFreshWaiting, nil },
		listKnocks:  func(context.Context, string, int, int) (string, error) { return "", nil },
		tableExists: func(string) bool { return true },
		heard:       func(string) bool { return true },
		sockets:     func(context.Context, string) (map[string]bool, bool) { return nil, false },
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
		"conntrack -D -p udp -s 100.127.255.2 -d 198.51.100.7 --sport 41234 --dport 35555",
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
// only thing keeping a tunnel alive until the controller arms it.
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

// Right after arming, the heard set is empty until the exit's next keepalive.
// Deleting the working entry then turns mihomo's next packet into a NEW flow the
// gate holds back — up to one keepalive of outage for nothing. Wait for the knock.
func TestAWGPinPlannerWaitsForTheExitToBeHeard(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "exit-a", Endpoint: "198.51.100.7:35555", Transport: domain.TransportAWG, MasterAddr: "203.0.113.1:41234"},
	}}}
	p := awgPinPlanner{
		list:        func(context.Context, string, int) (string, error) { return ctUnpinned, nil },
		tableExists: func(string) bool { return true },
		heard:       func(string) bool { return false },
	}
	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range actions {
		if a.Changes() {
			t.Fatalf("acted before the exit was heard: %s", a.Display)
		}
	}
}

// Found on the stand: the exit starts knocking the moment it has the endpoint,
// before the master has armed its gate and its knock-drop rule. A whitelisted
// exit's knock is then ACCEPTED, its conntrack entry confirmed, and every later
// knock refreshes it even once it is dropped. That entry holds the tuple the
// SNAT needs: mihomo's packets fail NAT (insert_failed) and its writes return
// EPERM, forever. The planner must delete it too.
func TestAWGPinPlannerDeletesAConfirmedKnock(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "exit-a", Endpoint: "198.51.100.7:35555", Transport: domain.TransportAWG, MasterAddr: "203.0.113.1:41234"},
	}}}
	const knock = "udp      17 24 src=198.51.100.7 dst=203.0.113.1 sport=35555 dport=41234 [UNREPLIED] src=203.0.113.1 dst=198.51.100.7 sport=41234 dport=35555 mark=0 use=1"
	p := awgPinPlanner{
		list:        func(context.Context, string, int) (string, error) { return "", nil },
		listKnocks:  func(context.Context, string, int, int) (string, error) { return knock, nil },
		tableExists: func(string) bool { return false },
		heard:       func(string) bool { return true },
		sockets:     func(context.Context, string) (map[string]bool, bool) { return nil, false },
	}
	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	want := "conntrack -D -p udp -s 198.51.100.7 -d 203.0.113.1 --sport 35555 --dport 41234"
	for _, a := range actions {
		if a.Changes() && a.Display == want {
			return
		}
	}
	t.Fatalf("confirmed knock not deleted; actions: %+v", actions)
}

// Found on the stand (kernel 5.15): after a mihomo restart the new socket's flow
// never reaches conntrack at all — the NAT clash fails its insert — so the old
// ASSURED entry is the ONLY one listed and looks healthy: the exit's keepalives
// keep answering it. What gives it away is that no mihomo socket owns it.
func TestStaleAWGPinEntriesUsesMihomosSockets(t *testing.T) {
	entries := parseConntrackUDP(ctLive) // orig sport 50446
	if got := staleAWGPinEntriesOwned(entries, 41234, map[string]bool{"100.127.255.2:50446": true}); len(got) != 0 {
		t.Fatalf("entry owned by a live socket deleted: %+v", got)
	}
	got := staleAWGPinEntriesOwned(entries, 41234, map[string]bool{"192.0.2.4:53703": true})
	if len(got) != 1 || got[0].origSport != 50446 {
		t.Fatalf("orphaned entry not selected: %+v", got)
	}
	// No live socket at all (mihomo between restarts): an orphan is still an orphan.
	if got := staleAWGPinEntriesOwned(entries, 41234, map[string]bool{}); len(got) != 1 {
		t.Fatalf("with no sockets the entry is orphaned, got %+v", got)
	}
}

func TestParseSSLocal(t *testing.T) {
	out := "ESTAB 0 0 192.0.2.4:53703 198.51.100.7:35555\nUNCONN 0 0 0.0.0.0:9993 0.0.0.0:*\n"
	got := parseSSLocal(out)
	if !got["192.0.2.4:53703"] || !got["0.0.0.0:9993"] || len(got) != 2 {
		t.Fatalf("parseSSLocal = %v", got)
	}
}
