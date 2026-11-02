package nodeexporter

import (
	"strings"
	"testing"
)

// A /proc/net/tcp table: header plus the rows each test needs. The columns after
// the third are ignored by the parser, so they are filled with the shape the
// kernel prints rather than with real values.
func tcpTable(rows ...string) string {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	return header + strings.Join(rows, "\n") + "\n"
}

// 9100 = 0x238C. 10.20.3.10 little-endian per word = 0A03140A.
const (
	listenMgmt     = "   0: 0A03140A:238C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100 0 0 10 0"
	listenWildcard = "   1: 00000000:238C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000 100 0 0 10 0"
	listenLoopback = "   2: 0100007F:238C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000 100 0 0 10 0"
	listenOther    = "   3: 0A03140A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000 100 0 0 10 0"
	// A scrape in flight: same port, but it has a peer, so it is a conversation
	// and not a listener. Counting it would make the planner believe the exporter
	// is bound for as long as somebody is talking to a dead one.
	establishedOnPort = "   4: 0A03140A:238C AC1B0164:C142 01 00000000:00000000 00:00000000 00000000     0        0 12349 1 0000 100 0 0 10 0"
)

func TestListenAddrsFromTable_OnlyListenersOnThePort(t *testing.T) {
	got := ListenAddrsFrom(strings.NewReader(tcpTable(listenMgmt, listenOther, establishedOnPort)), 9100, false)
	if len(got) != 1 || got[0] != "10.20.3.10" {
		t.Fatalf("want just the listener on 9100, got %v", got)
	}
}

func TestListenAddrsFromTable_WildcardAndLoopback(t *testing.T) {
	got := ListenAddrsFrom(strings.NewReader(tcpTable(listenWildcard, listenLoopback)), 9100, false)
	if len(got) != 2 || got[0] != "0.0.0.0" || got[1] != "127.0.0.1" {
		t.Fatalf("want the wildcard and the loopback listener, got %v", got)
	}
}

// The v6 table packs the address as four 32-bit words, each little-endian. Read
// as one blob it decodes to a different address entirely, so an exporter on [::]
// would read as bound to something harmless.
func TestListenAddrsFromTable_V6Wildcard(t *testing.T) {
	row := "   0: 00000000000000000000000000000000:238C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0000 100 0 0 10 0"
	got := ListenAddrsFrom(strings.NewReader(tcpTable(row)), 9100, true)
	if len(got) != 1 || got[0] != "::" {
		t.Fatalf("want the v6 wildcard, got %v", got)
	}
}

func TestClassifyBind(t *testing.T) {
	const mgmt = "10.20.3.10"
	for _, tc := range []struct {
		name  string
		addrs []string
		want  Bind
	}{
		{"nothing listening", nil, BindNone},
		{"the mgmt address", []string{mgmt}, BindMgmt},
		{"mgmt plus loopback", []string{"127.0.0.1", mgmt}, BindMgmt},
		{"loopback only", []string{"127.0.0.1"}, BindNone},
		{"the v4 wildcard", []string{"0.0.0.0"}, BindExposed},
		{"the v6 wildcard", []string{"::"}, BindExposed},
		// The one that matters: a wildcard answers on the mgmt address too, so a
		// probe that only asks "does <mgmt>:9100 reply" reads an exporter open to
		// the whole internet as correctly bound.
		{"wildcard alongside mgmt", []string{mgmt, "0.0.0.0"}, BindExposed},
		{"some other address", []string{"192.0.2.7"}, BindExposed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyBind(tc.addrs, mgmt); got != tc.want {
				t.Errorf("ClassifyBind(%v) = %v, want %v", tc.addrs, got, tc.want)
			}
		})
	}
}

// With no mgmt address we cannot tell a correct bind from an exposed one, and
// guessing towards "fine" is how a public listener survives a reconcile pass.
func TestClassifyBind_UnknownMgmtAddressIsNeverMgmt(t *testing.T) {
	if got := ClassifyBind([]string{"192.0.2.7"}, ""); got != BindExposed {
		t.Errorf("want exposed without a mgmt address, got %v", got)
	}
	if got := ClassifyBind([]string{"127.0.0.1"}, ""); got != BindNone {
		t.Errorf("loopback is not exposed, got %v", got)
	}
}
