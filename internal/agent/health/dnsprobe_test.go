package health

import (
	"context"
	"net"
	"strings"
	"testing"
)

// The probe must talk UDP to the server it was given and to nothing else. This
// asserts it by standing up a UDP listener on loopback and checking the query
// arrives there — the resolv.conf on the machine running the test is irrelevant,
// which is exactly the property the probe exists to have.
func TestQueryDNSOverUDPDialsTheGivenServerNotResolvConf(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()

	got := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		if _, _, rerr := pc.ReadFrom(buf); rerr == nil {
			got <- struct{}{}
		}
	}()

	// The server never answers, so the query fails — the assertion is that it was
	// ASKED, not that it succeeded.
	_ = QueryDNSOverUDP(context.Background(), pc.LocalAddr().String())
	select {
	case <-got:
	default:
		t.Fatal("the probe never sent a datagram to the server it was given; it went somewhere else")
	}
}

// A server that says nothing must fail the probe rather than time out into a pass.
func TestQueryDNSOverUDPFailsOnSilence(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()

	if err := QueryDNSOverUDP(context.Background(), pc.LocalAddr().String()); err == nil {
		t.Fatal("a silent resolver was reported as a working UDP path")
	}
}

func TestQueryDNSOverUDPRejectsAServerWithoutAPort(t *testing.T) {
	err := QueryDNSOverUDP(context.Background(), "1.1.1.1")
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("want a host:port complaint, got %v", err)
	}
}
