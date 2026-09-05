//go:build linux

package health

import (
	"net"
	"strconv"
	"testing"
)

// The real bind, on the only platform where it means anything.
//
// Everything else about this probe is tested with an injected function so the
// logic can be exercised on a dev laptop, but the logic is not the interesting
// part — the interesting part is that Linux refuses the bind when another socket
// already holds the port without SO_REUSEADDR, which is exactly what a kernel
// WireGuard interface is. That behaviour cannot be asserted anywhere but here, and
// it is the entire premise of the feature.
func TestUDPReturnBindableSeesAWildcardHolder(t *testing.T) {
	held, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("take a wildcard port: %v", err)
	}
	defer func() { _ = held.Close() }()
	taken := held.LocalAddr().(*net.UDPAddr).Port

	ok, err := UDPReturnBindable(taken)
	if err != nil {
		t.Skipf("probe could not be taken (needs CAP_NET_ADMIN): %v", err)
	}
	if ok {
		t.Errorf("port %d is held by a wildcard socket, but the probe says a reply socket is possible", taken)
	}

	free, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.LocalAddr().(*net.UDPAddr).Port
	_ = free.Close()

	ok, err = UDPReturnBindable(freePort)
	if err != nil {
		t.Fatalf("probe errored on a free port: %v", err)
	}
	if !ok {
		t.Errorf("port %d is free, but the probe says a reply socket is impossible", freePort)
	}
}

// The port list must come from the kernel, and it must be the list of SERVICES
// rather than the list of sockets.
//
// Both halves are asserted against a live /proc/net/udp because both are about
// what the kernel actually prints. A service port has to appear: that is the
// whole mechanism, and a list that misses one is a black hole nobody is told
// about. An ephemeral port must NOT appear: every outbound datagram this master
// sends takes one, and counting them would mint a fresh `port` label on the gauge
// every pass and flap the check between healthy and broken on whichever high port
// happened to be open when it looked.
func TestHeldUDPPortsListsServicesAndNotEphemeralSockets(t *testing.T) {
	lo, hi := ephemeralRange()

	// A service: a port below the kernel's ephemeral range, so it reads as something
	// deliberately bound rather than something handed out.
	service, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = service.Close()
	const servicePort = 10053
	svc, err := net.ListenPacket("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(servicePort)))
	if err != nil {
		t.Skipf("cannot take :%d on this machine (%v); nothing to assert", servicePort, err)
	}
	defer func() { _ = svc.Close() }()
	if servicePort >= lo && servicePort <= hi {
		t.Skipf("this kernel hands out :%d (range %d-%d), so it is not a service port here",
			servicePort, lo, hi)
	}

	// And an ephemeral one, taken the way an outbound socket takes it.
	ephemeral, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ephemeral.Close() }()
	taken := ephemeral.LocalAddr().(*net.UDPAddr).Port

	ports, err := HeldUDPPorts()
	if err != nil {
		t.Fatalf("read the socket table: %v", err)
	}
	seen := map[int]bool{}
	for _, p := range ports {
		seen[p] = true
	}
	if !seen[servicePort] {
		t.Errorf("port %d is bound and outside the ephemeral range, but is not among the %d ports read: "+
			"a service that black-holes client traffic would go unreported", servicePort, len(ports))
	}
	if taken >= lo && taken <= hi && seen[taken] {
		t.Errorf("ephemeral port %d was counted as a service; every outbound datagram would mint a metric series",
			taken)
	}
}
