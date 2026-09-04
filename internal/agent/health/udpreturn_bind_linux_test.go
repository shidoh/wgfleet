//go:build linux

package health

import (
	"net"
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

// The port list must come from the kernel. On a real Linux box this must return
// something — a machine with no UDP sockets at all does not exist in practice —
// and it must include a port we have just taken.
func TestHeldUDPPortsReadsTheLiveSocketTable(t *testing.T) {
	held, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	taken := held.LocalAddr().(*net.UDPAddr).Port

	ports, err := HeldUDPPorts()
	if err != nil {
		t.Fatalf("read the socket table: %v", err)
	}
	for _, p := range ports {
		if p == taken {
			return
		}
	}
	t.Errorf("port %d is open but not in the %d ports read from /proc/net/udp", taken, len(ports))
}
