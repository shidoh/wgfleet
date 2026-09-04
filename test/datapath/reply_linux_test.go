//go:build linux

package datapath

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

const transparent = 19 // IP_TRANSPARENT

// replySocket is exactly what mihomo does to answer an intercepted flow: bind the
// SERVER's address and port with IP_TRANSPARENT so the reply carries the source
// the client is expecting, then send to the client. Reproduced here rather than
// described, because the whole failure is one errno from this call.
func replySocket(t *testing.T, server *net.UDPAddr) (int, error) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, transparent, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	var addr [4]byte
	copy(addr[:], server.IP.To4())
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: server.Port, Addr: addr}); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func requirePrivileges(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs CAP_NET_ADMIN for IP_TRANSPARENT; run under sudo")
	}
}

// The reply path must work for an ordinary destination port.
func TestReplySocketOpensForAFreePort(t *testing.T) {
	requirePrivileges(t)
	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4433}

	fd, err := replySocket(t, server)
	if err != nil {
		t.Fatalf("no reply socket for a free port %d: %v", server.Port, err)
	}
	_ = syscall.Close(fd)
}

// And it must NOT work for a port this host already holds — that is the bug,
// stated as an assertion. A wildcard UDP socket without SO_REUSEADDR is exactly
// what a kernel WireGuard interface is.
//
// This is the case the 2026-08-27 rehearsal could not see, because it drove ports
// the node did not hold.
func TestReplySocketIsRefusedForAPortTheHostHolds(t *testing.T) {
	requirePrivileges(t)

	held, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	port := held.LocalAddr().(*net.UDPAddr).Port
	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: port}

	fd, err := replySocket(t, server)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("a reply socket opened on port %d while the host holds it — "+
			"the collision this test exists to catch is not being caught", port)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("refused with %v, want EADDRINUSE — the failure mode differs from production", err)
	}
}

// The full loop, on a real kernel: a client sends to a foreign address, something
// transparent picks the datagram up, and the reply comes back bearing the
// server's address. When the reply socket cannot be opened, the client waits
// forever — which is what a user sees as a video that stalls rather than an error.
func TestInterceptedFlowGetsItsReplyBack(t *testing.T) {
	requirePrivileges(t)

	// The "client": an ordinary socket that will send to a foreign address and
	// expects an answer from it.
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	// The "server" the client believes it is talking to. Nothing listens there; the
	// reply is forged from a transparent socket, exactly as a proxy does.
	server := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 4433}

	fd, err := replySocket(t, server)
	if err != nil {
		t.Fatalf("reply socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	var caddr [4]byte
	copy(caddr[:], clientAddr.IP.To4())
	if err := syscall.Sendto(fd, []byte("pong"), 0,
		&syscall.SockaddrInet4{Port: clientAddr.Port, Addr: caddr}); err != nil {
		t.Fatalf("send the reply: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, from, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the client never got its reply: %v", err)
	}
	if got := string(buf[:n]); got != "pong" {
		t.Errorf("payload = %q, want %q", got, "pong")
	}
	if from.(*net.UDPAddr).IP.String() != server.IP.String() {
		t.Errorf("reply came from %s, want the server's address %s — a client would drop it",
			from, server.IP)
	}
}
