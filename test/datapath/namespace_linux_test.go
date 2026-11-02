//go:build linux

package datapath

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
)

// clientWGPort is the port the client-facing AmneziaWG interface listens on by
// default, and the port every one of these assertions is about.
//
// Written as a literal rather than derived, on purpose. An earlier rehearsal
// drove 5353 and 4433 — ports nothing held — and stayed green while client QUIC
// was one-way. A rehearsal that picks a convenient port is a
// rehearsal of a different system.
const clientWGPort = 443

// The premise, on the real port: a namespace that already holds :443 cannot open
// the transparent reply socket mihomo needs, so every reply to a client's QUIC
// flow is dropped inside the proxy. This is the outage, reproduced.
func TestPortCollisionIsRealOnTheClientWGPort(t *testing.T) {
	requirePrivileges(t)
	held := holdWildcard(t, clientWGPort)
	defer func() { _ = held.Close() }()

	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: clientWGPort}
	fd, err := replySocket(t, server)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatal("a reply socket opened on :443 while this namespace holds it — " +
			"the collision this whole migration exists to remove is not reproducible here, " +
			"so nothing below proves anything")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("refused with %v, want EADDRINUSE — the failure mode differs from production", err)
	}
}

// And the fix, on the same port and in the same run: a network namespace that does
// NOT hold :443 opens the reply socket, while the outer one still cannot.
//
// This is the assertion the branch was missing. Every earlier test in this package
// asserted that the BUG exists, which is true before the fix and true after it —
// green forever, and worth nothing. What the migration claims is that a socket
// held out there stops being in the way in here, and that claim can fail: it fails
// if the namespace is not really separate, and it fails if something in the
// namespace binds the port too.
func TestNamespaceRemovesThePortCollision(t *testing.T) {
	requirePrivileges(t)
	held := holdWildcard(t, clientWGPort)
	defer func() { _ = held.Close() }()

	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: clientWGPort}

	// Both answers are taken in one run so the comparison is between two namespaces
	// and not between two machines.
	if fd, err := replySocket(t, server); err == nil {
		_ = syscall.Close(fd)
		t.Fatal("test premise: the outer namespace should still be holding :443")
	}

	err := inNewNetNS(func() error {
		fd, berr := replySocket(t, server)
		if berr != nil {
			return berr
		}
		return syscall.Close(fd)
	})
	if err != nil {
		t.Fatalf("the reply socket is still refused inside a namespace of its own (%v) — "+
			"moving mihomo there does not fix the collision, and the whole migration is "+
			"buying nothing", err)
	}
}

// A datagram sent from the namespace's reply socket must still carry the SERVER's
// address, or a client drops it as unsolicited. The move must not change what the
// client sees, only where the socket lives.
func TestNamespaceReplyStillCarriesTheServerAddress(t *testing.T) {
	requirePrivileges(t)
	held := holdWildcard(t, clientWGPort)
	defer func() { _ = held.Close() }()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	// Loopback inside a fresh namespace is a different loopback, so the reply cannot
	// reach the outer client. What is asserted here is the part that IS namespace-
	// local: the socket binds the server's address on the held port and accepts a
	// send, which is the operation that returns EADDRINUSE on a colliding host.
	err = inNewNetNS(func() error {
		if lerr := loopbackUp(); lerr != nil {
			return lerr
		}
		server := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: clientWGPort}
		fd, berr := replySocket(t, server)
		if berr != nil {
			return berr
		}
		defer func() { _ = syscall.Close(fd) }()
		var caddr [4]byte
		copy(caddr[:], clientAddr.IP.To4())
		return syscall.Sendto(fd, []byte("pong"), 0,
			&syscall.SockaddrInet4{Port: clientAddr.Port, Addr: caddr})
	})
	if err != nil {
		t.Fatalf("the namespace could not forge a reply from the server address: %v", err)
	}
}

// holdWildcard binds a wildcard UDP socket on a port, which is what a kernel
// WireGuard interface is as far as this collision is concerned: no SO_REUSEADDR,
// so nothing else may have the port.
func holdWildcard(t *testing.T, port int) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", net.JoinHostPort("0.0.0.0", itoa(port)))
	if err != nil {
		t.Skipf("cannot hold :%d on this machine (%v); without it there is no collision to test", port, err)
	}
	return c
}

// inNewNetNS runs fn in a fresh network namespace.
//
// The thread is locked and never unlocked, which is deliberate: `unshare` moves
// the calling THREAD, and a thread left in a foreign namespace would be handed to
// unrelated goroutines by the scheduler. Never unlocking makes the runtime destroy
// the thread when this goroutine ends, so the namespace goes with it.
func inNewNetNS(fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // no Unlock: this thread must not be reused
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		done <- fn()
	}()
	return <-done
}

// loopbackUp brings `lo` up inside the current namespace. A fresh namespace has it
// DOWN, and a socket bound to a loopback address cannot send until it is up.
func loopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	var req [40]byte
	copy(req[:], "lo")
	// ifr_flags at offset 16: IFF_UP | IFF_RUNNING.
	req[16] = 0x41
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafePointerOf(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
