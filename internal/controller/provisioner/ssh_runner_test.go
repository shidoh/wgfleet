package provisioner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shidoh/wgfleet/internal/domain"
)

// encodePEM renders the block ssh.MarshalPrivateKey returns.
func encodePEM(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// newHostKey returns a fresh ed25519 ssh.PublicKey and its authorized_keys line.
func newHostKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestHostKeyCallbackPinned(t *testing.T) {
	pinned, line := newHostKey(t)
	cb, algos, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1", HostKey: line})
	if err != nil {
		t.Fatalf("pinned key should parse: %v", err)
	}
	// The pinned key's algorithm must be advertised, so the server presents that
	// key type rather than another host key that FixedHostKey would reject.
	if len(algos) != 1 || algos[0] != ssh.KeyAlgoED25519 {
		t.Errorf("pinned ed25519 key must constrain host-key algorithms to [%s], got %v", ssh.KeyAlgoED25519, algos)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}
	if err := cb("10.0.0.1:22", addr, pinned); err != nil {
		t.Errorf("matching host key must be accepted: %v", err)
	}

	other, _ := newHostKey(t)
	if err := cb("10.0.0.1:22", addr, other); err == nil {
		t.Error("a different host key must be rejected")
	}
}

func TestHostKeyAlgorithmsForRSA(t *testing.T) {
	// RSA expands to the SHA-2 variants so a pinned RSA host key still negotiates
	// against servers that have disabled the SHA-1 "ssh-rsa" algorithm.
	got := hostKeyAlgorithmsFor(ssh.KeyAlgoRSA)
	want := []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	if len(got) != len(want) {
		t.Fatalf("RSA host-key algorithms = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RSA host-key algorithms = %v, want %v", got, want)
		}
	}
}

func TestHostKeyCallbackInvalidPin(t *testing.T) {
	if _, _, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1", HostKey: "garbage not a key"}); err == nil {
		t.Error("an unparseable pinned host key must error rather than silently downgrade")
	}
}

func TestHostKeyCallbackUnpinnedFallback(t *testing.T) {
	// No pinned key: a callback is still returned (trust-on-first-use), so bootstrap
	// works on a fresh VM. The WARN log is the operator's signal to pin.
	cb, algos, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1"})
	if err != nil || cb == nil {
		t.Fatalf("unpinned target should yield a usable callback, got cb=%v err=%v", cb, err)
	}
	if algos != nil {
		t.Errorf("unpinned target must not constrain host-key algorithms, got %v", algos)
	}
}

func TestHostKeyCallbackInsecureIgnore(t *testing.T) {
	// The explicit per-node opt-out accepts any host key even when one is pinned,
	// so a stale/mismatched pin can be bypassed deliberately rather than blocking.
	pinned, line := newHostKey(t)
	cb, algos, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1", HostKey: line, InsecureIgnoreHostKey: true})
	if err != nil || cb == nil {
		t.Fatalf("insecure-ignore target should yield a usable callback, got cb=%v err=%v", cb, err)
	}
	if algos != nil {
		t.Errorf("insecure-ignore must not constrain host-key algorithms, got %v", algos)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}
	other, _ := newHostKey(t)
	if err := cb("10.0.0.1:22", addr, other); err != nil {
		t.Errorf("insecure-ignore must accept any host key, rejected: %v", err)
	}
	_ = pinned
}

// A TCP connection that opens and then says nothing is not a hypothetical: it is
// what the fleet's public path does when it wedges (2026-09-09 and again
// 2026-09-11 — ESTAB to the exit's port 22, 12 bytes in Send-Q, no movement).
//
// ssh.ClientConfig.Timeout bounds only the TCP connect, so the handshake that
// follows had NO bound at all and the dial blocked forever. Every caller inherits
// that: the rolling upgrade sat 13 minutes on one node with a five-minute
// per-node deadline it could not enforce, because the deadline can only be
// noticed by a call that returns.
func TestDialSSHGivesUpOnAServerThatAcceptsAndSaysNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c // held open, deliberately silent
	}()

	restore := sshHandshakeTimeout
	sshHandshakeTimeout = 300 * time.Millisecond
	defer func() { sshHandshakeTimeout = restore }()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	target := domain.SSHTarget{
		Host: host, Port: p, User: "root",
		KeyPath:               writeTestKey(t),
		InsecureIgnoreHostKey: true,
	}

	done := make(chan error, 1)
	go func() {
		_, err := DialSSH(target, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent server must not produce a usable client")
		}
		if !strings.Contains(err.Error(), "ssh dial") {
			t.Errorf("the error must name the dial that failed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialSSH hung on a silent server — the handshake is still unbounded")
	}
	select {
	case c := <-accepted:
		_ = c.Close()
	default:
	}
}

// writeTestKey drops a throwaway private key on disk; DialSSH reads one before it
// touches the network, and this test is about the network half.
func writeTestKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, encodePEM(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
