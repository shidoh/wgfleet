package provisioner

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shidoh/wgfleet/internal/domain"
)

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
	cb, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1", HostKey: line})
	if err != nil {
		t.Fatalf("pinned key should parse: %v", err)
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

func TestHostKeyCallbackInvalidPin(t *testing.T) {
	if _, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1", HostKey: "garbage not a key"}); err == nil {
		t.Error("an unparseable pinned host key must error rather than silently downgrade")
	}
}

func TestHostKeyCallbackUnpinnedFallback(t *testing.T) {
	// No pinned key: a callback is still returned (trust-on-first-use), so bootstrap
	// works on a fresh VM. The WARN log is the operator's signal to pin.
	cb, err := hostKeyCallback(domain.SSHTarget{Host: "10.0.0.1"})
	if err != nil || cb == nil {
		t.Fatalf("unpinned target should yield a usable callback, got cb=%v err=%v", cb, err)
	}
}
