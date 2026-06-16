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
