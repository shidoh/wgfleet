package support

import (
	"errors"
	"strings"
	"testing"
)

// A real AmneziaWG key. Public and private keys are both 44-char base64 ending
// in "=" and are INDISTINGUISHABLE BY SHAPE, which is why the gate's primary
// check is exact comparison against values the node actually holds rather than
// a regex over shape.
const (
	privKey = "aFakeButWellFormedPrivateKeyForTests1234567="
	pubKey  = "aFakeButWellFormedPublicKeyForTests98765432="
)

// The test this feature exists for: a private key that reached the bundle by ANY
// route must stop the archive being written.
func TestGateRefusesABundleContainingARealSecret(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"state.txt": "line one\nPrivateKey = " + privKey + "\nline three\n"},
	}}
	err := Gate(nodes, []string{privKey})
	if err == nil {
		t.Fatal("gate passed a bundle containing a real private key")
	}
	var le *LeakError
	if !asLeakError(err, &le) {
		t.Fatalf("error is %T, want *LeakError", err)
	}
	if le.File != "exit-de-1/state.txt" {
		t.Errorf("File = %q, want the file the secret landed in", le.File)
	}
	if le.Line != 2 {
		t.Errorf("Line = %d, want 2", le.Line)
	}
	if strings.Contains(err.Error(), privKey) {
		t.Error("the gate printed the secret it was refusing to leak")
	}
}

// The false-positive guard. Public keys are all over a legitimate bundle — awg
// show prints one per peer. A gate that fires on them gets disabled by the first
// person who hits it, and then protects nothing.
func TestGateAllowsPublicKeys(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"network.txt": "peer: " + pubKey + "\n  allowed ips: 10.0.0.2/32\n"},
	}}
	if err := Gate(nodes, []string{privKey}); err != nil {
		t.Errorf("gate rejected a bundle of public keys: %v", err)
	}
}

// Second, coarser layer: an unknown secret-bearing line in uncontrolled text
// (container logs, third-party units) that the exact check cannot know about.
func TestGateCatchesSecretBearingKeysByName(t *testing.T) {
	nodes := []Node{{
		Name:  "master-1",
		Files: map[string]string{"containers.txt": "loaded config\nsecret: hunter2hunter2hunter2\n"},
	}}
	if err := Gate(nodes, nil); err == nil {
		t.Error("gate passed a line whose key names it as a secret")
	}
}

func TestGateAcceptsAlreadyRedactedValues(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"state.txt": "PrivateKey = <redacted>\nsecret: <redacted>\n"},
	}}
	if err := Gate(nodes, nil); err != nil {
		t.Errorf("gate rejected properly redacted output: %v", err)
	}
}

func TestScrubMasksSecretBearingValues(t *testing.T) {
	in := "private-key: " + privKey + "\nlisten-port: 51820\ntoken=abc123\n"
	got := Scrub(in)
	if strings.Contains(got, privKey) {
		t.Error("scrub left a private key in place")
	}
	if !strings.Contains(got, "listen-port: 51820") {
		t.Error("scrub mangled a non-secret line")
	}
	if strings.Contains(got, "abc123") {
		t.Error("scrub left a token in place")
	}
}

// An empty secret must never be searched for: strings.Contains(x, "") is always
// true, so one empty entry would fail every bundle and make the gate useless.
func TestGateIgnoresEmptySecrets(t *testing.T) {
	nodes := []Node{{Name: "n", Files: map[string]string{"a.txt": "nothing sensitive\n"}}}
	if err := Gate(nodes, []string{"", "   "}); err != nil {
		t.Errorf("gate tripped on an empty secret: %v", err)
	}
}

func asLeakError(err error, target **LeakError) bool { return errors.As(err, target) }
