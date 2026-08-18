package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteNodeBundlePermissions is the one that matters here: node.key is a
// PRIVATE key and its mode is a bare literal in WriteNodeBundle with nothing
// guarding it. The same class of slip already happened once in this codebase —
// the rendered mihomo config went out 0644 while holding one WireGuard private
// key per exit, which is why reconcile.FileAction now refuses secret-bearing
// content with group/world-readable modes. This path has no such guard, so the
// test is the guard.
func TestWriteNodeBundlePermissions(t *testing.T) {
	ca, err := NewCA("wgfleet-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := WriteNodeBundle(ca, "exit-1", dir); err != nil {
		t.Fatalf("WriteNodeBundle: %v", err)
	}

	for _, want := range []struct {
		name string
		perm os.FileMode
	}{
		{"node.key", 0o600}, // private key: owner-only, never group/world readable
		{"node.crt", 0o644},
		{"ca.crt", 0o644},
	} {
		fi, err := os.Stat(filepath.Join(dir, want.name))
		if err != nil {
			t.Errorf("%s missing from the bundle: %v", want.name, err)
			continue
		}
		if got := fi.Mode().Perm(); got != want.perm {
			t.Errorf("%s mode = %#o, want %#o", want.name, got, want.perm)
		}
	}
}

// TestWriteNodeBundleContents proves the three files are what they claim to be
// and belong together. A bundle whose ca.crt does not verify its own node.crt
// would leave the node unable to authenticate, and the failure would only show up
// as an opaque mTLS error at registration time, far from here.
func TestWriteNodeBundleContents(t *testing.T) {
	ca, err := NewCA("wgfleet-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := WriteNodeBundle(ca, "exit-1", dir); err != nil {
		t.Fatal(err)
	}

	nodeCert := parseCertFile(t, filepath.Join(dir, "node.crt"))
	if nodeCert.Subject.CommonName != "exit-1" {
		t.Errorf("node.crt CN = %q, want the node ID", nodeCert.Subject.CommonName)
	}

	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.crt is not a usable PEM certificate")
	}
	if _, err := nodeCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("node.crt does not verify against the bundled ca.crt: %v", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := pem.Decode(keyPEM); b == nil {
		t.Error("node.key is not PEM")
	}
}

// TestWriteNodeBundleCreatesMissingDir — the caller passes a path that usually
// does not exist yet (a fresh node's output dir), so failing to create it would
// break every first-time provision.
func TestWriteNodeBundleCreatesMissingDir(t *testing.T) {
	ca, _ := NewCA("ca")
	dir := filepath.Join(t.TempDir(), "does", "not", "exist")
	if err := WriteNodeBundle(ca, "n1", dir); err != nil {
		t.Fatalf("WriteNodeBundle into a missing dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node.crt")); err != nil {
		t.Errorf("bundle not written: %v", err)
	}
}

func parseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		t.Fatalf("%s is not PEM", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return c
}
