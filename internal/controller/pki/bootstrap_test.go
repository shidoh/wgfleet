package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// Re-reading the pair on every handshake is what makes renewal take effect without
// a restart. Its failure is what makes renewal DANGEROUS: the agent keeps handshaking
// on the certificate it loaded at startup, so it looks healthy, while the pair on
// disk is one the next restart cannot load at all. That restart is the first symptom
// — and by then the node is off the control plane, where nothing can reach it to fix
// the file. The error was discarded by an `if err == nil`; it has to be reported.
func TestAFailedReloadIsReportedAndTheGoodCertificateIsKept(t *testing.T) {
	ca, err := NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	kp, err := ca.IssueNodeCert("exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	good, err := tls.X509KeyPair(kp.CertPEM, kp.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	reloadRetryDelay = 0 // the retry is behaviour under test elsewhere; do not sleep here
	t.Cleanup(func() { reloadRetryDelay = 100 * time.Millisecond })

	loadErr := errors.New("node.key: certificate does not certify this key")
	fail := false
	load := func() (tls.Certificate, error) {
		if fail {
			return tls.Certificate{}, loadErr
		}
		return good, nil
	}

	var reported []error
	cfg, err := ReloadableClientTLS(load, ca.CertPEM(), "controller", func(e error) {
		reported = append(reported, e)
	})
	if err != nil {
		t.Fatal(err)
	}

	fail = true
	got, err := cfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("a handshake must still be attempted on the last good pair: %v", err)
	}
	if len(reported) != 1 || !errors.Is(reported[0], loadErr) {
		t.Fatalf("the reload failure was swallowed: %v", reported)
	}
	if len(got.Certificate) == 0 || !bytes.Equal(got.Certificate[0], good.Certificate[0]) {
		t.Error("the last good certificate was not kept, so a reload failure would also drop the connection")
	}
}

// A rotation renames the key and the certificate separately, so a handshake can
// land between them, read a new key beside an old certificate, and fail to pair
// them. That is the renewal working, not a fault — and renewal is exactly when
// handshakes cluster, because the connection is re-established right after it.
// One retry tells the two apart, and the transient case must stay silent: a
// counter that ticks on every successful rotation is a counter nobody reads.
func TestATransientFailureDuringRotationIsNotReported(t *testing.T) {
	reloadRetryDelay = 0
	t.Cleanup(func() { reloadRetryDelay = 100 * time.Millisecond })

	ca, err := NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.IssueNodeCert("exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	startup, err := tls.X509KeyPair(first.CertPEM, first.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ca.IssueNodeCert("exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := tls.X509KeyPair(second.CertPEM, second.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	load := func() (tls.Certificate, error) {
		calls++
		switch calls {
		case 1:
			return startup, nil // construction
		case 2:
			return tls.Certificate{}, errors.New("tls: private key does not match public key")
		default:
			return rotated, nil // the rename that was in flight has landed
		}
	}

	var reported []error
	cfg, err := ReloadableClientTLS(load, ca.CertPEM(), "controller", func(e error) {
		reported = append(reported, e)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reported) != 0 {
		t.Errorf("a self-correcting blip during rotation was reported as a fault: %v", reported)
	}
	if !bytes.Equal(got.Certificate[0], rotated.Certificate[0]) {
		t.Error("the retry did not adopt the freshly rotated certificate")
	}
}
