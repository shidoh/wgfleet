package certrenew

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/pki"
)

type caSigner struct {
	ca      *pki.CA
	id      string
	lastCSR []byte
}

func (c *caSigner) RenewCertificate(_ context.Context, csrDER []byte) ([]byte, []byte, error) {
	c.lastCSR = csrDER
	certPEM, err := c.ca.SignNodeCSR(csrDER, c.id)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, c.ca.CertPEM(), nil
}

func testPaths(t *testing.T) Paths {
	dir := t.TempDir()
	return Paths{Cert: filepath.Join(dir, "node.crt"), Key: filepath.Join(dir, "node.key"), CA: filepath.Join(dir, "ca.crt")}
}

// Rotation must install a matched pair, and the private key must never be the thing
// that travelled — only the public half, inside the request.
func TestRotateInstallsAMatchedPairAndKeepsTheKeyLocal(t *testing.T) {
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	signer := &caSigner{ca: ca, id: "exit-de-1"}
	p := testPaths(t)

	if err := Rotate(context.Background(), signer, p); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	certPEM, err := os.ReadFile(p.Cert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tlsPairValid(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("the installed pair does not match: %v", err)
	}
	if cert.Subject.CommonName != "exit-de-1" {
		t.Errorf("CN = %q, want the identity the controller decided", cert.Subject.CommonName)
	}
	// The key is a secret and must be written as one.
	info, err := os.Stat(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %#o, want 0600", perm)
	}
	// Nothing resembling a private key may appear in what we sent.
	csr, err := x509.ParseCertificateRequest(signer.lastCSR)
	if err != nil {
		t.Fatal(err)
	}
	if pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: signer.lastCSR}) == nil {
		t.Fatal("unreachable")
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the request we sent is not self-signed: %v", err)
	}
	// The CA travels back too, so a CA rotation needs no second trip.
	if _, err := os.Stat(p.CA); err != nil {
		t.Errorf("CA was not installed: %v", err)
	}
}

// A controller that answers with a certificate for somebody else's key must not
// have that certificate installed: the node would immediately stop authenticating.
func TestRotateRefusesAMismatchedCertificate(t *testing.T) {
	ca, _ := pki.NewCA("test-ca")
	other, _ := ca.IssueNodeCert("someone-else")
	p := testPaths(t)

	bad := signerFunc(func(context.Context, []byte) ([]byte, []byte, error) {
		return other.CertPEM, ca.CertPEM(), nil
	})
	if err := Rotate(context.Background(), bad, p); err == nil {
		t.Fatal("a certificate for a different key was installed")
	}
	if _, err := os.Stat(p.Key); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused rotation still touched the key file")
	}
}

type signerFunc func(context.Context, []byte) ([]byte, []byte, error)

func (f signerFunc) RenewCertificate(ctx context.Context, csr []byte) ([]byte, []byte, error) {
	return f(ctx, csr)
}
