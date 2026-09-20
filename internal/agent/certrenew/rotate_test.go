package certrenew

import (
	"bytes"
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
	keyPEM, kerr := os.ReadFile(p.Key)
	if kerr != nil {
		t.Fatal(kerr)
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
	// The private half must never leave the node. The previous version of this check
	// PEM-encoded the CSR under an "EC PRIVATE KEY" label and asserted the result was
	// non-nil — which it always is — so it would have passed unchanged if Rotate had
	// marshalled and transmitted the key itself. Compare against the actual key on
	// disk instead.
	csr, err := x509.ParseCertificateRequest(signer.lastCSR)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("the installed key is not PEM")
	}
	if bytes.Contains(signer.lastCSR, block.Bytes) {
		t.Fatal("the private key was transmitted inside the certificate request")
	}
	if bytes.Contains(signer.lastCSR, keyPEM) {
		t.Fatal("the PEM-encoded private key was transmitted inside the certificate request")
	}
	// And what we sent must be a CSR proving possession, not merely well-formed bytes.
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

// The key and the certificate are two files and one identity. If the second write
// fails after the first succeeded, the node is left holding a key its certificate
// does not certify — it can no longer authenticate, and renewal travels over the
// very channel it just lost, so it cannot repair itself either. The previous pair
// still worked; put it back.
func TestAFailedCertificateWriteRestoresThePreviousKey(t *testing.T) {
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	signer := &caSigner{ca: ca, id: "exit-de-1"}
	p := testPaths(t)

	// A working pair on disk first — this is the one that must survive.
	if err := Rotate(context.Background(), signer, p); err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(p.Cert)
	if err != nil {
		t.Fatal(err)
	}

	// Now make the certificate unwritable: its directory does not exist.
	broken := p
	broken.Cert = filepath.Join(filepath.Dir(p.Cert), "gone", "node.crt")
	if err := Rotate(context.Background(), signer, broken); err == nil {
		t.Fatal("a rotation whose certificate could not be written reported success")
	}

	keyAfter, err := os.ReadFile(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Error("the key was replaced although the certificate write failed: the pair on disk no longer matches")
	}
	if _, err := tlsPairValid(certBefore, keyAfter); err != nil {
		t.Errorf("the pair left on disk does not match, so this node cannot authenticate: %v", err)
	}
}

// "No previous key" and "the previous key cannot be read" are not the same fact,
// and treating them alike is how a rotation ends WORSE than not rotating: the
// overwrite proceeds with nothing held back, and a certificate write that then
// fails leaves a key no certificate certifies. The node's only way out of that is
// an operator over SSH. Not rotating costs nothing — the current pair still
// authenticates and the next pass tries again — so a key that exists and cannot be
// read must stop the attempt before the first write.
func TestAnUnreadableCurrentKeyStopsTheRotationBeforeItStarts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads regardless of mode; this test needs an unprivileged user")
	}
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	signer := &caSigner{ca: ca, id: "exit-de-1"}
	p := testPaths(t)
	if err := Rotate(context.Background(), signer, p); err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(p.Cert)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(p.Key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p.Key, 0o600) })

	if err := Rotate(context.Background(), signer, p); err == nil {
		t.Fatal("a rotation that could not read the key it was replacing reported success")
	}
	// The certificate must be untouched: nothing was written at all.
	certAfter, err := os.ReadFile(p.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certBefore, certAfter) {
		t.Error("the certificate was replaced although the rotation could not be rolled back")
	}
}
