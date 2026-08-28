package certrenew

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Signer asks the controller to sign a certificate request.
type Signer interface {
	RenewCertificate(ctx context.Context, csrDER []byte) (certPEM, caPEM []byte, err error)
}

// Paths are the files a node's identity lives in.
type Paths struct{ Cert, Key, CA string }

// Rotate generates a NEW keypair, has the controller certify it, and installs both.
//
// A new key each time, not a re-certification of the old one: the point of rotating
// is that a key which has been on a machine for a year stops being the one that
// authenticates it. The old key stays valid until its certificate expires, which is
// what keeps this safe to do at any moment — nothing is revoked, the node simply
// starts using the new pair.
//
// The pair has to move together and cannot: two files, two renames, and a crash
// between them leaves a key the certificate on disk does not certify. So the risk is
// narrowed rather than pretended away. The pair is verified in memory BEFORE
// anything is written, each file is written to a temporary and fsynced before its
// rename, and the window between the two renames is a few microseconds. If a node
// does land in it, the next start fails to load its identity and the operator
// re-issues over SSH — the same path an expired certificate takes, and the reason
// that path is kept.
func Rotate(ctx context.Context, signer Signer, p Paths) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("renew: generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		// The subject is ignored by the controller, which issues for the verified
		// peer's identity. It is filled in anyway so a CSR captured in a log or a
		// packet dump says who meant to send it.
		Subject: pkix.Name{Organization: []string{"wgfleet"}},
	}, key)
	if err != nil {
		return fmt.Errorf("renew: build certificate request: %w", err)
	}
	certPEM, caPEM, err := signer.RenewCertificate(ctx, csrDER)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("renew: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Refuse to install a pair that does not match before touching anything.
	if _, err := tlsPairValid(certPEM, keyPEM); err != nil {
		return fmt.Errorf("renew: controller returned a certificate that does not match our key: %w", err)
	}
	if err := writeAtomic(p.Key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(p.Cert, certPEM, 0o644); err != nil {
		return err
	}
	if len(caPEM) > 0 && p.CA != "" {
		if err := writeAtomic(p.CA, caPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// NotBeforeAfter reads a certificate's validity period.
func NotBeforeAfter(certPath string) (notBefore, notAfter time.Time, err error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("no PEM block in %q", certPath)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return c.NotBefore, c.NotAfter, nil
}

func tlsPairValid(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("certificate or key is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("certificate does not certify this key")
	}
	return cert, nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".renew-*")
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("renew: write %q: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("renew: chmod %q: %w", path, err)
	}
	// fsync before the rename: this is the node's identity, and a rename that lands
	// ahead of the bytes leaves a zero-length key that nothing can authenticate with.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("renew: sync %q: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("renew: close %q: %w", path, err)
	}
	return os.Rename(tmp.Name(), path)
}
