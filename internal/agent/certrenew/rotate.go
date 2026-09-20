package certrenew

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/shidoh/wgfleet/internal/atomicfile"
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
// The pair has to move together and cannot: two files, two renames, and a failure
// between them leaves a key the certificate on disk does not certify. The risk is
// narrowed from three sides rather than pretended away. The pair is verified in
// memory BEFORE anything is written; each file is written to a temporary, fsynced,
// renamed, and the directory fsynced after; and a certificate write that fails
// puts the PREVIOUS key back, so a failed rotation ends where it began instead of
// one step worse. What remains is a crash landing between the two renames, which
// no two-file scheme can close: the next start then fails to load its identity and
// the operator re-issues over SSH — the same path an expired certificate takes,
// and the reason that path is kept.
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
	// Read the key we are about to replace, so the second write has something to
	// roll back to. ABSENT is fine — a first install has no previous pair — but
	// "exists and could not be read" must stop the rotation before it starts.
	// Treating the two alike meant a transient read error let the overwrite proceed
	// with nothing to restore, and a cert write that then failed left the node
	// holding a key no certificate on disk certifies: strictly worse than the
	// working pair it had, on a node whose only way back is an operator over SSH.
	// Not rotating is free — the current pair still authenticates, and the next
	// pass tries again.
	prevKey, readErr := os.ReadFile(p.Key)
	switch {
	case readErr == nil:
	case errors.Is(readErr, fs.ErrNotExist):
		prevKey = nil
	default:
		return fmt.Errorf("renew: refusing to rotate: the current key %q exists but cannot be read, "+
			"so a failed install could not be rolled back: %w", p.Key, readErr)
	}
	if err := atomicfile.Write(p.Key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := atomicfile.Write(p.Cert, certPEM, 0o644); err != nil {
		// The new key is on disk and the certificate that certifies it is not, so
		// what remains is a pair that cannot authenticate anything — and renewal
		// travels over the mTLS channel this pair opens, which means the node could
		// not fix this by trying again. The previous pair still worked: put the key
		// back and let the next pass retry from a state that talks.
		if prevKey != nil {
			if rerr := atomicfile.Write(p.Key, prevKey, 0o600); rerr != nil {
				return fmt.Errorf("renew: installing the certificate failed (%w) AND the previous key could not be "+
					"restored (%v) — this node now holds a key nothing certifies and must be re-issued out of band "+
					"with `wgfleet-controller --certs renew`", err, rerr)
			}
		}
		return err
	}
	if len(caPEM) > 0 && p.CA != "" {
		if err := atomicfile.Write(p.CA, caPEM, 0o644); err != nil {
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
