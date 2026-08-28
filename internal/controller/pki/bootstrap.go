package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// SaveCA writes the CA certificate (0644) and private key (0600) to disk. The
// key is a secret; callers must place it on a path covered by .gitignore and,
// in production, behind a secret manager.
func SaveCA(ca *CA, certPath, keyPath string) error {
	kp, err := ca.Marshal()
	if err != nil {
		return err
	}
	if err := writeFile(certPath, kp.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := writeFile(keyPath, kp.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

// LoadCAFromFiles loads a CA from certificate and key file paths.
func LoadCAFromFiles(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key %q: %w", keyPath, err)
	}
	return LoadCA(certPEM, keyPEM)
}

// WriteNodeBundle issues a node client certificate and writes node.crt,
// node.key (0600) and ca.crt into dir — exactly the material an agent needs to
// establish its mTLS identity. Used by `--issue-node` and, later, the
// provisioner's bootstrap phase.
func WriteNodeBundle(ca *CA, nodeID, dir string) error {
	kp, err := ca.IssueNodeCert(nodeID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"node.crt", kp.CertPEM, 0o644},
		{"node.key", kp.KeyPEM, 0o600},
		{"ca.crt", ca.CertPEM(), 0o644},
	}
	for _, f := range files {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// ClientTLS builds an agent mTLS config from raw PEM material: its own cert/key
// and the CA certificate to trust for the controller. Unlike (*CA).ClientTLSConfig
// this needs no CA private key, which the agent never has.
func ClientTLS(certPEM, keyPEM, caCertPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("no certificates found in CA PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ReloadableClientTLS is ClientTLS with a certificate that can be swapped while the
// process runs.
//
// Renewal is worthless if picking up the new certificate needs a restart: the agent
// would rotate, keep presenting the old one, and only actually change identity at
// the next unrelated restart — which on a healthy node might be months away, i.e.
// after the certificate it renewed had already expired. GetClientCertificate is
// consulted per handshake, so a reconnect after rotation presents the new pair while
// connections already open keep the old one, which stays valid until its own expiry.
func ReloadableClientTLS(load func() (tls.Certificate, error), caCertPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := load()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("no certificates found in CA PEM")
	}
	var holder atomic.Pointer[tls.Certificate]
	holder.Store(&cert)
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Re-read on every handshake rather than caching: a handshake is rare and a
			// stale identity is expensive, so the cheap thing to do is the current thing.
			if fresh, err := load(); err == nil {
				holder.Store(&fresh)
			}
			return holder.Load(), nil
		},
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}, nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, perm)
}
