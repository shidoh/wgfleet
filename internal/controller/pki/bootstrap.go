package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
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

func writeFile(path string, data []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, perm)
}
