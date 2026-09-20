package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// reloadRetryDelay is how long a failed re-read waits before its one retry. Long
// enough to outlast the gap between the key rename and the certificate rename
// (each preceded by an fsync), short enough to be unnoticed inside a handshake
// that happens on the order of once per reconnect. A variable so tests do not
// sleep.
var reloadRetryDelay = 100 * time.Millisecond

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
//
// onLoadError is called when a re-read fails TWICE (see the retry below). The handshake still proceeds on the
// last pair that loaded — dropping the connection over an unreadable FILE would
// take the node off the control plane for a fault that has not reached the wire
// yet — but the failure must leave a trace. It used to be discarded by an
// `if err == nil`, which made the dangerous case the quiet one: the agent keeps
// authenticating with the certificate it started with, looks healthy for as long as
// it stays up, and the pair on disk is one the next restart cannot load. That
// restart is then the first symptom, and it happens at the moment the node stops
// being reachable to fix it.
func ReloadableClientTLS(load func() (tls.Certificate, error), caCertPEM []byte, serverName string, onLoadError func(error)) (*tls.Config, error) {
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
			fresh, err := load()
			if err != nil {
				// Retry once before calling it a fault. The pair is two files written
				// by two independent renames, so a handshake landing between them reads
				// a new key beside an old certificate and fails to pair them — which is
				// not corruption but the rotation itself, self-correcting within
				// milliseconds. Renewal is also exactly when handshakes cluster, because
				// the connection is re-established right after it. Reporting that as
				// "the next restart will not be able to load this" would cry wolf on the
				// one event the counter exists to watch.
				time.Sleep(reloadRetryDelay)
				if fresh, err = load(); err != nil {
					if onLoadError != nil {
						onLoadError(err)
					}
					return holder.Load(), nil
				}
			}
			holder.Store(&fresh)
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
