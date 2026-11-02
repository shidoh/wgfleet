// Package pki provides the certificate authority and mTLS configuration that
// secure the controller↔agent channel. Each node is issued a client
// certificate whose Common Name is its node ID, so the authenticated identity
// is the certificate itself: revoking a cert removes a node from the fleet.
// Node private keys are generated on the node and never reach
// the controller; this package only handles the control-channel PKI, not WG keys.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 365 * 24 * time.Hour
	// serialBits bounds the random certificate serial number.
	serialBits = 128
)

// KeyPair is a PEM-encoded certificate and its private key.
type KeyPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// CA is the fleet certificate authority. It signs the controller's server
// certificate and every node's client certificate.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	now     func() time.Time // injectable clock for deterministic tests
}

// NewCA creates a fresh self-signed CA with the given common name.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	now := time.Now()
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"wgfleet"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // issues leaves only, no intermediate CAs
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pemBlock("CERTIFICATE", der),
		now:     time.Now,
	}, nil
}

// LoadCA reconstructs a CA from its PEM certificate and private key.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certDER, err := decodePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate %q is not a CA", cert.Subject.CommonName)
	}
	keyDER, err := decodePEM(keyPEM, "EC PRIVATE KEY", "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	key, err := parseECKey(keyDER)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: certPEM, now: time.Now}, nil
}

// Marshal returns the CA's own certificate and private key as a KeyPair, for
// persisting after NewCA. The key must be stored as a secret (0600/SOPS), never
// in git.
func (ca *CA) Marshal() (KeyPair, error) {
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal CA key: %w", err)
	}
	return KeyPair{
		CertPEM: ca.certPEM,
		KeyPEM:  pemBlock("EC PRIVATE KEY", keyDER),
	}, nil
}

// CertPEM returns the CA certificate (public, safe to distribute).
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// NotAfter is when this CA lapses. Every node certificate chains to it, so the
// lapse invalidates the whole fleet at once — and unlike a node certificate there
// is no control-plane path left to repair it. Exposed so it can be measured.
func (ca *CA) NotAfter() time.Time { return ca.cert.NotAfter }

// CertPool returns a pool trusting only this CA, for verifying peers.
func (ca *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// IssueServerCert issues the controller's server certificate, valid for the
// given DNS names and IPs (SANs). It generates a fresh key for the leaf.
func (ca *CA) IssueServerCert(commonName string, hosts []string) (KeyPair, error) {
	return ca.issueLeaf(commonName, hosts, x509.ExtKeyUsageServerAuth)
}

// IssueNodeCert issues a node's client certificate with CN=nodeID. This is the
// node's control-plane identity.
func (ca *CA) IssueNodeCert(nodeID string) (KeyPair, error) {
	return ca.issueLeaf(nodeID, nil, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issueLeaf(commonName string, hosts []string, eku x509.ExtKeyUsage) (KeyPair, error) {
	if commonName == "" {
		return KeyPair{}, fmt.Errorf("certificate common name is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return KeyPair{}, err
	}
	now := ca.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"wgfleet"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("sign leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal leaf key: %w", err)
	}
	return KeyPair{
		CertPEM: pemBlock("CERTIFICATE", der),
		KeyPEM:  pemBlock("EC PRIVATE KEY", keyDER),
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func parseECKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	// Fall back to PKCS#8, which some tools emit.
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse EC key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want *ecdsa.PrivateKey", parsed)
	}
	return key, nil
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func decodePEM(data []byte, types ...string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	for _, t := range types {
		if block.Type == t {
			return block.Bytes, nil
		}
	}
	return nil, fmt.Errorf("unexpected PEM type %q, want one of %v", block.Type, types)
}

// SignNodeCSR issues a fresh node certificate for a certificate request the node
// generated itself.
//
// This is the renewal path, and it differs from IssueNodeCert in the one way that
// matters: the node keeps its private key. Bootstrap has no choice — there is no
// channel yet, so the controller mints both halves and ships them over SSH — but a
// node that is already talking to us can generate a keypair, send only the public
// half, and never put its identity on the wire at all.
//
// callerID is the identity of the VERIFIED mTLS peer, and it overrides whatever
// subject the request carries. A certificate request is an unauthenticated blob of
// the requester's choosing; treating its CommonName as the name to issue would let
// any node with a valid certificate rename itself into any other node in the fleet.
// The same rule the gRPC layer already follows: identity comes from the connection,
// never from the message.
func (ca *CA) SignNodeCSR(csrDER []byte, callerID string) ([]byte, error) {
	if callerID == "" {
		return nil, fmt.Errorf("sign CSR: caller identity is required")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: parse: %w", err)
	}
	// The signature proves the requester holds the private key for the public key
	// they are asking us to certify. Without this check a node could have us certify
	// somebody else's public key under its own name.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("sign CSR: signature: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := ca.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: callerID, Organization: []string{"wgfleet"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}
	return pemBlock("CERTIFICATE", der), nil
}

// NodeCertRenewalWire mirrors api.WireCertRenewal for callers that must name the
// version in operator-facing text without importing the wire contract.
const NodeCertRenewalWire = 10
