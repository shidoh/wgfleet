package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// ServerTLSConfig builds the controller's TLS config: it presents serverKP and
// requires every client to present a certificate signed by this CA. TLS 1.3 is
// the floor. Node identity is then taken from the verified peer cert CN.
func (ca *CA) ServerTLSConfig(serverKP KeyPair) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverKP.CertPEM, serverKP.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds an agent's TLS config: it presents clientKP and trusts
// only this CA for the server. serverName must match a SAN on the controller's
// server certificate.
func (ca *CA) ClientTLSConfig(clientKP KeyPair, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientKP.CertPEM, clientKP.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.CertPool(),
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// CommonNameFromCerts returns the CN of the leaf (first) verified peer
// certificate — the authenticated node identity. It is the bridge between the
// TLS layer and the application's notion of "which node is this".
func CommonNameFromCerts(chains [][]*x509.Certificate) (string, error) {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", fmt.Errorf("no verified peer certificate")
	}
	cn := chains[0][0].Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("peer certificate has empty common name")
	}
	return cn, nil
}
