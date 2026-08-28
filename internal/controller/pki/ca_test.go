package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

// Renewal signs a CSR the node generated, so the node's private key never crosses
// the wire — and the identity in the resulting certificate comes from the caller,
// never from the request.
func TestSignNodeCSRTakesTheNameFromTheCallerNotTheRequest(t *testing.T) {
	ca, err := NewCA("wgfleet-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A node asking, dishonestly, to be someone else.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "master-xa-1"}}, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := ca.SignNodeCSR(csrDER, "exit-de-1")
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block returned")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "exit-de-1" {
		t.Errorf("CN = %q, want the caller's identity %q — a node must not be able to rename itself by asking",
			cert.Subject.CommonName, "exit-de-1")
	}
	// The certificate must belong to the key the node holds, or it is useless to it.
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("the signed certificate does not carry the requester's public key")
	}
	// Client auth only: a node certificate must never be usable as a server.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want client auth only", cert.ExtKeyUsage)
	}
	// And a full validity period, not the remainder of the old one.
	if d := time.Until(cert.NotAfter); d < 360*24*time.Hour {
		t.Errorf("renewed certificate is valid for %v, want a full term", d)
	}
	if _, err := ca.SignNodeCSR([]byte("not a csr"), "exit-de-1"); err == nil {
		t.Error("a malformed CSR was accepted")
	}
	if _, err := ca.SignNodeCSR(csrDER, ""); err == nil {
		t.Error("an empty caller identity was accepted")
	}
}
