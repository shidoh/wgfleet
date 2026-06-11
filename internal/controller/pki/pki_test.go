package pki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestCAMarshalRoundTrip(t *testing.T) {
	ca, err := NewCA("wgfleet-test-ca")
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	kp, err := ca.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	loaded, err := LoadCA(kp.CertPEM, kp.KeyPEM)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// A cert issued by the reloaded CA must verify against the original pool.
	leaf, err := loaded.IssueNodeCert("exit-de-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := verifyAgainst(ca.CertPool(), leaf, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("leaf from reloaded CA should verify against original pool: %v", err)
	}
}

func TestIssueNodeCertSetsCN(t *testing.T) {
	ca, _ := NewCA("ca")
	kp, err := ca.IssueNodeCert("exit-nl-7")
	if err != nil {
		t.Fatal(err)
	}
	cert := parseLeaf(t, kp)
	if cert.Subject.CommonName != "exit-nl-7" {
		t.Errorf("CN = %q, want exit-nl-7", cert.Subject.CommonName)
	}
	if !hasEKU(cert, x509.ExtKeyUsageClientAuth) {
		t.Error("node cert missing client-auth EKU")
	}
}

func TestIssueServerCertHasSANs(t *testing.T) {
	ca, _ := NewCA("ca")
	kp, err := ca.IssueServerCert("controller", []string{"controller.mgmt", "10.20.25.254"})
	if err != nil {
		t.Fatal(err)
	}
	cert := parseLeaf(t, kp)
	if !hasEKU(cert, x509.ExtKeyUsageServerAuth) {
		t.Error("server cert missing server-auth EKU")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "controller.mgmt" {
		t.Errorf("DNS SANs = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.20.25.254" {
		t.Errorf("IP SANs = %v", cert.IPAddresses)
	}
}

func TestEmptyCommonNameRejected(t *testing.T) {
	ca, _ := NewCA("ca")
	if _, err := ca.IssueNodeCert(""); err == nil {
		t.Fatal("expected error for empty CN")
	}
}

// TestMutualTLSHandshake exercises the full server+client config against a real
// in-memory TLS connection and checks identity extraction from the peer cert.
func TestMutualTLSHandshake(t *testing.T) {
	ca, _ := NewCA("ca")
	serverKP, _ := ca.IssueServerCert("controller", []string{"127.0.0.1"})
	nodeKP, _ := ca.IssueNodeCert("exit-de-1")

	serverCfg, err := ca.ServerTLSConfig(serverKP)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := ca.ClientTLSConfig(nodeKP, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	identityCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err
			return
		}
		cn, err := CommonNameFromCerts(tlsConn.ConnectionState().VerifiedChains)
		if err != nil {
			errCh <- err
			return
		}
		identityCh <- cn
	}()

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()

	select {
	case cn := <-identityCh:
		if cn != "exit-de-1" {
			t.Errorf("server saw identity %q, want exit-de-1", cn)
		}
	case err := <-errCh:
		t.Fatalf("server side: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}
}

func TestUntrustedClientRejected(t *testing.T) {
	serverCA, _ := NewCA("server-ca")
	rogueCA, _ := NewCA("rogue-ca")

	serverKP, _ := serverCA.IssueServerCert("controller", []string{"127.0.0.1"})
	rogueKP, _ := rogueCA.IssueNodeCert("attacker")

	serverCfg, _ := serverCA.ServerTLSConfig(serverKP)
	clientCfg, _ := rogueCA.ClientTLSConfig(rogueKP, "127.0.0.1")
	clientCfg.RootCAs = serverCA.CertPool() // client trusts server, but its own cert is rogue

	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		_ = tlsConn.Handshake() // expected to fail; server rejects rogue client
		_ = conn.Close()
	}()

	// In TLS 1.3 the client finishes its handshake before the server validates
	// the client certificate, so the dial may succeed; the rejection surfaces
	// as an alert on the first read. Either path proves the rogue is rejected.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		return // rejected at handshake — good
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("read over connection with untrusted client cert should have failed")
	}
}

// --- helpers ---

func parseLeaf(t *testing.T, kp KeyPair) *x509.Certificate {
	t.Helper()
	der, err := decodePEM(kp.CertPEM, "CERTIFICATE")
	if err != nil {
		t.Fatalf("decode leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func verifyAgainst(pool *x509.CertPool, kp KeyPair, eku x509.ExtKeyUsage) error {
	der, err := decodePEM(kp.CertPEM, "CERTIFICATE")
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{eku}})
	return err
}

func hasEKU(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}
