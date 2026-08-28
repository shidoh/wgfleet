package grpcapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"crypto/tls"
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"math/big"
)

// spySigner records the identity the service passed down.
type spySigner struct {
	ca     *pki.CA
	sawID  string
	forced error
}

func (s *spySigner) SignNodeCSR(csrDER []byte, callerID string) ([]byte, error) {
	s.sawID = callerID
	if s.forced != nil {
		return nil, s.forced
	}
	return s.ca.SignNodeCSR(csrDER, callerID)
}
func (s *spySigner) CertPEM() []byte { return s.ca.CertPEM() }

func testCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Renewal must be scoped to whoever the connection says is calling, never to the
// name in the request. Anything else lets one valid node mint a certificate for
// every other node in the fleet.
func TestRenewCertificateIssuesForTheVerifiedCallerOnly(t *testing.T) {
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	spy := &spySigner{ca: ca}
	svc := NewService(nil, nil, nil)
	svc.SetCertSigner(spy)

	ctx := ctxWithNodeIdentity(t, "exit-de-1")
	resp, err := svc.RenewCertificate(ctx, &pb.RenewCertificateRequest{CsrDer: testCSR(t, "master-xa-1")})
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if spy.sawID != "exit-de-1" {
		t.Errorf("signed for %q, want the verified peer %q", spy.sawID, "exit-de-1")
	}
	if len(resp.GetCertPem()) == 0 || len(resp.GetCaCertPem()) == 0 {
		t.Error("response is missing the certificate or the CA")
	}
}

// An unauthenticated caller has no identity, so there is nothing to renew.
func TestRenewCertificateRefusesAnUnidentifiedCaller(t *testing.T) {
	svc := NewService(nil, nil, nil)
	svc.SetCertSigner(&spySigner{})
	if _, err := svc.RenewCertificate(context.Background(),
		&pb.RenewCertificateRequest{CsrDer: []byte("x")}); err == nil {
		t.Error("a caller with no verified certificate was served")
	}
}

// A controller with no CA must say so rather than fail obscurely: a node that
// cannot renew is heading for expiry and should hear about it.
func TestRenewCertificateSaysSoWithNoCA(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-de-1"),
		&pb.RenewCertificateRequest{CsrDer: testCSR(t, "exit-de-1")})
	if err == nil {
		t.Fatal("renewal succeeded with no signer configured")
	}
}

func TestRenewCertificateRefusesAnEmptyRequest(t *testing.T) {
	ca, _ := pki.NewCA("test-ca")
	svc := NewService(nil, nil, nil)
	svc.SetCertSigner(&spySigner{ca: ca})
	if _, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-de-1"),
		&pb.RenewCertificateRequest{}); err == nil {
		t.Error("an empty certificate request was accepted")
	}
	spy := &spySigner{ca: ca, forced: errors.New("bad csr")}
	svc.SetCertSigner(spy)
	if _, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-de-1"),
		&pb.RenewCertificateRequest{CsrDer: []byte("nonsense")}); err == nil {
		t.Error("a malformed certificate request was accepted")
	}
}

// ctxWithNodeIdentity builds the context the gRPC layer would present for a peer
// whose VERIFIED chain carries this CommonName.
func ctxWithNodeIdentity(t *testing.T, cn string) context.Context {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}
