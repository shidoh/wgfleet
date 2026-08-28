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
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
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
	svc := NewService(renewTestStore(t, "exit-de-1", "master-xa-1"), nil, nil)
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
	svc := NewService(renewTestStore(t, "exit-de-1", "master-xa-1"), nil, nil)
	svc.SetCertSigner(&spySigner{})
	if _, err := svc.RenewCertificate(context.Background(),
		&pb.RenewCertificateRequest{CsrDer: []byte("x")}); err == nil {
		t.Error("a caller with no verified certificate was served")
	}
}

// A controller with no CA must say so rather than fail obscurely: a node that
// cannot renew is heading for expiry and should hear about it.
func TestRenewCertificateSaysSoWithNoCA(t *testing.T) {
	svc := NewService(renewTestStore(t, "exit-de-1", "master-xa-1"), nil, nil)
	_, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-de-1"),
		&pb.RenewCertificateRequest{CsrDer: testCSR(t, "exit-de-1")})
	if err == nil {
		t.Fatal("renewal succeeded with no signer configured")
	}
}

func TestRenewCertificateRefusesAnEmptyRequest(t *testing.T) {
	ca, _ := pki.NewCA("test-ca")
	svc := NewService(renewTestStore(t, "exit-de-1", "master-xa-1"), nil, nil)
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

// Expiry was the only revocation this system ever had: there is no CRL, so Drain →
// Decommission → Delete removed the inventory row and the fleet then WAITED OUT the
// certificate. Renewal taken from the CN alone quietly repealed that — a retired
// host would have been handed a fresh year on every anniversary, forever, and
// Register re-creates the row it was deleted from on the very next pass. A VPS
// handed back to its provider must not leave with a self-renewing key to the
// control plane.
func TestRenewCertificateRefusesNodesThatLeftTheFleet(t *testing.T) {
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("deleted from inventory", func(t *testing.T) {
		svc := NewService(renewTestStore(t, "master-xa-1"), nil, nil)
		svc.SetCertSigner(&spySigner{ca: ca})
		_, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-retired"),
			&pb.RenewCertificateRequest{CsrDer: testCSR(t, "exit-retired")})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("a node that is not in the inventory renewed: err = %v", err)
		}
	})

	t.Run("decommissioned", func(t *testing.T) {
		st := renewTestStore(t, "exit-de-1")
		if err := st.SetNodeDecommission(context.Background(), "exit-de-1", true); err != nil {
			t.Fatal(err)
		}
		svc := NewService(st, nil, nil)
		svc.SetCertSigner(&spySigner{ca: ca})
		_, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-de-1"),
			&pb.RenewCertificateRequest{CsrDer: testCSR(t, "exit-de-1")})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("a decommissioned node renewed: err = %v", err)
		}
	})

	t.Run("still in the fleet", func(t *testing.T) {
		svc := NewService(renewTestStore(t, "exit-de-1"), nil, nil)
		svc.SetCertSigner(&spySigner{ca: ca})
		if _, err := svc.RenewCertificate(ctxWithNodeIdentity(t, "exit-de-1"),
			&pb.RenewCertificateRequest{CsrDer: testCSR(t, "exit-de-1")}); err != nil {
			t.Errorf("a live node was refused: %v", err)
		}
	})
}

// renewTestStore builds an in-memory inventory holding exactly these nodes.
func renewTestStore(t *testing.T, ids ...string) store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, id := range ids {
		if err := st.UpsertNode(context.Background(), domain.Node{
			ID: id, Name: id, Role: domain.RoleExit, State: domain.StateReady,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}
