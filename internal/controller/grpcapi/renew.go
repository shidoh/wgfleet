package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
)

// CertSigner signs a node's certificate request. The controller supplies its CA;
// kept an interface so the service does not import the PKI package and so tests
// can watch what identity is passed down.
type CertSigner interface {
	SignNodeCSR(csrDER []byte, callerID string) ([]byte, error)
	CertPEM() []byte
}

// SetCertSigner enables RenewCertificate. Without one the RPC is refused rather
// than silently unavailable: a node that cannot renew is a node heading for expiry,
// and it should hear about it while there is still time to act.
func (s *Service) SetCertSigner(signer CertSigner) { s.signer = signer }

// RenewCertificate issues a fresh client certificate for the caller's own identity.
//
// The authorisation model is the connection itself. NodeIDFromContext reads the verified
// mTLS peer's CommonName — never a field of the request — so asking requires a
// certificate that is currently valid, and the answer can only ever be a
// certificate for the asker. There is nothing to approve and no pending-request
// object to keep in sync, which for a fleet of this size is the whole point.
//
// The corollary is that an ALREADY EXPIRED certificate cannot be renewed here: the
// handshake fails before this method is reached. That is not a gap to be patched
// but the property that makes the model safe, and it is why the operator keeps an
// out-of-band path (--certs renew, delivered over SSH) for the node that missed its
// window.
func (s *Service) RenewCertificate(ctx context.Context, req *pb.RenewCertificateRequest) (*pb.RenewCertificateResponse, error) {
	nodeID, err := NodeIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if s.signer == nil {
		return nil, status.Error(codes.Unimplemented,
			"this controller cannot sign renewals (no CA loaded); re-issue the certificate out of band")
	}
	if len(req.GetCsrDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate request is empty")
	}
	certPEM, err := s.signer.SignNodeCSR(req.GetCsrDer(), nodeID)
	if err != nil {
		s.log.Warn("certificate renewal refused", "node", nodeID, "err", err)
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate request: %v", err)
	}
	s.log.Info("certificate renewed", "node", nodeID)
	return &pb.RenewCertificateResponse{CertPem: certPEM, CaCertPem: s.signer.CertPEM()}, nil
}
