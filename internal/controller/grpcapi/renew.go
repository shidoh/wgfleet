package grpcapi

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/controller/store"
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
//
// The inventory check below is the other half, and it is not optional. There is no
// CRL, so before renewal existed the ONLY thing that ever ended a node's membership
// was NotAfter: Drain → Decommission → Delete removed the row and the fleet then
// waited out the certificate. Renewal, taken from the CN alone, would have handed a
// retired host a fresh year on every anniversary — forever, and invisibly, since
// Register re-creates the inventory row it was deleted from on the very next pass.
// A VPS handed back to its provider must not leave with a self-renewing key to the
// control plane. So: no row, or Decommission set, means no renewal, and a store that
// cannot answer means no renewal either — a node has 20% of its lifetime (73 days)
// to ask again, which is a great deal longer than any database outage worth
// weighing against handing out a year of access on a failed read.
func (s *Service) RenewCertificate(ctx context.Context, req *pb.RenewCertificateRequest) (*pb.RenewCertificateResponse, error) {
	nodeID, err := NodeIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Fail closed on every answer but "this node is still in the fleet".
	node, err := s.store.GetNode(ctx, nodeID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("certificate renewal refused: node is not in the inventory", "node", nodeID)
		return nil, status.Error(codes.PermissionDenied,
			"this node is not in the fleet inventory; renewal is refused")
	case err != nil:
		s.log.Error("certificate renewal refused: inventory unreadable", "node", nodeID, "err", err)
		return nil, status.Errorf(codes.Unavailable, "look up node %q: %v", nodeID, err)
	case node.Decommission:
		s.log.Warn("certificate renewal refused: node is decommissioned", "node", nodeID)
		return nil, status.Error(codes.PermissionDenied,
			"this node is decommissioned; renewal is refused")
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
