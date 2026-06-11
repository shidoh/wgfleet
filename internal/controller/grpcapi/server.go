package grpcapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/shidoh/wgfleet/internal/api"
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// SpecRenderer renders the desired NodeSpec for a node. *keybroker.Broker
// satisfies it; the interface keeps the server testable.
type SpecRenderer interface {
	RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error)
	RegisterPublicKey(ctx context.Context, nodeID, publicKey string) error
}

// Service implements pb.NodeServiceServer, backed by the store and key broker.
type Service struct {
	pb.UnimplementedNodeServiceServer
	store    store.Store
	renderer SpecRenderer
	log      *slog.Logger
}

var _ pb.NodeServiceServer = (*Service)(nil)

// NewService constructs the NodeService implementation.
func NewService(st store.Store, renderer SpecRenderer, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, renderer: renderer, log: log}
}

// NewServer builds a gRPC server with mTLS credentials and the NodeService
// registered. The caller owns the listener and calls Serve/GracefulStop.
func NewServer(tlsCfg *tls.Config, svc *Service) *grpc.Server {
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterNodeServiceServer(s, svc)
	return s
}

// Register announces a node. Identity comes from the cert CN; the request only
// carries discovered facts (role, public IP, region). The node row is created
// on first contact (it is already authorized — it holds a CA-issued cert) and
// updated idempotently thereafter.
func (s *Service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	nodeID, err := NodeIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	role, err := domain.ParseRole(req.GetRole())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "register %q: %v", nodeID, err)
	}

	node, err := s.store.GetNode(ctx, nodeID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		node = domain.Node{ID: nodeID, Name: nodeID}
		s.log.Warn("node registering without prior inventory entry; auto-creating",
			"node", nodeID, "role", role)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "lookup node %q: %v", nodeID, err)
	}

	node.Role = role
	if req.GetPublicIp() != "" {
		node.PublicIP = req.GetPublicIp()
	}
	if req.GetRegion() != "" {
		node.Region = req.GetRegion()
	}
	if req.GetMgmtAddr() != "" {
		node.MgmtAddr = req.GetMgmtAddr()
	}
	if node.State == "" || node.State == domain.StatePending {
		node.State = domain.StateReconciling
	}
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return nil, status.Errorf(codes.Internal, "persist node %q: %v", nodeID, err)
	}
	s.log.Info("node registered", "node", nodeID, "role", role, "public_ip", node.PublicIP)
	return &pb.RegisterResponse{NodeId: nodeID, State: string(node.State)}, nil
}

// PublishPublicKey records the node's WireGuard public key in the key registry.
func (s *Service) PublishPublicKey(ctx context.Context, req *pb.PublishPublicKeyRequest) (*pb.PublishPublicKeyResponse, error) {
	nodeID, err := NodeIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if req.GetPublicKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "public key is empty")
	}
	if err := s.renderer.RegisterPublicKey(ctx, nodeID, req.GetPublicKey()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.FailedPrecondition, "node %q not registered", nodeID)
		}
		return nil, status.Errorf(codes.Internal, "register pubkey for %q: %v", nodeID, err)
	}
	s.log.Info("public key registered", "node", nodeID)
	return &pb.PublishPublicKeyResponse{Accepted: true}, nil
}

// PullSpec returns the node's desired NodeSpec, rendered from fleet config and
// the pubkey registry.
func (s *Service) PullSpec(ctx context.Context, _ *pb.PullSpecRequest) (*pb.NodeSpec, error) {
	nodeID, err := NodeIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	spec, err := s.renderer.RenderNodeSpec(ctx, nodeID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "render spec for %q: %v", nodeID, err)
	}
	return api.SpecToProto(spec), nil
}

// ReportStatus consumes a stream of status reports and persists the latest from
// each. It also reflects the reported state onto the node row.
func (s *Service) ReportStatus(stream pb.NodeService_ReportStatusServer) error {
	nodeID, err := NodeIDFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	var received uint32
	for {
		report, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&pb.ReportStatusAck{Received: received})
		}
		if err != nil {
			return status.Errorf(codes.Internal, "recv status from %q: %v", nodeID, err)
		}
		st := api.StatusFromProto(nodeID, report)
		if err := s.store.RecordStatus(stream.Context(), st); err != nil {
			return status.Errorf(codes.Internal, "record status from %q: %v", nodeID, err)
		}
		if st.State.Valid() {
			if err := s.store.SetNodeState(stream.Context(), nodeID, st.State, st.ReconcileError); err != nil &&
				!errors.Is(err, store.ErrNotFound) {
				return status.Errorf(codes.Internal, "set state for %q: %v", nodeID, err)
			}
		}
		received++
	}
}
