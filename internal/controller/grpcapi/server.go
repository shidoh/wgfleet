package grpcapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/shidoh/wgfleet/internal/api"
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/logging"
)

// SpecRenderer renders the desired NodeSpec for a node. *keybroker.Broker
// satisfies it; the interface keeps the server testable.
type SpecRenderer interface {
	RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error)
	RegisterPublicKey(ctx context.Context, nodeID, publicKey string) error
	RegisterRealityKey(ctx context.Context, nodeID, publicKey string) error
	RegisterClientVlessKey(ctx context.Context, nodeID, publicKey string) error
	// RegisterClientWGKey records the master's client-facing WireGuard public key
	// (the interface end users dial once the agent owns it).
	RegisterClientWGKey(ctx context.Context, nodeID, publicKey string) error
	// RegisterLifelineKey records an exit's LIFELINE interface WireGuard public
	// key (the reserve client-facing interface awgl0).
	RegisterLifelineKey(ctx context.Context, nodeID, publicKey string) error
	RegisterTunnelKey(ctx context.Context, nodeID, tunnel, publicKey string) error
}

// Service implements pb.NodeServiceServer, backed by the store and key broker.
type Service struct {
	pb.UnimplementedNodeServiceServer
	store    store.Store
	renderer SpecRenderer
	log      *slog.Logger
	trigger  UpgradeTrigger // optional auto-upgrade hook; see SetUpgradeTrigger
	signer   CertSigner     // optional CA for RenewCertificate; see SetCertSigner
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
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		// Tolerate the agents' client keepalive pings. Agents ping while idle between
		// reconciles so a dead control channel is detected and torn down fast; without
		// a permissive enforcement policy the server GOAWAYs a client that pings "too
		// often" (default MinTime 5m, no pings without a stream), which would defeat
		// the keepalive. MinTime must be ≤ the client's keepalive Time (30s).
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
		// Proactively probe idle agent connections so the controller sheds half-open
		// ones (an agent that vanished on a flaky overlay) instead of pinning them.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 20 * time.Second,
		}),
	)
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
	if err := s.gateVersion(ctx, nodeID); err != nil {
		return nil, err
	}
	role, err := domain.ParseRole(req.GetRole())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "register %q: %v", nodeID, err)
	}
	wire, agentVersion := reportedVersions(ctx)
	logging.Trace(s.log, "rpc Register", "node", nodeID, "role", role, "wire", wire, "agent_version", agentVersion,
		"public_ip", req.GetPublicIp(), "mgmt_addr", req.GetMgmtAddr())

	node, err := s.store.GetNode(ctx, nodeID)
	known := true
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Deleted is not "never seen". The certificate is not revoked when a node
		// is deleted, so an agent that still reaches the controller would re-create
		// its row here on the next pass and undo the operator's delete — and put
		// the exit back in the master's tunnel list. A retired id stays out until
		// someone provisions it again on purpose.
		if retired, rerr := s.store.Retired(ctx, nodeID); rerr != nil {
			return nil, status.Errorf(codes.Internal, "lookup node %q: %v", nodeID, rerr)
		} else if retired {
			s.log.Warn("a deleted node tried to register; refused — provision it again to re-admit it, or stop its agent",
				"node", nodeID, "role", role)
			return nil, status.Errorf(codes.PermissionDenied,
				"node %q was deleted from the fleet; it is not admitted until an operator provisions it again", nodeID)
		}
		known = false
		node = domain.Node{ID: nodeID, Name: nodeID}
		s.log.Warn("node registering without prior inventory entry; auto-creating",
			"node", nodeID, "role", role)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "lookup node %q: %v", nodeID, err)
	}
	before := node

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
	node.AgentVersion = agentVersion
	node.WireVersion = wire
	if node.State == "" || node.State == domain.StatePending {
		node.State = domain.StateReconciling
	}
	// Register is called on EVERY agent reconcile pass (~every 30s per node), and in
	// steady state nothing it carries has changed. Writing anyway rewrote identical
	// rows around the clock — pure WAL churn — and logging anyway buried the real
	// events under ~59k INFO lines/day. So persist and announce only on an actual
	// delta; the unchanged case is a DEBUG line and no write at all. Liveness does
	// not depend on this write: ReportStatus stamps last_seen on every report.
	if known && node == before {
		s.log.Debug("node re-registered (unchanged)", "node", nodeID, "role", role)
		return &pb.RegisterResponse{NodeId: nodeID, State: string(node.State)}, nil
	}
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return nil, status.Errorf(codes.Internal, "persist node %q: %v", nodeID, err)
	}
	// Say WHAT changed, and who asked.
	//
	// The guard above is supposed to make this line rare: in steady state a
	// re-registration carries nothing new, so there is nothing to persist and
	// nothing to announce. Measured on the live master 2026-09-04 it fired 721
	// times in three hours — 97% of the controller's entire journal, for one node,
	// while not a single exit appeared — which means the guard never holds there and
	// the row is rewritten every ~15 seconds forever. It also buried the events an
	// operator actually needs: the reason mihomo bounced twice in 36 seconds that
	// morning could not be reconstructed from this log at all.
	//
	// Naming the differing fields and the caller turns "it happens" into "this field,
	// from this peer", which is the difference between a mystery and a fix.
	s.log.Info("node registered", "node", nodeID, "role", role, "public_ip", node.PublicIP,
		"changed", changedNodeFields(before, node, known), "peer", peerAddr(ctx))
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
	// Route by key type: empty == WireGuard (back-compat); "reality" is the exit's
	// REALITY x25519 key for the master's vless proxy (ADR-0025); "wireguard:<exit>"
	// is the master's per-tunnel WireGuard identity for one master↔exit tunnel
	// (ADR-0030). Anything else is rejected rather than silently stored under a type
	// nothing reads.
	register := s.renderer.RegisterPublicKey
	keyType := req.GetKeyType()
	switch {
	case keyType == api.KeyTypeWireGuard:
	case keyType == api.KeyTypeReality:
		register = s.renderer.RegisterRealityKey
	case keyType == api.KeyTypeClientVless:
		register = s.renderer.RegisterClientVlessKey
	case keyType == api.KeyTypeClientWG:
		register = s.renderer.RegisterClientWGKey
	case keyType == api.KeyTypeLifeline:
		register = s.renderer.RegisterLifelineKey
	default:
		tunnel, ok := api.ParseTunnelKeyType(keyType)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown key type %q", keyType)
		}
		register = func(ctx context.Context, nodeID, publicKey string) error {
			return s.renderer.RegisterTunnelKey(ctx, nodeID, tunnel, publicKey)
		}
	}
	if err := register(ctx, nodeID, req.GetPublicKey()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.FailedPrecondition, "node %q not registered", nodeID)
		}
		return nil, status.Errorf(codes.Internal, "register %s key for %q: %v", keyTypeLabel(keyType), nodeID, err)
	}
	// DEBUG, not INFO: this fires on every publish, and agents republish every key
	// on every reconcile pass. The keybroker logs at INFO when a key actually
	// changes, so a real rotation is still visible without the per-pass noise.
	s.log.Debug("public key published", "node", nodeID, "type", keyTypeLabel(keyType))
	return &pb.PublishPublicKeyResponse{Accepted: true}, nil
}

// keyTypeLabel gives the empty (WireGuard) key type a readable name for logs.
func keyTypeLabel(t string) string {
	if t == api.KeyTypeWireGuard {
		return "wireguard"
	}
	return t
}

// PullSpec returns the node's desired NodeSpec, rendered from fleet config and
// the pubkey registry.
func (s *Service) PullSpec(ctx context.Context, _ *pb.PullSpecRequest) (*pb.NodeSpec, error) {
	nodeID, err := NodeIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.gateVersion(ctx, nodeID); err != nil {
		return nil, err
	}
	spec, err := s.renderer.RenderNodeSpec(ctx, nodeID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "render spec for %q: %v", nodeID, err)
	}
	logging.Trace(s.log, "rpc PullSpec", "node", nodeID, "peers", len(spec.Peers),
		"exit_tunnels", exitTunnelCount(spec), "decommission", spec.Decommission)
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
		logging.Trace(s.log, "rpc ReportStatus", "node", nodeID, "state", st.State,
			"checks", len(st.Checks), "egress_ip", st.EgressIP, "exit_health", len(st.ExitHealth))
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

// changedNodeFields names the fields that differ between the stored node and the
// one this registration would write. A first registration reports "new" rather
// than every field, which would be noise on the one occasion the write is
// expected.
func changedNodeFields(before, after domain.Node, known bool) string {
	if !known {
		return "new"
	}
	var changed []string
	bv, av := reflect.ValueOf(before), reflect.ValueOf(after)
	t := bv.Type()
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		if !reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
			changed = append(changed, t.Field(i).Name)
		}
	}
	if len(changed) == 0 {
		return "nothing"
	}
	return strings.Join(changed, ",")
}

// peerAddr reports the caller's address, or "unknown" when the transport does not
// carry one. Two registrations arriving 1.5 seconds apart every 30 seconds is a
// different problem depending on whether they come from one peer or two, and the
// journal could not tell.
func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return "unknown"
}

// exitTunnelCount is what a trace line can say about a spec without printing it.
func exitTunnelCount(spec domain.NodeSpec) int {
	if spec.Master == nil {
		return 0
	}
	return len(spec.Master.ExitTunnels)
}
