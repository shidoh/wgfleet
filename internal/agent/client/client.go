// Package client is the agent's mTLS gRPC client to the controller's
// NodeService. It hides the wire types: callers work in domain terms.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/shidoh/wgfleet/internal/api"
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/version"
)

// Client is a controller connection for one agent.
type Client struct {
	conn *grpc.ClientConn
	rpc  pb.NodeServiceClient
}

// Dial connects to the controller at addr using the given mTLS config. It does
// not block on connectivity; the first RPC establishes the connection. Every RPC
// carries the agent's build + wire version as metadata so the controller can gate
// incompatible agents before acting (see internal/api/wire.go).
func Dial(addr string, tlsCfg *tls.Config) (*Client, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithChainUnaryInterceptor(versionUnaryInterceptor),
		grpc.WithChainStreamInterceptor(versionStreamInterceptor),
		// Recover from control-plane blips in seconds, not the gRPC default of up to
		// ~120s: cap the reconnect backoff so a node that briefly lost the controller
		// (an overlay MTU/relay hiccup, a controller restart) re-registers promptly
		// once the path is back, instead of flapping Degraded while it waits out a
		// long backoff.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   20 * time.Second,
			},
			MinConnectTimeout: 20 * time.Second,
		}),
		// Keep the idle connection warm and detect a dead one proactively, so the next
		// reconcile does not stall on a half-open socket. Time (30s) is ≥ the server's
		// enforced MinTime (15s), so the server never GOAWAYs us for pinging too fast.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial controller %q: %w", addr, err)
	}
	return &Client{conn: conn, rpc: pb.NewNodeServiceClient(conn)}, nil
}

// versionContext appends the agent's wire + build version to the outgoing
// metadata so the controller can read it on every RPC.
func versionContext(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		api.MDWireVersion, strconv.FormatUint(uint64(api.WireContractVersion), 10),
		api.MDAgentVersion, version.Short(),
	)
}

func versionUnaryInterceptor(ctx context.Context, method string, req, reply any,
	cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(versionContext(ctx), method, req, reply, cc, opts...)
}

func versionStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
	method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(versionContext(ctx), desc, cc, method, opts...)
}

// Close releases the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// Register announces this node to the controller and returns its current state.
func (c *Client) Register(ctx context.Context, role domain.Role, publicIP, region, mgmtAddr string) (domain.NodeState, error) {
	resp, err := c.rpc.Register(ctx, &pb.RegisterRequest{
		Role:     string(role),
		PublicIp: publicIP,
		Region:   region,
		MgmtAddr: mgmtAddr,
	})
	if err != nil {
		return "", fmt.Errorf("register: %w", err)
	}
	return domain.NodeState(resp.GetState()), nil
}

// PublishPublicKey registers this node's WireGuard public key.
func (c *Client) PublishPublicKey(ctx context.Context, publicKey string) error {
	return c.publishKey(ctx, publicKey, api.KeyTypeWireGuard)
}

// PublishRealityKey registers this exit's REALITY x25519 public key (ADR-0025),
// stored separately from the WireGuard key.
func (c *Client) PublishRealityKey(ctx context.Context, publicKey string) error {
	return c.publishKey(ctx, publicKey, api.KeyTypeReality)
}

// PublishClientVlessKey registers this master's CLIENT-FACING REALITY x25519
// public key (the client VLESS inbound), stored separately from the WireGuard and
// exit-reality keys.
func (c *Client) PublishClientVlessKey(ctx context.Context, publicKey string) error {
	return c.publishKey(ctx, publicKey, api.KeyTypeClientVless)
}

// PublishClientWGKey registers this master's CLIENT-FACING WireGuard public key
// (the AmneziaWG interface end users dial), stored separately from the node's
// fleet-internal WireGuard key.
func (c *Client) PublishClientWGKey(ctx context.Context, publicKey string) error {
	return c.publishKey(ctx, publicKey, api.KeyTypeClientWG)
}

// PublishLifelineKey registers this exit's LIFELINE interface WireGuard public
// key (the reserve client-facing interface awgl0), stored separately from the
// node's fleet-internal and ordinary client-facing keys.
func (c *Client) PublishLifelineKey(ctx context.Context, publicKey string) error {
	return c.publishKey(ctx, publicKey, api.KeyTypeLifeline)
}

// PublishTunnelKey registers the master's per-tunnel WireGuard public key for one
// master↔exit tunnel (ADR-0030). tunnel is the exit's node name.
func (c *Client) PublishTunnelKey(ctx context.Context, tunnel, publicKey string) error {
	return c.publishKey(ctx, publicKey, api.TunnelKeyType(tunnel))
}

func (c *Client) publishKey(ctx context.Context, publicKey, keyType string) error {
	resp, err := c.rpc.PublishPublicKey(ctx, &pb.PublishPublicKeyRequest{
		PublicKey: publicKey,
		KeyType:   keyType,
	})
	if err != nil {
		return fmt.Errorf("publish %q key: %w", keyType, err)
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("controller rejected %q key", keyType)
	}
	return nil
}

// PullSpec fetches this node's desired NodeSpec.
func (c *Client) PullSpec(ctx context.Context) (domain.NodeSpec, error) {
	pbSpec, err := c.rpc.PullSpec(ctx, &pb.PullSpecRequest{})
	if err != nil {
		return domain.NodeSpec{}, fmt.Errorf("pull spec: %w", err)
	}
	return api.SpecFromProto(pbSpec), nil
}

// ReportStatus sends one status report and closes the stream, returning the
// number of reports the controller acknowledged.
func (c *Client) ReportStatus(ctx context.Context, st domain.NodeStatus) (uint32, error) {
	stream, err := c.rpc.ReportStatus(ctx)
	if err != nil {
		return 0, fmt.Errorf("open status stream: %w", err)
	}
	if err := stream.Send(api.StatusToProto(st)); err != nil {
		return 0, fmt.Errorf("send status: %w", err)
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return 0, fmt.Errorf("close status stream: %w", err)
	}
	return ack.GetReceived(), nil
}

// RenewCertificate asks the controller to sign a certificate request and returns
// the new certificate and the CA, both PEM.
//
// The request travels over the CURRENT mTLS connection, which is what authorises
// it: the controller issues for the identity that connection already proved and for
// no other. Nothing about the node's private key is sent — only the public half,
// inside the CSR.
func (c *Client) RenewCertificate(ctx context.Context, csrDER []byte) (certPEM, caPEM []byte, err error) {
	resp, err := c.rpc.RenewCertificate(ctx, &pb.RenewCertificateRequest{CsrDer: csrDER})
	if err != nil {
		return nil, nil, fmt.Errorf("renew certificate: %w", err)
	}
	if len(resp.GetCertPem()) == 0 {
		return nil, nil, fmt.Errorf("renew certificate: controller returned no certificate")
	}
	return resp.GetCertPem(), resp.GetCaCertPem(), nil
}
