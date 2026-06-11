// Package client is the agent's mTLS gRPC client to the controller's
// NodeService. It hides the wire types: callers work in domain terms.
package client

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/shidoh/wgfleet/internal/api"
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Client is a controller connection for one agent.
type Client struct {
	conn *grpc.ClientConn
	rpc  pb.NodeServiceClient
}

// Dial connects to the controller at addr using the given mTLS config. It does
// not block on connectivity; the first RPC establishes the connection.
func Dial(addr string, tlsCfg *tls.Config) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("dial controller %q: %w", addr, err)
	}
	return &Client{conn: conn, rpc: pb.NewNodeServiceClient(conn)}, nil
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
	resp, err := c.rpc.PublishPublicKey(ctx, &pb.PublishPublicKeyRequest{PublicKey: publicKey})
	if err != nil {
		return fmt.Errorf("publish public key: %w", err)
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("controller rejected public key")
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
