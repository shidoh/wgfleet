// Package grpcapi implements the controller-side NodeService gRPC server over
// mutual TLS. The authenticated node identity is taken from the client
// certificate CN, never from request fields, so a node cannot act as another.
package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/shidoh/wgfleet/internal/controller/pki"
)

// NodeIDFromContext extracts the authenticated node ID (client-certificate CN)
// from a gRPC request context. It fails closed: any missing TLS state, missing
// peer, or empty CN is an error, never an anonymous fallback.
func NodeIDFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("connection is not mutually authenticated TLS")
	}
	return pki.CommonNameFromCerts(tlsInfo.State.VerifiedChains)
}
