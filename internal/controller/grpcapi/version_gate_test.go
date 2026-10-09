package grpcapi_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/shidoh/wgfleet/internal/api"
	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

// fakeTrigger records auto-upgrade requests.
type fakeTrigger struct {
	mu      sync.Mutex
	upgrade []string
}

func (f *fakeTrigger) TriggerUpgrade(nodeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upgrade = append(f.upgrade, nodeID)
	return nil
}

func (f *fakeTrigger) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.upgrade...)
}

// rawClient dials the harness as nodeID but WITHOUT the agent client's version
// interceptor, so the test controls the wire-version metadata. The caller adds
// metadata to the per-RPC context.
func (h *harness) rawClient(t *testing.T, nodeID string) pb.NodeServiceClient {
	t.Helper()
	nodeKP, err := h.ca.IssueNodeCert(nodeID)
	if err != nil {
		t.Fatalf("node cert: %v", err)
	}
	clientTLS, err := h.ca.ClientTLSConfig(nodeKP, "127.0.0.1")
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewNodeServiceClient(conn)
}

func withWireVersion(ctx context.Context, wire string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, api.MDWireVersion, wire, api.MDAgentVersion, "test-agent")
}

func TestRegisterRejectsIncompatibleAgent(t *testing.T) {
	h := newHarness(t, integrationFleet())
	trigger := &fakeTrigger{}
	h.svc.SetUpgradeTrigger(trigger)

	// Seed the node so the gate can mark it Degraded.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.store.UpsertNode(ctx, domain.Node{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady,
	}); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	rc := h.rawClient(t, "exit-de-1")
	// wire "0" => WireUnknown => incompatible + auto-upgradable.
	_, err := rc.Register(withWireVersion(ctx, "0"), &pb.RegisterRequest{Role: "exit"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Register: got %v, want FailedPrecondition", err)
	}

	node, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if node.State != domain.StateDegraded {
		t.Errorf("node state = %q, want Degraded", node.State)
	}
	if got := trigger.calls(); len(got) != 1 || got[0] != "exit-de-1" {
		t.Errorf("auto-upgrade calls = %v, want [exit-de-1]", got)
	}
}

func TestPullSpecRejectsIncompatibleAgent(t *testing.T) {
	h := newHarness(t, integrationFleet())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rc := h.rawClient(t, "exit-de-1")

	// A too-new agent (controller behind): not auto-upgradable, still refused.
	overNew := api.WireContractVersion + 1
	_, err := rc.PullSpec(withWireVersion(ctx, itoa(overNew)), &pb.PullSpecRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("PullSpec: got %v, want FailedPrecondition", err)
	}
}

func TestRegisterAcceptsCurrentAgentAndRecordsVersion(t *testing.T) {
	h := newHarness(t, integrationFleet())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rc := h.rawClient(t, "exit-de-1")

	mdCtx := metadata.AppendToOutgoingContext(ctx,
		api.MDWireVersion, itoa(api.WireContractVersion), api.MDAgentVersion, "v9.9.9+abc")
	if _, err := rc.Register(mdCtx, &pb.RegisterRequest{Role: "exit"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	node, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if node.AgentVersion != "v9.9.9+abc" {
		t.Errorf("agent version = %q, want v9.9.9+abc", node.AgentVersion)
	}
	if node.WireVersion != api.WireContractVersion {
		t.Errorf("wire version = %d, want %d", node.WireVersion, api.WireContractVersion)
	}
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b []byte
	for u > 0 {
		b = append([]byte{byte('0' + u%10)}, b...)
		u /= 10
	}
	return string(b)
}

// A render that failed because the controller could not READ ITS OWN STATE is not
// the controller answering "no". Sent as NotFound it was an answer the agent
// obeyed: the node went to Error, applied nothing and dropped its self-checks
// for the pass. Sent as Unavailable the agent does what it does when the
// controller is down — reconciles on its last good spec.
//
// A node the manifest does not know stays NotFound: that IS an answer, and an
// agent falling back to its cache on it would rebuild a node the operator removed.
func TestPullSpecTellsAnUnreadableStoreFromARefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"state could not be read", fmt.Errorf("master %q: %w: disk I/O error", "m", store.ErrUnreadable), codes.Unavailable},
		{"node not in the manifest", errors.New(`keybroker: node "x" not found in fleet manifest`), codes.NotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, integrationFleet())
			h.svc.FailRendersForTest(tc.err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			rc := h.rawClient(t, "exit-de-1")
			_, err := rc.PullSpec(withWireVersion(ctx, itoa(api.WireContractVersion)), &pb.PullSpecRequest{})
			if status.Code(err) != tc.want {
				t.Fatalf("PullSpec: got %v, want %v", err, tc.want)
			}
		})
	}
}
