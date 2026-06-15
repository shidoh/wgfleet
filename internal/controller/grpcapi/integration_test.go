package grpcapi_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/shidoh/wgfleet/internal/agent/client"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/grpcapi"
	"github.com/shidoh/wgfleet/internal/controller/keybroker"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// harness wires a real mTLS gRPC server over a loopback listener plus a matching
// agent client, so tests exercise the full transport: TLS, identity from cert
// CN, conversion, store and key broker.
type harness struct {
	ca       *pki.CA
	store    store.Store
	svc      *grpcapi.Service
	server   *grpc.Server
	addr     string
	discardL *slog.Logger
}

func newHarness(t *testing.T, fleet config.FleetSection) *harness {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca, err := pki.NewCA("wgfleet-test-ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	serverKP, err := ca.IssueServerCert("controller", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	serverTLS, err := ca.ServerTLSConfig(serverKP)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	broker := keybroker.New(st, fleet, log)
	svc := grpcapi.NewService(st, broker, log)
	srv := grpcapi.NewServer(serverTLS, svc)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.GracefulStop)

	return &harness{ca: ca, store: st, svc: svc, server: srv, addr: ln.Addr().String(), discardL: log}
}

// agentFor issues a node cert (CN=nodeID) and dials the server as that node.
func (h *harness) agentFor(t *testing.T, nodeID string) *client.Client {
	t.Helper()
	nodeKP, err := h.ca.IssueNodeCert(nodeID)
	if err != nil {
		t.Fatalf("node cert: %v", err)
	}
	clientTLS, err := h.ca.ClientTLSConfig(nodeKP, "127.0.0.1")
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	c, err := client.Dial(h.addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func integrationFleet() config.FleetSection {
	return config.FleetSection{
		Masters: []config.MasterConfig{{
			Name:      "master-xa-1",
			MgmtAddr:  "10.20.25.254",
			ClientAWG: config.ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"},
			Routing:   config.MasterRouting{DirectCIDRs: []string{"10.0.0.0/8"}, Balance: "health"},
		}},
		Exits: []config.ExitConfig{{
			Name:        "exit-de-1",
			Region:      "de",
			Egress:      "warp",
			AddressPool: "10.81.0.0/24",
			DNSFilter:   true,
			Firewall:    config.FirewallConfig{ASBlacklist: true},
		}},
	}
}

func TestEndToEndExitOnboarding(t *testing.T) {
	h := newHarness(t, integrationFleet())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Master comes up first and publishes its pubkey so exits can peer it.
	master := h.agentFor(t, "master-xa-1")
	if _, err := master.Register(ctx, domain.RoleMaster, "203.0.113.1", "ru", "10.20.25.254"); err != nil {
		t.Fatalf("master register: %v", err)
	}
	if err := master.PublishPublicKey(ctx, "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc="); err != nil {
		t.Fatalf("master publish: %v", err)
	}

	// 2. Exit registers, publishes its pubkey, pulls its spec.
	exit := h.agentFor(t, "exit-de-1")
	state, err := exit.Register(ctx, domain.RoleExit, "198.51.100.7", "de", "10.20.0.5")
	if err != nil {
		t.Fatalf("exit register: %v", err)
	}
	if state != domain.StateReconciling {
		t.Errorf("exit state after register = %q, want Reconciling", state)
	}
	if err := exit.PublishPublicKey(ctx, "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY="); err != nil {
		t.Fatalf("exit publish: %v", err)
	}

	spec, err := exit.PullSpec(ctx)
	if err != nil {
		t.Fatalf("exit pull spec: %v", err)
	}
	if spec.Role != domain.RoleExit || spec.Egress != domain.EgressWARP {
		t.Fatalf("exit spec role/egress = %v/%v", spec.Role, spec.Egress)
	}
	if len(spec.Peers) != 1 || spec.Peers[0].Name != "master-xa-1" || spec.Peers[0].PublicKey != "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=" {
		t.Fatalf("exit spec peers = %+v", spec.Peers)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("pulled spec invalid: %v", err)
	}

	// 3. Master now pulls its spec and sees the exit as a mihomo tunnel.
	mspec, err := master.PullSpec(ctx)
	if err != nil {
		t.Fatalf("master pull spec: %v", err)
	}
	if mspec.Master == nil || len(mspec.Master.ExitTunnels) != 1 {
		t.Fatalf("master spec mihomo tunnels = %+v", mspec.Master)
	}
	et := mspec.Master.ExitTunnels[0]
	if et.Endpoint != "198.51.100.7:51820" || et.ServerPublicKey != "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=" {
		t.Fatalf("master exit tunnel wrong: %+v", et)
	}
	if et.AWG == nil {
		t.Fatal("master exit tunnel must carry AWG params (crosses the wire)")
	}

	// 4. Exit reports Ready; controller persists status and reflects state.
	received, err := exit.ReportStatus(ctx, domain.NodeStatus{
		State:    domain.StateReady,
		EgressIP: "104.16.0.1",
		Checks:   []domain.HealthCheck{{Name: "warp-egress", OK: true}},
	})
	if err != nil {
		t.Fatalf("report status: %v", err)
	}
	if received != 1 {
		t.Errorf("controller acked %d reports, want 1", received)
	}

	node, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if node.State != domain.StateReady {
		t.Errorf("persisted node state = %q, want Ready", node.State)
	}
	gotStatus, err := h.store.GetStatus(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotStatus.EgressIP != "104.16.0.1" {
		t.Errorf("persisted egress IP = %q", gotStatus.EgressIP)
	}
}

func TestIdentityIsFromCertNotRequest(t *testing.T) {
	h := newHarness(t, integrationFleet())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The agent's cert CN is "exit-de-1"; even though it could put anything in
	// the request, the controller keys everything off the verified CN.
	exit := h.agentFor(t, "exit-de-1")
	if _, err := exit.Register(ctx, domain.RoleExit, "198.51.100.7", "de", "10.20.0.5"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := exit.PublishPublicKey(ctx, "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY="); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// The pubkey must land on exit-de-1, proving identity came from the cert.
	node, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if node.PublicKey != "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=" {
		t.Errorf("pubkey landed on wrong node or missing: %q", node.PublicKey)
	}
}
