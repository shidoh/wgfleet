package web

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The console must show the address the fleet actually dials. Nothing discovers
// public_ip, so the store row is a copy from provisioning time: after the operator
// moves a node, the store still holds the old address while the tunnels have
// already moved to the manifest's new one. Showing the store value there told the
// operator the fleet was somewhere it no longer is.
func TestNodeListShowsManifestPublicIPOverStore(t *testing.T) {
	prov := &stubProv{manifest: []domain.Node{{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit,
		MgmtAddr: "10.20.0.5", PublicIP: "198.51.100.99",
	}}}
	h, st := newProvHandler(t, prov)
	if err := st.UpsertNode(context.Background(), domain.Node{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit,
		MgmtAddr: "10.20.0.5", PublicIP: "198.51.100.7", // stale copy
		State: domain.StateReady,
	}); err != nil {
		t.Fatal(err)
	}

	nodes, err := h.nodes(context.Background())
	if err != nil {
		t.Fatalf("nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(nodes))
	}
	if nodes[0].PublicIP != "198.51.100.99" {
		t.Errorf("PublicIP = %q, want the manifest's 198.51.100.99", nodes[0].PublicIP)
	}
}

// mgmt_addr keeps the old blank-only backfill: the agent reports it on every
// Register, so the store value is a live fact, not a copy.
func TestNodeListKeepsStoreMgmtAddr(t *testing.T) {
	prov := &stubProv{manifest: []domain.Node{{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, MgmtAddr: "10.20.0.9",
	}}}
	h, st := newProvHandler(t, prov)
	if err := st.UpsertNode(context.Background(), domain.Node{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit,
		MgmtAddr: "10.20.0.5", State: domain.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	nodes, err := h.nodes(context.Background())
	if err != nil {
		t.Fatalf("nodes: %v", err)
	}
	if nodes[0].MgmtAddr != "10.20.0.5" {
		t.Errorf("MgmtAddr = %q, want the agent-reported 10.20.0.5", nodes[0].MgmtAddr)
	}
}

// The address in a client profile / VLESS link comes from the spec the controller
// resolved (manifest first), not from the store's copy. Same rule as
// clientcfg.EndpointHost, which this mirrors for the web pages.
func TestEndpointHostPrefersSpec(t *testing.T) {
	node := domain.Node{PublicIP: "203.0.113.1"}
	spec := domain.NodeSpec{Master: &domain.MasterSpec{
		Compose: domain.ComposeSpec{PublicIP: "198.51.100.4"},
	}}

	if got := endpointHost(node, spec); got != "198.51.100.4" {
		t.Errorf("endpointHost() = %q, want the declared 198.51.100.4", got)
	}
	// A master that declares none falls back to what the store registered.
	spec.Master.Compose.PublicIP = ""
	if got := endpointHost(node, spec); got != "203.0.113.1" {
		t.Errorf("endpointHost() = %q, want the registered 203.0.113.1", got)
	}
	// A DNS name is a legitimate client-facing endpoint (docs/master-migration.md).
	spec.Master.Compose.PublicIP = "vpn.example.net"
	if got := endpointHost(node, spec); !strings.Contains(got, "example.net") {
		t.Errorf("endpointHost() = %q, want the DNS name passed through", got)
	}
	// Nothing anywhere: the pages must show their "no public endpoint" notice
	// rather than render a link to an empty host.
	if got := endpointHost(domain.Node{}, domain.NodeSpec{}); got != "" {
		t.Errorf("endpointHost() = %q, want empty", got)
	}
}
