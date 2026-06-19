package provisioner

import (
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestRenderAgentYAMLIncludesMgmtAddr(t *testing.T) {
	in := BootstrapInput{
		Node: domain.Node{
			ID:       "exit-de-1",
			Role:     domain.RoleExit,
			MgmtAddr: "10.20.3.22",
		},
		ControllerEndpoint: "master-xa-1.mgmt:8443",
	}
	got := renderAgentYAML(in)
	if !strings.Contains(got, `mgmt_addr: "10.20.3.22"`) {
		t.Fatalf("agent.yaml missing mgmt_addr:\n%s", got)
	}
}

func TestRenderAgentYAMLOmitsMgmtAddrWhenEmpty(t *testing.T) {
	in := BootstrapInput{
		Node:               domain.Node{ID: "exit-de-1", Role: domain.RoleExit},
		ControllerEndpoint: "master-xa-1.mgmt:8443",
	}
	if got := renderAgentYAML(in); strings.Contains(got, "mgmt_addr:") {
		t.Fatalf("agent.yaml should omit mgmt_addr when unset:\n%s", got)
	}
}

func TestRenderAgentYAMLBakesReconcileInterval(t *testing.T) {
	base := BootstrapInput{
		Node:               domain.Node{ID: "exit-de-1", Role: domain.RoleExit},
		ControllerEndpoint: "master-xa-1.mgmt:8443",
	}
	// Set: the fleet value is baked verbatim.
	in := base
	in.ReconcileInterval = 30 * time.Second
	if got := renderAgentYAML(in); !strings.Contains(got, "reconcile_interval: 30s") {
		t.Fatalf("agent.yaml missing reconcile_interval: 30s:\n%s", got)
	}
	// Unset: the key is omitted so the agent uses its built-in default.
	if got := renderAgentYAML(base); strings.Contains(got, "reconcile_interval:") {
		t.Fatalf("agent.yaml should omit reconcile_interval when unset:\n%s", got)
	}
}

// The unit is generic: the metrics endpoint is derived by the agent from
// agent.yaml's mgmt_addr, so no per-node --metrics flag is baked in.
func TestRenderSystemdUnitCarriesNoPerNodeFlags(t *testing.T) {
	in := BootstrapInput{Node: domain.Node{ID: "exit-de-1", Role: domain.RoleExit, MgmtAddr: "10.20.3.22"}}
	got := renderSystemdUnit(in)
	if strings.Contains(got, "--metrics") {
		t.Fatalf("systemd unit should not bake --metrics:\n%s", got)
	}
	if !strings.Contains(got, "ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml --log-format json\n") {
		t.Fatalf("unexpected ExecStart line:\n%s", got)
	}
}
