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

func TestRenderFail2banJail(t *testing.T) {
	in := BootstrapInput{MgmtIgnoreCIDRs: []string{"10.20.3.10/32", "10.20.3.20/32"}}
	got := renderFail2banJail(in)
	for _, want := range []string{
		"backend = systemd",
		"banaction = nftables[type=multiport]",
		"[sshd]",
		"enabled = true",
		"ignoreip = 127.0.0.1/8 ::1 10.20.3.10/32 10.20.3.20/32",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fail2ban jail missing %q:\n%s", want, got)
		}
	}
}

func TestRenderFail2banJailLoopbackOnlyWithoutMgmtCIDRs(t *testing.T) {
	if got := renderFail2banJail(BootstrapInput{}); !strings.Contains(got, "ignoreip = 127.0.0.1/8 ::1\n") {
		t.Fatalf("ignoreip should be loopback-only when no mgmt CIDRs:\n%s", got)
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
