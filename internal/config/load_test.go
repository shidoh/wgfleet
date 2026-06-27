package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	tests := []struct{ in, want string }{
		{"~/.ssh/id_ed25519", filepath.Join(home, ".ssh/id_ed25519")},
		{"~/.lima/_config/user", filepath.Join(home, ".lima/_config/user")},
		{"~", home},
		{"/etc/wgfleet/ca.crt", "/etc/wgfleet/ca.crt"}, // absolute unchanged
		{"./pki/ca.key", "./pki/ca.key"},               // relative unchanged
		{"", ""},                                       // empty unchanged
		{"~user/x", "~user/x"},                         // ~user form not expanded
	}
	for _, tt := range tests {
		if got := ExpandPath(tt.in); got != tt.want {
			t.Errorf("ExpandPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

const controllerYAML = `
controller:
  listen: "0.0.0.0:8443"
  store: "/var/lib/wgfleet/state.db"
  metrics: "127.0.0.1:9300"
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key: "secret://ca-key"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
      client_awg:
        listen_port: 443
        address_pool: 10.80.0.0/24
      routing:
        direct_cidrs: [10.0.0.0/8, 192.168.0.0/16]
        direct_geo: [RU]
        balance: health
  exits:
    - name: exit-de-1
      region: de
      egress: warp
      address_pool: 10.81.0.0/24
      dns_filter: true
      firewall:
        as_blacklist: true
        whitelist: [10.20.0.0/16]
`

func TestLoadControllerConfig(t *testing.T) {
	path := writeTemp(t, "controller.yaml", controllerYAML)
	cfg, err := Load(path, &ControllerConfig{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Controller.Listen != "0.0.0.0:8443" {
		t.Errorf("listen = %q", cfg.Controller.Listen)
	}
	if len(cfg.Fleet.Masters) != 1 || cfg.Fleet.Masters[0].Name != "master-xa-1" {
		t.Fatalf("masters = %+v", cfg.Fleet.Masters)
	}
	if cfg.Fleet.Masters[0].ClientAWG.ListenPort != 443 {
		t.Errorf("listen_port = %d", cfg.Fleet.Masters[0].ClientAWG.ListenPort)
	}
	if got := cfg.Fleet.Exits[0].Egress; got != "warp" {
		t.Errorf("egress = %q", got)
	}
	if cfg.Controller.PKI.CAKey != "secret://ca-key" {
		t.Errorf("ca_key = %q", cfg.Controller.PKI.CAKey)
	}
}

func TestWebUISessionTTLDefault(t *testing.T) {
	var c ControllerConfig
	if got := c.WebUISessionTTL(); got != 7*24*time.Hour {
		t.Errorf("default session TTL = %v; want 168h", got)
	}
	c.Controller.SessionTTL = 2 * time.Hour
	if got := c.WebUISessionTTL(); got != 2*time.Hour {
		t.Errorf("configured session TTL = %v; want 2h", got)
	}
}

const dualTransportYAML = `
controller:
  listen: "0.0.0.0:8443"
  store: "/var/lib/wgfleet/state.db"
  metrics: "127.0.0.1:9300"
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key: "secret://ca-key"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
      client_awg:
        listen_port: 443
        address_pool: 10.80.0.0/24
  exits:
    - name: exit-de-1
      region: de
      egress: warp
      address_pool: 10.81.0.0/24
      mgmt_addr: 10.20.3.20
      transports:
        awg:
          enabled: true
          listen_port: 0
        reality:
          enabled: true
          listen_port: 443
          dest_domain: www.microsoft.com
          dest_port: 443
          sni: www.microsoft.com
      active_transport: reality-xhttp
`

func TestLoadDualTransportSections(t *testing.T) {
	path := writeTemp(t, "controller.yaml", dualTransportYAML)
	cfg, err := Load(path, &ControllerConfig{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := cfg.Fleet.Exits[0]
	if !e.Transports.AWG.Enabled || !e.Transports.Reality.Enabled {
		t.Fatalf("both sections should be enabled: %+v", e.Transports)
	}
	if got := len(e.EnabledTransports()); got != 2 {
		t.Errorf("EnabledTransports = %v, want 2", e.EnabledTransports())
	}
	if got := e.ResolvedActiveTransport().String(); got != "reality-xhttp" {
		t.Errorf("active = %q, want reality-xhttp", got)
	}
	if got := e.Transports.Reality.ListenPort; got != 443 {
		t.Errorf("reality listen_port = %d, want 443", got)
	}
	if got := e.Transports.Reality.DestHostPort(); got != "www.microsoft.com:443" {
		t.Errorf("dest = %q, want www.microsoft.com:443", got)
	}
}

func TestEnvOverride(t *testing.T) {
	path := writeTemp(t, "controller.yaml", controllerYAML)
	t.Setenv("WGFLEET_CONTROLLER_LISTEN", "127.0.0.1:9443")
	cfg, err := Load(path, &ControllerConfig{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Controller.Listen != "127.0.0.1:9443" {
		t.Errorf("env override failed: listen = %q", cfg.Controller.Listen)
	}
}

const agentYAML = `
agent:
  role: exit
  controller: "master-xa-1.mgmt:8443"
  node_id: "exit-de-1"
  reconcile_interval: 90s
  identity:
    cert: "/etc/wgfleet/node.crt"
    key: "/etc/wgfleet/node.key"
    ca: "/etc/wgfleet/ca.crt"
`

func TestLoadAgentConfigDuration(t *testing.T) {
	path := writeTemp(t, "agent.yaml", agentYAML)
	cfg, err := Load(path, &AgentConfig{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Agent.ReconcileInterval != 90*time.Second {
		t.Errorf("reconcile_interval = %v, want 90s", cfg.Agent.ReconcileInterval)
	}
	if cfg.Interval() != 90*time.Second {
		t.Errorf("Interval() = %v", cfg.Interval())
	}
}

func TestAgentIntervalDefault(t *testing.T) {
	var cfg AgentConfig
	if cfg.Interval() != DefaultReconcileInterval {
		t.Errorf("default interval = %v, want %v", cfg.Interval(), DefaultReconcileInterval)
	}
}

func TestAgentValidatesOverlayMSS(t *testing.T) {
	base := AgentConfig{Agent: AgentSection{
		Role: "exit", Controller: "c:8443", NodeID: "n",
		Identity: IdentitySection{Cert: "/c", Key: "/k", CA: "/ca"},
	}}
	for _, ok := range []int{0, 536, 1240, 1460} {
		cfg := base
		cfg.Agent.MgmtOverlayMSS = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("mgmt_overlay_mss %d rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []int{1, 535, 1461, 9000} {
		cfg := base
		cfg.Agent.MgmtOverlayMSS = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mgmt_overlay_mss") {
			t.Errorf("mgmt_overlay_mss %d should be rejected, got %v", bad, err)
		}
	}
}

func TestValidationRejectsBadEgress(t *testing.T) {
	bad := controllerYAML + ""
	bad = replaceFirst(bad, "egress: warp", "egress: teleport")
	path := writeTemp(t, "bad.yaml", bad)
	if _, err := Load(path, &ControllerConfig{}); err == nil {
		t.Fatal("expected validation error for bad egress")
	}
}

func replaceFirst(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
