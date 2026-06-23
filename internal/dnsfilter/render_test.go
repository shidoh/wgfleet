package dnsfilter

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestRenderBlockyBindsLoopbackAndMgmtOnly(t *testing.T) {
	out, err := RenderBlocky(domain.DNSFilterSpec{
		Enabled:    true,
		MgmtAddr:   "10.20.4.10",
		Prometheus: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("render is not valid YAML: %v\n%s", err, out)
	}

	ports, _ := cfg["ports"].(map[string]any)
	dns, _ := ports["dns"].([]any)
	if len(dns) != 2 {
		t.Fatalf("expected dns to bind exactly loopback + mgmt, got %v", dns)
	}
	if dns[0] != "127.0.0.1:53" || dns[1] != "10.20.4.10:53" {
		t.Errorf("dns binds wrong addresses: %v", dns)
	}
	// Defense in depth: the public interface must never appear as a bind.
	if strings.Contains(out, "0.0.0.0") {
		t.Errorf("resolver must not bind 0.0.0.0:\n%s", out)
	}

	// Prometheus exposed when requested.
	prom, _ := cfg["prometheus"].(map[string]any)
	if prom["enable"] != true {
		t.Errorf("expected prometheus enabled: %v", prom)
	}

	// Platform self-protection allowlist is always present.
	if !strings.Contains(out, "zerotier.com") || !strings.Contains(out, "*.amnezia.org") {
		t.Errorf("platform allowlist missing:\n%s", out)
	}

	// CRITICAL: the security allowlist must be an INLINE source — a single list
	// entry holding all domains newline-joined — NOT one bare-string entry per
	// domain. blocky reads each entry as a source reference; a bare domain becomes
	// `file://domain`, fails to open, and the group loads empty (control plane
	// unprotected). See the live `file://zerotier.com` open-failure that motivated
	// this. So: exactly ONE element, a string containing every domain.
	blocking, _ := cfg["blocking"].(map[string]any)
	allow, _ := blocking["allowlists"].(map[string]any)
	sec, _ := allow["security"].([]any)
	if len(sec) != 1 {
		t.Fatalf("security allowlist must be a single inline source, got %d entries: %v", len(sec), sec)
	}
	inline, ok := sec[0].(string)
	if !ok || !strings.Contains(inline, "\n") || !strings.Contains(inline, "zerotier.com") {
		t.Errorf("security allowlist must be a newline-joined inline block, got %q", sec[0])
	}
}

func TestRenderBlockyMasterClientBind(t *testing.T) {
	// Master-tier resolver (ADR-0024): binds loopback + mgmt + the client-pool
	// gateway, so VPN clients can use the master as their DNS through the tunnel.
	out, err := RenderBlocky(domain.DNSFilterSpec{
		Enabled:        true,
		MgmtAddr:       "10.20.3.10",
		ClientBindAddr: "10.73.0.1",
		Upstreams:      []string{"10.20.3.20", "10.20.3.21"}, // exit-blockys
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out)
	}
	ports, _ := cfg["ports"].(map[string]any)
	dns, _ := ports["dns"].([]any)
	want := []any{"127.0.0.1:53", "10.20.3.10:53", "10.73.0.1:53"}
	if len(dns) != len(want) {
		t.Fatalf("expected loopback+mgmt+gateway binds, got %v", dns)
	}
	for i := range want {
		if dns[i] != want[i] {
			t.Errorf("dns bind[%d] = %v, want %v (full: %v)", i, dns[i], want[i], dns)
		}
	}
	// Still never the public interface.
	if strings.Contains(out, "0.0.0.0") {
		t.Errorf("master resolver must not bind 0.0.0.0:\n%s", out)
	}
	// Upstreams = the exit-blockys (master forwards public queries to exits).
	if !strings.Contains(out, "10.20.3.20") || !strings.Contains(out, "10.20.3.21") {
		t.Errorf("master upstreams should be the exit-blockys:\n%s", out)
	}
}

func TestRenderBlockyClientBindOmittedOnExit(t *testing.T) {
	// Exit-tier (no ClientBindAddr): binds loopback + mgmt only, unchanged.
	out, err := RenderBlocky(domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.3.20"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(out), &cfg)
	ports, _ := cfg["ports"].(map[string]any)
	dns, _ := ports["dns"].([]any)
	if len(dns) != 2 {
		t.Fatalf("exit resolver should bind exactly loopback + mgmt, got %v", dns)
	}
}

func TestRenderBlockyDefaultsUpstreamsAndBootstrap(t *testing.T) {
	out, err := RenderBlocky(domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.4.10"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp-tls:dns.quad9.net:853", "tcp-tls:dns.mullvad.net", "9.9.9.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected default %q:\n%s", want, out)
		}
	}
}

func TestRenderBlockyTLSDisabledWhenNegative(t *testing.T) {
	out, err := RenderBlocky(domain.DNSFilterSpec{
		Enabled:  true,
		MgmtAddr: "10.20.4.10",
		Ports:    domain.DNSPorts{TLS: -1, HTTP: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(out), &cfg)
	ports, _ := cfg["ports"].(map[string]any)
	if _, ok := ports["tls"]; ok {
		t.Errorf("tls should be disabled when port < 0: %v", ports)
	}
	if _, ok := ports["http"]; ok {
		t.Errorf("http should be disabled when port < 0: %v", ports)
	}
}

func TestRenderBlockyOperatorOverridesDeepMerge(t *testing.T) {
	out, err := RenderBlocky(domain.DNSFilterSpec{
		Enabled:   true,
		MgmtAddr:  "10.20.4.10",
		Allowlist: []string{"*.example.com"},
		Custom: domain.CustomConfig{
			Overrides: map[string]any{
				"conditional": map[string]any{
					"mapping": map[string]any{"lab.lan": "10.20.2.1"},
				},
				"blocking": map[string]any{
					"denylists":         map[string]any{"ads": []any{"https://example.test/pro.txt"}},
					"clientGroupsBlock": map[string]any{"default": []any{"ads"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
	// Operator override added.
	cond, _ := cfg["conditional"].(map[string]any)
	mapping, _ := cond["mapping"].(map[string]any)
	if mapping["lab.lan"] != "10.20.2.1" {
		t.Errorf("conditional override not applied: %v", cond)
	}
	// Deep-merge preserved the base allowlist while adding operator denylists.
	blocking, _ := cfg["blocking"].(map[string]any)
	if _, ok := blocking["allowlists"]; !ok {
		t.Errorf("base allowlists clobbered by override: %v", blocking)
	}
	denylists, _ := blocking["denylists"].(map[string]any)
	if denylists["ads"] == nil {
		t.Errorf("operator denylists not merged: %v", blocking)
	}
	// Operator allowlist domain present alongside the platform set.
	if !strings.Contains(out, "*.example.com") {
		t.Errorf("operator allowlist domain missing:\n%s", out)
	}
}

func TestRenderBlockyRequiresMgmtAddr(t *testing.T) {
	if _, err := RenderBlocky(domain.DNSFilterSpec{Enabled: true}); err == nil {
		t.Fatal("expected error without mgmt address (must not bind public iface)")
	}
}

func TestRenderBlockyDisabled(t *testing.T) {
	if _, err := RenderBlocky(domain.DNSFilterSpec{Enabled: false}); err == nil {
		t.Fatal("expected error when filter disabled")
	}
}
