package config

import (
	"strings"
	"testing"
)

func TestClientVLESSListenPortDerivation(t *testing.T) {
	m := MasterConfig{Name: "master-xa-1"}
	p1 := m.ClientVLESSListenPort()
	if p1 < clientVLESSPortLo || p1 > clientVLESSPortHi {
		t.Fatalf("derived port %d out of [%d,%d]", p1, clientVLESSPortLo, clientVLESSPortHi)
	}
	// Deterministic: same name → same port.
	if p2 := m.ClientVLESSListenPort(); p2 != p1 {
		t.Errorf("non-deterministic: %d != %d", p1, p2)
	}
	// Different names very likely differ (the derivation is name-seeded).
	other := MasterConfig{Name: "master-xa-2"}.ClientVLESSListenPort()
	if other == p1 {
		t.Errorf("two masters collided on port %d (seed not name-dependent?)", p1)
	}
	// An explicit port wins.
	pinned := MasterConfig{Name: "master-xa-1", ClientVLESS: ClientVLESSConfig{ListenPort: 51234}}
	if got := pinned.ClientVLESSListenPort(); got != 51234 {
		t.Errorf("explicit port = %d, want 51234", got)
	}
}

func TestClientVLESSResolvedEmptySNI(t *testing.T) {
	// Unset ⇒ default ON.
	if !(ClientVLESSConfig{}).ResolvedEmptySNI() {
		t.Error("unset empty_sni should default ON for the client leg")
	}
	off := false
	if (ClientVLESSConfig{EmptySNI: &off}).ResolvedEmptySNI() {
		t.Error("empty_sni: false must force it off")
	}
	on := true
	if !(ClientVLESSConfig{EmptySNI: &on}).ResolvedEmptySNI() {
		t.Error("empty_sni: true must be on")
	}
}

func TestClientVLESSDestHostPort(t *testing.T) {
	if got := (ClientVLESSConfig{}).DestHostPort(); got != "" {
		t.Errorf("no domain ⇒ empty, got %q", got)
	}
	if got := (ClientVLESSConfig{DestDomain: "www.python.org"}).DestHostPort(); got != "www.python.org:443" {
		t.Errorf("default port ⇒ :443, got %q", got)
	}
	if got := (ClientVLESSConfig{DestDomain: "example.com", DestPort: 8443}).DestHostPort(); got != "example.com:8443" {
		t.Errorf("explicit port, got %q", got)
	}
}

// hasClientVlessErr reports whether Validate flagged a client_vless-specific
// problem. The base config intentionally omits controller.store / pki, so
// Validate always returns SOME error; we inspect only for the client_vless part.
func hasClientVlessErr(c ControllerConfig) bool {
	err := c.Validate()
	return err != nil && strings.Contains(err.Error(), "client_vless")
}

func TestClientVLESSValidation(t *testing.T) {
	base := func(cv ClientVLESSConfig) ControllerConfig {
		return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{{
			Name:        "m1",
			MgmtAddr:    "10.20.0.1",
			ClientAWG:   ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"},
			ClientVLESS: cv,
		}}}}
	}
	// Disabled ⇒ no client_vless validation runs, even with a bad port.
	if hasClientVlessErr(base(ClientVLESSConfig{Enabled: false, ListenPort: 70000})) {
		t.Error("disabled client_vless must skip validation")
	}
	// Enabled with a bad port ⇒ client_vless error.
	if !hasClientVlessErr(base(ClientVLESSConfig{Enabled: true, ListenPort: 70000})) {
		t.Error("out-of-range client_vless.listen_port should fail")
	}
	// Enabled colliding with the client AWG port ⇒ client_vless error.
	if !hasClientVlessErr(base(ClientVLESSConfig{Enabled: true, ListenPort: 443})) {
		t.Error("client_vless port colliding with the client AWG port should fail")
	}
	// Enabled, valid, unset port ⇒ no client_vless error.
	if hasClientVlessErr(base(ClientVLESSConfig{Enabled: true})) {
		t.Error("valid enabled client_vless should not raise a client_vless error")
	}
}
