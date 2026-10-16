package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestExitTransportDefaults(t *testing.T) {
	var e ExitConfig // empty manifest exit — neither section enabled
	ts := e.EnabledTransports()
	if len(ts) != 1 || ts[0] != domain.TransportAWG {
		t.Fatalf("default EnabledTransports = %v, want [awg]", ts)
	}
	if got := e.ResolvedActiveTransport(); got != domain.TransportAWG {
		t.Errorf("default active transport = %q, want awg", got)
	}

	// Both sections enabled, no active_transport ⇒ first enabled (awg, canonical order).
	dual := ExitConfig{Transports: TransportsConfig{
		AWG:     AWGTransportConfig{Enabled: true},
		Reality: RealityTransportConfig{Enabled: true},
	}}
	if got := dual.EnabledTransports(); len(got) != 2 {
		t.Fatalf("dual EnabledTransports = %v, want both", got)
	}
	if got := dual.ResolvedActiveTransport(); got != domain.TransportAWG {
		t.Errorf("dual default active = %q, want awg", got)
	}

	// reality-only enabled ⇒ active defaults to reality.
	realityOnly := ExitConfig{Transports: TransportsConfig{Reality: RealityTransportConfig{Enabled: true}}}
	if got := realityOnly.ResolvedActiveTransport(); got != domain.TransportRealityXHTTP {
		t.Errorf("reality-only default active = %q, want reality-xhttp", got)
	}
}

func TestWGListenPortPrefersAWGSection(t *testing.T) {
	// AWG section port wins over the legacy top-level field.
	e := ExitConfig{Name: "exit-de-1", ListenPort: 25000, Transports: TransportsConfig{
		AWG: AWGTransportConfig{Enabled: true, ListenPort: 31000},
	}}
	if got := e.WGListenPort(); got != 31000 {
		t.Errorf("WGListenPort = %d, want 31000 (awg section)", got)
	}
	// Unset ⇒ stable-random derived (not the reality default 443).
	bare := ExitConfig{Name: "exit-de-1"}
	if got := bare.WGListenPort(); got < exitPortRangeLo || got > exitPortRangeHi {
		t.Errorf("derived WGListenPort = %d, want within [%d,%d]", got, exitPortRangeLo, exitPortRangeHi)
	}
}

func TestRealityDestHostPort(t *testing.T) {
	// domain + explicit port.
	r := RealityTransportConfig{DestDomain: "www.example.com", DestPort: 8443}
	if got := r.DestHostPort(); got != "www.example.com:8443" {
		t.Errorf("DestHostPort = %q, want www.example.com:8443", got)
	}
	// domain, default port 443.
	r2 := RealityTransportConfig{DestDomain: "www.example.com"}
	if got := r2.DestHostPort(); got != "www.example.com:443" {
		t.Errorf("DestHostPort = %q, want www.example.com:443", got)
	}
	// no domain ⇒ empty (keybroker falls back).
	if got := (RealityTransportConfig{}).DestHostPort(); got != "" {
		t.Errorf("DestHostPort = %q, want empty", got)
	}
}

// controllerWithExit builds a config that passes the unrelated checks so a test can
// isolate exit-transport validation.
func controllerWithExit(e ExitConfig) ControllerConfig {
	c := baseValidController()
	c.Controller.WebUI = "127.0.0.1:9000"
	c.Controller.Metrics = "127.0.0.1:9300"
	c.Fleet.Exits = []ExitConfig{e}
	return c
}

func validExit() ExitConfig {
	return ExitConfig{
		Name: "exit-de-1", Egress: "warp", AddressPool: "10.81.0.0/24", MgmtAddr: "10.20.3.20",
	}
}

func dualTransport() TransportsConfig {
	return TransportsConfig{
		AWG:     AWGTransportConfig{Enabled: true},
		Reality: RealityTransportConfig{Enabled: true},
	}
}

func TestValidateRejectsActiveTransportNotEnabled(t *testing.T) {
	e := validExit()
	e.Transports = TransportsConfig{AWG: AWGTransportConfig{Enabled: true}}
	e.ActiveTransport = "reality-xhttp"
	err := controllerWithExit(e).Validate()
	if err == nil || !strings.Contains(err.Error(), "active_transport") {
		t.Fatalf("expected active-transport error, got %v", err)
	}
}

func TestValidateAcceptsDualTransport(t *testing.T) {
	e := validExit()
	e.Transports = dualTransport()
	e.Transports.Reality.ListenPort = 443
	e.ActiveTransport = "awg"
	if err := controllerWithExit(e).Validate(); err != nil {
		t.Fatalf("valid dual-transport exit rejected: %v", err)
	}
}

func TestValidateRejectsRealityAWGPortCollision(t *testing.T) {
	e := validExit()
	e.Transports = dualTransport()
	e.Transports.AWG.ListenPort = 51820
	e.Transports.Reality.ListenPort = 51820 // collides
	err := controllerWithExit(e).Validate()
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected port-collision error, got %v", err)
	}
}

func TestValidateRejectsRealityPortOutOfRange(t *testing.T) {
	e := validExit()
	e.Transports = dualTransport()
	e.Transports.Reality.DestPort = 70000
	err := controllerWithExit(e).Validate()
	if err == nil || !strings.Contains(err.Error(), "dest_port") {
		t.Fatalf("expected dest_port range error, got %v", err)
	}
}

func TestValidateRealityCamouflage(t *testing.T) {
	// Per-exit bad SNI (has a port) → rejected.
	e := validExit()
	e.Transports = dualTransport()
	e.Transports.Reality.SNI = "www.microsoft.com:443"
	if err := controllerWithExit(e).Validate(); err == nil || !strings.Contains(err.Error(), "bare hostname") {
		t.Fatalf("expected bare-hostname error, got %v", err)
	}

	// Valid camouflage (split domain/port + bare SNI) → accepted.
	e2 := validExit()
	e2.Transports = dualTransport()
	e2.Transports.Reality.SNI = "www.microsoft.com"
	e2.Transports.Reality.DestDomain = "www.microsoft.com"
	e2.Transports.Reality.DestPort = 443
	if err := controllerWithExit(e2).Validate(); err != nil {
		t.Fatalf("valid camouflage rejected: %v", err)
	}

	// Fleet-wide default validated too.
	c := controllerWithExit(validExit())
	c.Fleet.RealityDefaultSNI = "bad sni/with space"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "bare hostname") {
		t.Fatalf("expected fleet default SNI rejected, got %v", err)
	}
}

// mihomo refuses a REALITY dial without a uTLS fingerprint ("REALITY is based on
// uTLS, please set a client-fingerprint"), so "none" is a dead tunnel, and "random"
// may pick a profile without X25519MLKEM768, which REALITY ≥ 26.9.8 forwards to
// the camouflage dest. Both are config errors, caught at load.
func TestValidateRejectsUnusableRealityFingerprint(t *testing.T) {
	for _, fp := range []string{"none", "random", "randomized"} {
		e := validExit()
		e.Transports = dualTransport()
		e.Transports.Reality.Fingerprint = fp
		if err := controllerWithExit(e).Validate(); err == nil || !strings.Contains(err.Error(), "fingerprint") {
			t.Errorf("exit reality fingerprint %q: expected fingerprint error, got %v", fp, err)
		}
	}
	for _, fp := range []string{"", "chrome", "firefox"} {
		e := validExit()
		e.Transports = dualTransport()
		e.Transports.Reality.Fingerprint = fp
		if err := controllerWithExit(e).Validate(); err != nil && strings.Contains(err.Error(), "fingerprint") {
			t.Errorf("exit reality fingerprint %q rejected: %v", fp, err)
		}
	}
}
