package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestExitTransportDefaults(t *testing.T) {
	var e ExitConfig // empty manifest exit
	ts := e.EnabledTransports()
	if len(ts) != 1 || ts[0] != domain.TransportAWG {
		t.Fatalf("default EnabledTransports = %v, want [awg]", ts)
	}
	if got := e.ResolvedActiveTransport(); got != domain.TransportAWG {
		t.Errorf("default active transport = %q, want awg", got)
	}

	e2 := ExitConfig{Transports: []string{"reality-xhttp", "awg"}}
	if got := e2.ResolvedActiveTransport(); got != domain.TransportRealityXHTTP {
		t.Errorf("active transport defaults to first enabled = %q, want reality-xhttp", got)
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

func TestValidateRejectsUnknownTransport(t *testing.T) {
	e := validExit()
	e.Transports = []string{"awg", "smoke-signal"}
	err := controllerWithExit(e).Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown transport") {
		t.Fatalf("expected unknown-transport error, got %v", err)
	}
}

func TestValidateRejectsActiveTransportNotEnabled(t *testing.T) {
	e := validExit()
	e.Transports = []string{"awg"}
	e.ActiveTransport = "reality-xhttp"
	err := controllerWithExit(e).Validate()
	if err == nil || !strings.Contains(err.Error(), "active_transport") {
		t.Fatalf("expected active-transport error, got %v", err)
	}
}

func TestValidateAcceptsDualTransport(t *testing.T) {
	e := validExit()
	e.Transports = []string{"awg", "reality-xhttp"}
	e.ActiveTransport = "awg"
	e.Reality.ListenPort = 8443
	if err := controllerWithExit(e).Validate(); err != nil {
		t.Fatalf("valid dual-transport exit rejected: %v", err)
	}
}

func TestValidateRealityCamouflage(t *testing.T) {
	// Per-exit bad SNI (has a port) → rejected.
	e := validExit()
	e.Transports = []string{"awg", "reality-xhttp"}
	e.Reality.ServerName = "www.microsoft.com:443"
	if err := controllerWithExit(e).Validate(); err == nil || !strings.Contains(err.Error(), "bare hostname") {
		t.Fatalf("expected bare-hostname error, got %v", err)
	}

	// Bad dest (no port) → rejected.
	e2 := validExit()
	e2.Reality.Dest = "www.microsoft.com"
	if err := controllerWithExit(e2).Validate(); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("expected host:port error, got %v", err)
	}

	// Valid camouflage → accepted.
	e3 := validExit()
	e3.Reality.ServerName = "www.microsoft.com"
	e3.Reality.Dest = "www.microsoft.com:443"
	if err := controllerWithExit(e3).Validate(); err != nil {
		t.Fatalf("valid camouflage rejected: %v", err)
	}

	// Fleet-wide default validated too.
	c := controllerWithExit(validExit())
	c.Fleet.RealityDefaultSNI = "bad sni/with space"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "bare hostname") {
		t.Fatalf("expected fleet default SNI rejected, got %v", err)
	}
}
