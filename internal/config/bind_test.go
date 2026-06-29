package config

import (
	"strings"
	"testing"
)

// baseValidController returns a ControllerConfig that passes the non-bind checks,
// so a test can isolate the admin-surface bind validation.
func baseValidController() ControllerConfig {
	return ControllerConfig{
		Controller: ControllerSection{
			Listen: "0.0.0.0:8443", // mTLS gRPC — authenticated, not bind-checked
			Store:  "/var/lib/wgfleet/state.db",
			PKI:    PKISection{CACert: "/etc/wgfleet/ca.crt"},
		},
	}
}

func TestValidateRejectsPublicAdminBind(t *testing.T) {
	cases := map[string]string{
		"webui unspecified": "0.0.0.0:9000",
		"webui public ip":   "203.0.113.10:9000",
		"webui empty host":  ":9000",
	}
	for name, bind := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseValidController()
			cfg.Controller.WebUI = bind
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for webui %q", bind)
			}
			if !strings.Contains(err.Error(), "controller.webui") {
				t.Fatalf("error %q does not mention controller.webui", err)
			}
		})
	}
}

func TestValidateRejectsPublicMetricsBind(t *testing.T) {
	cfg := baseValidController()
	cfg.Controller.Metrics = "203.0.113.10:9300"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "controller.metrics") {
		t.Fatalf("expected metrics bind error, got %v", err)
	}
}

func TestValidateAcceptsMgmtAndLoopbackBinds(t *testing.T) {
	for _, bind := range []string{
		"127.0.0.1:9000",       // loopback
		"10.20.25.254:9000",    // RFC1918 (ZT overlay)
		"10.80.0.1:9000",       // RFC1918
		"192.168.1.10:9000",    // RFC1918
		"[::1]:9000",           // IPv6 loopback
		"controller.mgmt:9000", // hostname — trusted, not classifiable
		"",                     // disabled
	} {
		cfg := baseValidController()
		cfg.Controller.WebUI = bind
		cfg.Controller.Metrics = bind
		if err := cfg.Validate(); err != nil {
			t.Errorf("bind %q rejected unexpectedly: %v", bind, err)
		}
	}
}

func TestValidatePublicBindOverride(t *testing.T) {
	t.Setenv("WGFLEET_ALLOW_PUBLIC_BIND", "1")
	cfg := baseValidController()
	cfg.Controller.WebUI = "0.0.0.0:9000"
	cfg.Controller.Metrics = "203.0.113.10:9300"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("override should allow public binds, got %v", err)
	}
}
