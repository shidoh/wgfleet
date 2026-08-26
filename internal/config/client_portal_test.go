package config

import (
	"strings"
	"testing"
)

// portalErr reports whether Validate flagged a client_portal problem. The base
// config omits controller.store / pki, so Validate always returns SOME error.
func portalErr(bind string) string {
	c := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
		{Name: "m1", MgmtAddr: "10.20.0.1", ClientAWG: ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"}},
	}}}
	c.Controller.ClientPortal = bind
	err := c.Validate()
	if err == nil {
		return ""
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.Contains(line, "client_portal") {
			return line
		}
	}
	return ""
}

// The portal hands out WireGuard private keys over plain HTTP. It is meant to be
// reachable from the CLIENT TUNNEL — 10.80.0.1, the master's own address inside
// the client pool — and from nowhere else. A public bind would put unauthenticated
// key downloads on the open internet, so it gets the same guard the admin
// surfaces have; the docs telling the operator to "bind where clients reach it"
// make that mistake the natural one to make.
func TestClientPortalRejectsAPublicBind(t *testing.T) {
	tests := map[string]bool{
		"":                   false, // disabled
		"10.80.0.1:8080":     false, // the client tunnel — the intended bind
		"127.0.0.1:8080":     false, // behind a local reverse proxy
		"[fd00::1]:8080":     false, // unique-local
		"0.0.0.0:8080":       true,  // every interface, including the public one
		"203.0.113.10:8080":  true,  // the master's public address
		"[2001:db8::1]:8080": true,
	}
	for bind, wantErr := range tests {
		t.Run(bind, func(t *testing.T) {
			got := portalErr(bind)
			if wantErr && got == "" {
				t.Fatalf("client_portal %q was accepted; want a refusal", bind)
			}
			if !wantErr && got != "" {
				t.Fatalf("client_portal %q was refused: %s", bind, got)
			}
		})
	}
}

// A malformed bind must fail at config time, not as a background goroutine error
// after the controller is already serving.
func TestClientPortalRejectsAMalformedBind(t *testing.T) {
	if got := portalErr("not a bind"); got == "" {
		t.Fatal("a malformed client_portal bind was accepted")
	}
}
