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
	if bind != "" {
		// A bound portal must publish the URL clients type; the cases below are about
		// the bind itself, so give them a valid one.
		c.Controller.ClientPortalURL = "http://10.80.0.1:8080"
	}
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

// The bind and the published URL are one decision: a portal nobody has a link
// for is the state that made the whole self-service surface unreachable in the
// first place.
func TestClientPortalRequiresItsPublishedURL(t *testing.T) {
	c := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
		{Name: "m1", MgmtAddr: "10.20.0.1", ClientAWG: ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"}},
	}}}
	c.Controller.ClientPortal = "10.80.0.1:8080"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "client_portal_url is unset") {
		t.Fatalf("a bound portal with no published URL was accepted: %v", err)
	}

	c.Controller.ClientPortal = ""
	c.Controller.ClientPortalURL = "http://10.80.0.1:8080"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "nothing is listening") {
		t.Fatalf("a URL with no portal behind it was accepted: %v", err)
	}
}

// Plaintext is fine inside the tunnel or to a local proxy, and not fine to a
// routable host — the portal hands out private keys.
func TestClientPortalRejectsPlainHTTPToARoutableHost(t *testing.T) {
	base := func(u string) ControllerConfig {
		c := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
			{Name: "m1", MgmtAddr: "10.20.0.1", ClientAWG: ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"}},
		}}}
		c.Controller.ClientPortal = "127.0.0.1:8080"
		c.Controller.ClientPortalURL = u
		return c
	}
	for u, wantErr := range map[string]bool{
		"http://10.80.0.1:8080":    false, // inside the client tunnel
		"http://127.0.0.1:8080":    false, // a local reverse proxy terminates TLS
		"https://vpn.example.org":  false,
		"http://vpn.example.org":   true, // a name we cannot resolve is trusted… but this one is routable by scheme+host rule
		"http://203.0.113.10:8080": true,
		"ftp://10.80.0.1":          true,
		"not a url at all":         true,
	} {
		err := base(u).Validate()
		got := err != nil && strings.Contains(err.Error(), "client_portal_url")
		if got != wantErr {
			t.Errorf("client_portal_url %q: flagged = %v, want %v (err = %v)", u, got, wantErr, err)
		}
	}
}
