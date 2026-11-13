package config

import (
	"strings"
	"testing"
)

// newCamouflageFleet is one master and one listening REALITY exit, both with a
// public address and an own domain — the shape camouflage validation accepts.
func newCamouflageFleet() FleetSection {
	return FleetSection{
		Masters: []MasterConfig{{
			Name: "master-1", PublicIP: "192.0.2.10",
			ClientVLESS: ClientVLESSConfig{Enabled: true},
			Camouflage:  CamouflageConfig{Domain: "m1.example.net"},
		}},
		Exits: []ExitConfig{{
			Name: "exit-de-1", PublicIP: "198.51.100.20",
			Transports: TransportsConfig{Reality: RealityTransportConfig{Enabled: true}},
			Camouflage: CamouflageConfig{Domain: "e1.example.net"},
		}},
	}
}

func TestValidateCamouflageAccepts(t *testing.T) {
	cases := map[string]func(f *FleetSection){
		"as built": func(*FleetSection) {},
		"off everywhere": func(f *FleetSection) {
			f.Masters[0].Camouflage = CamouflageConfig{}
			f.Exits[0].Camouflage = CamouflageConfig{}
		},
		"address from ssh.host": func(f *FleetSection) {
			f.Exits[0].PublicIP = ""
			f.Exits[0].SSH.Host = "198.51.100.20"
		},
		"public https on an exit that dials out": func(f *FleetSection) {
			f.Exits[0].Transports.Reality.ExitInitiated = true
			f.Exits[0].Camouflage.PublicHTTPS = true
		},
		"public https beside an inbound on another port": func(f *FleetSection) {
			f.Exits[0].Transports.Reality.ListenPort = 8443
			f.Exits[0].Camouflage.PublicHTTPS = true
		},
		"fleet email and internal ca": func(f *FleetSection) {
			f.Camouflage = CamouflageFleet{ACMEEmail: "ops@example.net", ACMECA: CamouflageCAInternal}
		},
		"fleet ca url": func(f *FleetSection) {
			f.Camouflage.ACMECA = "https://acme-staging-v02.api.letsencrypt.org/directory"
		},
		"explicit sni without camouflage": func(f *FleetSection) {
			f.Exits[0].Camouflage = CamouflageConfig{}
			f.Exits[0].Transports.Reality.SNI = "www.example.org"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fleet := newCamouflageFleet()
			mutate(&fleet)
			if errs := (ControllerConfig{Fleet: fleet}).validateCamouflage(); len(errs) != 0 {
				t.Fatalf("validateCamouflage() = %v, want no errors", errs)
			}
		})
	}
}

func TestValidateCamouflageRejects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(f *FleetSection)
		wantFrag string
	}{
		{"bare label", func(f *FleetSection) { f.Exits[0].Camouflage.Domain = "localhost" }, "not a fully qualified name"},
		{"scheme", func(f *FleetSection) { f.Exits[0].Camouflage.Domain = "https://e1.example.net" }, "not a valid DNS name"},
		{"port", func(f *FleetSection) { f.Exits[0].Camouflage.Domain = "e1.example.net:443" }, "not a valid DNS name"},
		{"wildcard", func(f *FleetSection) { f.Exits[0].Camouflage.Domain = "*.example.net" }, "not a valid DNS name"},
		{"ip", func(f *FleetSection) { f.Exits[0].Camouflage.Domain = "198.51.100.20" }, "IP address"},
		{"duplicate", func(f *FleetSection) { f.Exits[0].Camouflage.Domain = "M1.example.net" }, "already used by fleet.masters[0]"},
		{"no address", func(f *FleetSection) {
			f.Exits[0].PublicIP = ""
			f.Exits[0].SSH.Host = "exit.example.net"
		}, "needs a public address"},
		{"overlay address in ssh.host", func(f *FleetSection) {
			f.Exits[0].PublicIP = ""
			f.Exits[0].SSH.Host = "10.147.20.5"
		}, "needs a public address"},
		{"exit sni beside camouflage", func(f *FleetSection) { f.Exits[0].Transports.Reality.DestDomain = "www.example.org" },
			"replaces transports.reality.sni/dest_domain"},
		{"client vless sni beside camouflage", func(f *FleetSection) { f.Masters[0].ClientVLESS.SNI = "www.example.org" },
			"replaces client_vless.sni/dest_domain"},
		{"portal sni beside camouflage", func(f *FleetSection) { f.Masters[0].RealityPortal.SNI = "www.example.org" },
			"replaces reality_portal.sni/dest_domain"},
		{"public https over the exit inbound", func(f *FleetSection) { f.Exits[0].Camouflage.PublicHTTPS = true },
			"TCP/443 is held by a REALITY inbound"},
		{"public https over the client inbound", func(f *FleetSection) {
			f.Masters[0].ClientVLESS.ListenPort = 443
			f.Masters[0].Camouflage.PublicHTTPS = true
		}, "TCP/443 is held by a REALITY inbound"},
		{"public https without a domain", func(f *FleetSection) {
			f.Exits[0].Camouflage = CamouflageConfig{PublicHTTPS: true}
		}, "needs camouflage.domain"},
		{"bad email", func(f *FleetSection) { f.Camouflage.ACMEEmail = "not an address" }, "acme_email"},
		{"plain http ca", func(f *FleetSection) { f.Camouflage.ACMECA = "http://ca.example.net/dir" }, "acme_ca"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fleet := newCamouflageFleet()
			tt.mutate(&fleet)
			errs := (ControllerConfig{Fleet: fleet}).validateCamouflage()
			for _, err := range errs {
				if strings.Contains(err.Error(), tt.wantFrag) {
					return
				}
			}
			t.Fatalf("validateCamouflage() = %v, want an error containing %q", errs, tt.wantFrag)
		})
	}
}
