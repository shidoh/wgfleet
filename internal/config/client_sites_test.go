package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func sitesFleet(sites ...ClientSiteConfig) FleetSection {
	return FleetSection{
		MgmtSubnet: "172.29.0.0/16",
		Masters: []MasterConfig{{Name: "m1", ClientAWG: ClientAWGConfig{AddressPool: "10.73.0.0/24",
			RouteThroughCIDRs: []string{"10.50.0.0/16"}}}},
		ClientSites: sites,
	}
}

var goodHome = ClientSiteConfig{Name: "home", CIDRs: []string{"172.18.0.0/21", "172.26.1.0/24"},
	ProbeURL: "http://172.26.1.100/", ProbeInterval: 60}

func TestClientSitesValid(t *testing.T) {
	office := ClientSiteConfig{Name: "office", CIDRs: []string{"192.168.50.0/24"}}
	if errs := validateClientSites(sitesFleet(goodHome, office)); len(errs) != 0 {
		t.Errorf("valid sites rejected: %v", errs)
	}
}

func TestClientSitesInvalid(t *testing.T) {
	with := func(f func(*ClientSiteConfig)) ClientSiteConfig {
		s := goodHome
		s.CIDRs = append([]string(nil), goodHome.CIDRs...)
		f(&s)
		return s
	}
	cases := []struct {
		name  string
		sites []ClientSiteConfig
		want  string
	}{
		{"no name", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.Name = "" })}, "name is required"},
		{"syntax in name", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.Name = "a,b" })}, "','"},
		{"reserved name", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.Name = "wgfleet" })}, "collides"},
		{"master name", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.Name = "m1" })}, "collides"},
		{"duplicate", []ClientSiteConfig{goodHome, goodHome}, "collides"},
		{"no cidrs", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.CIDRs = nil })}, "at least one"},
		{"bad cidr", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.CIDRs = []string{"172.16.0.0/33"} })}, "not a valid CIDR"},
		{"mgmt overlap", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.CIDRs = []string{"172.29.3.0/24"} })}, "fleet.mgmt_subnet"},
		{"pool overlap", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.CIDRs = []string{"10.0.0.0/8"} })}, "address_pool"},
		{"probe not http", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.ProbeURL = "https://172.26.1.100/" })}, "http://"},
		{"probe by name", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.ProbeURL = "http://tw.example/" })}, "IPv4 address"},
		{"probe outside", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.ProbeURL = "http://192.168.1.1/" })}, "outside"},
		{"interval low", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.ProbeInterval = 5 })}, "probe_interval"},
		{"route_through overlap", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.CIDRs = []string{"10.50.3.0/24"}; s.ProbeURL = ""; s.ProbeInterval = 0 })}, "route_through_cidrs"},
		{"two sites overlap", []ClientSiteConfig{goodHome, {Name: "lab", CIDRs: []string{"172.26.1.128/25"}}}, "of site \"home\""},
		{"ipv6 cidr", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.CIDRs = []string{"fd00:1::/64"}; s.ProbeURL = ""; s.ProbeInterval = 0 })}, "not IPv4"},
		{"ipv6 probe", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.ProbeURL = "http://[fd00::1]/" })}, "IPv4 address"},
		{"interval without probe", []ClientSiteConfig{with(func(s *ClientSiteConfig) { s.ProbeURL = "" })}, "probe_interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateClientSites(sitesFleet(tc.sites...))
			joined := ""
			for _, e := range errs {
				joined += e.Error() + "\n"
			}
			if !strings.Contains(joined, tc.want) {
				t.Errorf("want an error containing %q, got %q", tc.want, joined)
			}
		})
	}
}

func TestClientSitesSpec(t *testing.T) {
	got := sitesFleet(goodHome).ClientSitesSpec()
	want := domain.ClientSite{Name: "home", CIDRs: []string{"172.18.0.0/21", "172.26.1.0/24"},
		ProbeURL: "http://172.26.1.100/", ProbeInterval: 60}
	if len(got) != 1 || got[0].Name != want.Name || got[0].ProbeURL != want.ProbeURL ||
		got[0].ProbeInterval != want.ProbeInterval || strings.Join(got[0].CIDRs, ",") != strings.Join(want.CIDRs, ",") {
		t.Errorf("ClientSitesSpec = %+v, want %+v", got, want)
	}
}

func TestValidateRunsClientSites(t *testing.T) {
	cfg := ControllerConfig{}
	cfg.Fleet = sitesFleet(ClientSiteConfig{Name: "", CIDRs: []string{"192.168.1.0/24"}})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "fleet.client_sites") {
		t.Errorf("Validate did not report client_sites: %v", err)
	}
}

// A master named like a site's derived group would share one group name with it.
func TestClientSitesAutoGroupCollidesWithMaster(t *testing.T) {
	f := sitesFleet(goodHome)
	f.Masters = append(f.Masters, MasterConfig{Name: "home-auto"})
	joined := ""
	for _, e := range validateClientSites(f) {
		joined += e.Error()
	}
	if !strings.Contains(joined, "home-auto") {
		t.Errorf("master home-auto beside site home accepted: %q", joined)
	}
}

func TestClientSitesSpecRendersCanonicalCIDRs(t *testing.T) {
	got := sitesFleet(ClientSiteConfig{Name: "lab", CIDRs: []string{" 192.168.7.9/24 "}}).ClientSitesSpec()
	if len(got) != 1 || len(got[0].CIDRs) != 1 || got[0].CIDRs[0] != "192.168.7.0/24" {
		t.Errorf("CIDRs = %v, want the masked, trimmed prefix", got)
	}
}
