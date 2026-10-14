package config

import "testing"

func TestBlockyMetricsPort(t *testing.T) {
	off := false
	f := FleetSection{
		Masters: []MasterConfig{
			{Name: "m-filter", DNSFilter: true},
			{Name: "m-nofilter"},
		},
		Exits: []ExitConfig{
			{Name: "e-default", DNSFilter: true},
			{Name: "e-port", DNSFilter: true, DNS: DNSConfig{Ports: DNSPortsConfig{HTTP: 4100}}},
			{Name: "e-noprom", DNSFilter: true, DNS: DNSConfig{Prometheus: &off}},
			{Name: "e-nofilter"},
		},
	}
	for name, want := range map[string]int{
		"m-filter": 4000, "m-nofilter": 0,
		"e-default": 4000, "e-port": 4100, "e-noprom": 0, "e-nofilter": 0,
		"unknown": 0,
	} {
		if got := f.BlockyMetricsPort(name); got != want {
			t.Errorf("BlockyMetricsPort(%q) = %d, want %d", name, got, want)
		}
	}

	// fleet.master_dns wins over a master's own dns block, as in the renderer.
	f.MasterDNS = DNSConfig{Ports: DNSPortsConfig{HTTP: 4200}}
	f.Masters[0].DNS = DNSConfig{Ports: DNSPortsConfig{HTTP: 4300}}
	if got := f.BlockyMetricsPort("m-filter"); got != 4200 {
		t.Errorf("master with fleet.master_dns: got %d, want 4200", got)
	}
}
