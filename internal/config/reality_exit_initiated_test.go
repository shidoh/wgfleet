package config

import (
	"strings"
	"testing"
)

// newRealityExitInitiatedFleet is one master with a public address and one
// REALITY exit that dials the master's portal — the shape the validator accepts.
func newRealityExitInitiatedFleet() FleetSection {
	return FleetSection{
		Masters: []MasterConfig{{Name: "m", PublicIP: "192.0.2.10"}},
		Exits: []ExitConfig{{
			Name: "e",
			Transports: TransportsConfig{
				AWG:     AWGTransportConfig{Enabled: true},
				Reality: RealityTransportConfig{Enabled: true, ExitInitiated: true},
			},
		}},
	}
}

func TestValidateRealityExitInitiatedAcceptsTheSupportedShape(t *testing.T) {
	cases := map[string]func(f *FleetSection){
		"dual transport":            func(*FleetSection) {},
		"reality only":              func(f *FleetSection) { f.Exits[0].Transports.AWG.Enabled = false },
		"fingerprint is the bridge": func(f *FleetSection) { f.Exits[0].Transports.Reality.Fingerprint = "firefox" },
		"camouflage is kept":        func(f *FleetSection) { f.Exits[0].Transports.Reality.SNI = "www.python.org" },
		"listen port kept for off":  func(f *FleetSection) { f.Exits[0].Transports.Reality.ListenPort = 8443 },
		"master address is a name":  func(f *FleetSection) { f.Masters[0].PublicIP = "master.example.net" },
		"fleet default mode is not the exit's": func(f *FleetSection) {
			f.RealityDefaultSNI = "www.python.org"
		},
		"portal pinned": func(f *FleetSection) {
			f.Masters[0].RealityPortal = RealityPortalConfig{ListenPort: 45000, SNI: "www.python.org", DestDomain: "www.python.org"}
		},
		"flag off ignores masters": func(f *FleetSection) {
			f.Exits[0].Transports.Reality.ExitInitiated = false
			f.Masters[0].PublicIP = "10.0.0.1"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fleet := newRealityExitInitiatedFleet()
			mutate(&fleet)
			if errs := (ControllerConfig{Fleet: fleet}).validateRealityExitInitiated(); len(errs) != 0 {
				t.Fatalf("validateRealityExitInitiated() = %v, want no errors", errs)
			}
		})
	}
}

func TestValidateRealityExitInitiatedRejects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(f *FleetSection)
		wantFrag string
	}{
		{
			name:     "reality disabled",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.Reality.Enabled = false },
			wantFrag: "transports.reality.exit_initiated needs the reality transport enabled",
		},
		{
			name:     "no master",
			mutate:   func(f *FleetSection) { f.Masters = nil },
			wantFrag: "transports.reality.exit_initiated needs a master",
		},
		{
			name:     "private master",
			mutate:   func(f *FleetSection) { f.Masters[0].PublicIP = "10.0.0.1" },
			wantFrag: "(transports.reality.exit_initiated)",
		},
		{
			name:     "cgnat master",
			mutate:   func(f *FleetSection) { f.Masters[0].PublicIP = "100.64.1.1" },
			wantFrag: "not a public IPv4",
		},
		{
			name:     "explicit mode",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.Reality.Mode = "vision" },
			wantFrag: "transports.reality.mode",
		},
		{
			name:     "explicit xhttp path",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.Reality.XHTTPPath = "/x" },
			wantFrag: "transports.reality.xhttp_path",
		},
		{
			name:     "mux",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.Reality.Mux = true },
			wantFrag: "transports.reality.mux",
		},
		{
			name:     "empty sni",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.Reality.EmptySNI = true },
			wantFrag: "transports.reality.empty_sni",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fleet := newRealityExitInitiatedFleet()
			tt.mutate(&fleet)
			errs := (ControllerConfig{Fleet: fleet}).validateRealityExitInitiated()
			if !anyErrContains(errs, tt.wantFrag) {
				t.Fatalf("validateRealityExitInitiated() = %v, want an error containing %q", errs, tt.wantFrag)
			}
		})
	}
}

// The AWG flag's message names the AWG key; a shared helper must not change it.
func TestAWGExitInitiatedMessageUnchanged(t *testing.T) {
	fleet := newExitInitiatedFleet()
	fleet.Masters[0].PublicIP = "10.0.0.1"
	errs := (ControllerConfig{Fleet: fleet}).validateExitInitiated()
	if !anyErrContains(errs, "public_ip 10.0.0.1 is not a public IPv4 address an exit can reach (transports.awg.exit_initiated)") {
		t.Fatalf("validateExitInitiated() = %v", errs)
	}
}

func TestRealityPortalListenPortIsStableAndHigh(t *testing.T) {
	m := MasterConfig{Name: "master-xa-1"}
	p := m.RealityPortalListenPort()
	if p < clientVLESSPortLo || p > clientVLESSPortHi {
		t.Fatalf("derived portal port %d out of [%d,%d]", p, clientVLESSPortLo, clientVLESSPortHi)
	}
	if p != m.RealityPortalListenPort() {
		t.Fatal("derived portal port is not stable")
	}
	if other := (MasterConfig{Name: "master-xa-2"}).RealityPortalListenPort(); other == p {
		t.Errorf("two masters derived the same port %d", p)
	}
	m.RealityPortal.ListenPort = 45000
	if got := m.RealityPortalListenPort(); got != 45000 {
		t.Errorf("pinned port = %d, want 45000", got)
	}
}

// The derived port steps past every TCP port the master already listens on, so
// the two derivations (client VLESS and portal) can never land on one number.
func TestRealityPortalListenPortStepsPastKnownPorts(t *testing.T) {
	m := MasterConfig{Name: "master-xa-1"}
	derived := m.RealityPortalListenPort()

	m.ClientVLESS = ClientVLESSConfig{Enabled: true, ListenPort: derived}
	if got := m.RealityPortalListenPort(); got == derived {
		t.Errorf("portal port %d collides with client VLESS", got)
	}
	m.PublicTCPPorts = []int{derived + 1}
	if got := m.RealityPortalListenPort(); got == derived || got == derived+1 {
		t.Errorf("portal port %d collides with a known port", got)
	}
}

func TestValidateRealityPortalCollisions(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(m *MasterConfig)
		wantFrag string
	}{
		{"out of range", func(m *MasterConfig) { m.RealityPortal.ListenPort = 70000 }, "reality_portal.listen_port 70000 out of range"},
		{"privileged", func(m *MasterConfig) { m.RealityPortal.ListenPort = 443 }, "reality_portal.listen_port 443 out of range"},
		{"dest port", func(m *MasterConfig) { m.RealityPortal.DestPort = 70000 }, "reality_portal.dest_port"},
		{"client vless", func(m *MasterConfig) {
			m.ClientVLESS = ClientVLESSConfig{Enabled: true, ListenPort: 45000}
			m.RealityPortal.ListenPort = 45000
		}, "collides"},
		{"public tcp port", func(m *MasterConfig) {
			m.PublicTCPPorts = []int{45000}
			m.RealityPortal.ListenPort = 45000
		}, "collides"},
		{"redir port", func(m *MasterConfig) { m.RealityPortal.ListenPort = 7895 }, "collides"},
		{"portal socks", func(m *MasterConfig) { m.RealityPortal.ListenPort = 10808 }, "collides"},
		{"client vless socks", func(m *MasterConfig) { m.RealityPortal.ListenPort = 7893 }, "collides"},
		{"sni with port", func(m *MasterConfig) { m.RealityPortal.SNI = "a.example:443" }, "bare hostname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MasterConfig{Name: "m"}
			tt.mutate(&m)
			if errs := validateRealityPortal(0, m); !anyErrContains(errs, tt.wantFrag) {
				t.Fatalf("validateRealityPortal() = %v, want an error containing %q", errs, tt.wantFrag)
			}
		})
	}
	if errs := validateRealityPortal(0, MasterConfig{Name: "m"}); len(errs) != 0 {
		t.Fatalf("unset portal block rejected: %v", errs)
	}
}

func TestRealityPortalDestHostPort(t *testing.T) {
	if got := (RealityPortalConfig{}).DestHostPort(); got != "" {
		t.Errorf("unset dest = %q, want empty", got)
	}
	if got := (RealityPortalConfig{DestDomain: "a.example"}).DestHostPort(); got != "a.example:443" {
		t.Errorf("dest = %q, want a.example:443", got)
	}
}

func anyErrContains(errs []error, frag string) bool {
	for _, err := range errs {
		if strings.Contains(err.Error(), frag) {
			return true
		}
	}
	return false
}
