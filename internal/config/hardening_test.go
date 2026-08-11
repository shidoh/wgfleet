package config

import "testing"

func ptr(b bool) *bool { return &b }

func TestHardeningFor(t *testing.T) {
	cases := []struct {
		name                   string
		fleetSSHD, fleetF2B    *bool
		nodeSSHD, nodeF2B      *bool
		wantSSHD, wantFail2ban bool
	}{
		// The default is the load-bearing case: an operator who never writes the
		// block must get the fully hardened fleet every earlier version gave them.
		{"nothing set → both on", nil, nil, nil, nil, true, true},
		{"fleet off, node silent → node inherits off", ptr(false), ptr(false), nil, nil, false, false},

		// The reason the knob is per-node at all: keep your own sshd on the one box
		// you log into without un-hardening every public-facing exit.
		{"node off, fleet silent", nil, nil, ptr(false), nil, false, true},

		// An explicit true on a node must beat a fleet-wide false — otherwise the
		// override would only ever be able to weaken, never to re-harden one node.
		{"node re-enables against fleet off", ptr(false), ptr(false), ptr(true), ptr(true), true, true},

		// The two subsystems stay independent at both levels.
		{"fleet off sshd, node off fail2ban", ptr(false), nil, nil, ptr(false), false, false},
		{"node off sshd, fleet off fail2ban", nil, ptr(false), ptr(false), nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := FleetSection{Hardening: HardeningSection{SSHD: c.fleetSSHD, Fail2ban: c.fleetF2B}}
			got := f.HardeningFor(HardeningSection{SSHD: c.nodeSSHD, Fail2ban: c.nodeF2B})
			if got == nil {
				t.Fatal("HardeningFor = nil; the controller must always state its intent explicitly")
			}
			if got.SSHD != c.wantSSHD || got.Fail2ban != c.wantFail2ban {
				t.Errorf("HardeningFor = {SSHD:%v Fail2ban:%v}, want {SSHD:%v Fail2ban:%v}",
					got.SSHD, got.Fail2ban, c.wantSSHD, c.wantFail2ban)
			}
		})
	}
}

// A bare `false` in YAML must survive koanf's decode as an explicit opt-out. This
// is the whole reason the fields are *bool: with a plain bool, "written false" and
// "not written at all" would be the same value and the knob could never turn off —
// nor could a node re-enable what the fleet turned off.
func TestHardeningDecodesExplicitFalse(t *testing.T) {
	path := writeTemp(t, "controller.yaml", controllerYAML+`
  hardening:
    sshd: false
    fail2ban: true
`)
	cfg, err := Load(path, &ControllerConfig{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h := cfg.Fleet.Hardening
	if h.SSHD == nil || *h.SSHD {
		t.Errorf("sshd = %v, want an explicit false", h.SSHD)
	}
	if h.Fail2ban == nil || !*h.Fail2ban {
		t.Errorf("fail2ban = %v, want an explicit true", h.Fail2ban)
	}
	if spec := cfg.Fleet.HardeningFor(HardeningSection{}); spec.SSHD || !spec.Fail2ban {
		t.Errorf("HardeningFor = %+v, want sshd off / fail2ban on", spec)
	}
}

// The per-node override must decode from the master/exit entries too, not only at
// fleet level — and a node's explicit true must survive a fleet-wide false.
func TestHardeningDecodesPerNodeOverride(t *testing.T) {
	path := writeTemp(t, "controller.yaml", controllerYAML+`
  hardening:
    sshd: false
`)
	cfg, err := Load(path, &ControllerConfig{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Simulate the manifest entries carrying their own sections; decoding of the
	// nested key itself is covered by the round-trip below.
	master := cfg.Fleet.Masters[0]
	if got := cfg.Fleet.HardeningFor(master.Hardening); got.SSHD {
		t.Errorf("master with no override must inherit the fleet's sshd:false, got %+v", got)
	}
	master.Hardening = HardeningSection{SSHD: ptr(true)}
	if got := cfg.Fleet.HardeningFor(master.Hardening); !got.SSHD {
		t.Errorf("master opting back in must beat the fleet default, got %+v", got)
	}
}

func TestHardeningPerNodeKeyDecodes(t *testing.T) {
	// A second exit carrying its own hardening block: asserts the nested key parses
	// on a list element, not only at fleet level.
	path := writeTemp(t, "controller.yaml", controllerYAML+`
    - name: exit-de-2
      region: de
      egress: warp
      address_pool: 10.82.0.0/24
      hardening:
        sshd: false
        fail2ban: false
`)
	cfg, err := Load(path, &ControllerConfig{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var exit ExitConfig
	for _, e := range cfg.Fleet.Exits {
		if e.Name == "exit-de-2" {
			exit = e
		}
	}
	if exit.Name == "" {
		t.Fatalf("exit-de-2 not parsed; exits = %+v", cfg.Fleet.Exits)
	}
	if exit.Hardening.SSHD == nil || *exit.Hardening.SSHD {
		t.Errorf("exits[].hardening.sshd = %v, want an explicit false", exit.Hardening.SSHD)
	}
	got := cfg.Fleet.HardeningFor(exit.Hardening)
	if got.SSHD || got.Fail2ban {
		t.Errorf("HardeningFor = %+v, want both disabled", got)
	}
}
