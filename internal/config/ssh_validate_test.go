package config

import (
	"reflect"
	"strings"
	"testing"
)

func fullSSH() SSHConfig {
	return SSHConfig{Host: "203.0.113.5", User: "root", KeyPath: "/etc/wgfleet/bootstrap_ed25519"}
}

// An ssh block is all or nothing. Without one the node is simply not managed over
// SSH (the master beside the controller lives that way); with one, the controller
// will dial it to provision, upgrade and roll back — and without host, user or
// key_path every one of those fails, at the moment it is needed, with "has no ssh
// target". Refusing the manifest says so before then.
func TestValidateRejectsAPartialSSHBlock(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*ControllerConfig)
		wantFrag string
	}{
		{"master without key_path", func(c *ControllerConfig) {
			s := fullSSH()
			s.KeyPath = ""
			c.Fleet.Masters[1].SSH = s
		}, "fleet.masters[1] (master-xa-2): ssh.key_path is required"},
		{"exit without host", func(c *ControllerConfig) {
			s := fullSSH()
			s.Host = ""
			c.Fleet.Exits[0].SSH = s
		}, "fleet.exits[0] (exit-de-1): ssh.host is required"},
		{"exit without user", func(c *ControllerConfig) {
			s := fullSSH()
			s.User = ""
			c.Fleet.Exits[0].SSH = s
		}, "fleet.exits[0] (exit-de-1): ssh.user is required"},
		{"only a port", func(c *ControllerConfig) {
			c.Fleet.Masters[0].SSH = SSHConfig{Port: 22}
		}, "fleet.masters[0] (master-xa-1): ssh.host is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := twoMasters()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantFrag) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.wantFrag)
			}
		})
	}
}

func TestValidateAcceptsAFullOrAbsentSSHBlock(t *testing.T) {
	cfg := twoMasters()
	cfg.Fleet.Masters[1].SSH = fullSSH()
	cfg.Fleet.Exits[0].SSH = fullSSH()
	// Masters[0] has none: the co-located master.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("full and absent ssh blocks rejected: %v", err)
	}
}

// The tester's manifest: `key:` instead of `key_path:`. The decoder drops the
// unknown key, the block is partial, and now the manifest is refused — and the
// unknown key itself is named, so the reason is on the screen.
func TestUnknownKeysNamesAMisspelledKey(t *testing.T) {
	path := writeTemp(t, "controller.yaml", `
controller:
  listen: "0.0.0.0:8443"
  lsten_typo: "x"
fleet:
  masters:
    - name: master-1
      ssh:
        host: 203.0.113.1
        user: root
        key: /etc/wgfleet/bootstrap_ed25519
  exits:
    - name: exit-1
      address_pool: 10.81.0.0/24
`)
	got, err := UnknownKeys(path, &ControllerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"controller.lsten_typo", "fleet.masters[0].ssh.key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownKeys = %v, want %v", got, want)
	}
}

// Environment overrides are not the file: WGFLEET_SSH_INSECURE_HOST_KEY=1 is a
// documented switch, and the loader would read it as the key ssh.insecure.host.key.
func TestUnknownKeysIgnoresTheEnvironment(t *testing.T) {
	t.Setenv("WGFLEET_SSH_INSECURE_HOST_KEY", "1")
	path := writeTemp(t, "controller.yaml", "controller:\n  listen: \"0.0.0.0:8443\"\n")
	got, err := UnknownKeys(path, &ControllerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("UnknownKeys = %v, want none", got)
	}
}
