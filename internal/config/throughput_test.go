package config

import "testing"

func TestEgressThroughputFloorKBytes(t *testing.T) {
	cases := []struct {
		name        string
		fleet, exit int
		want        int
	}{
		{"both unset → default", 0, 0, DefaultMinEgressThroughputKBytes},
		{"fleet override", 500, 0, 500},
		{"exit override wins", 500, 300, 300},
		{"exit disabled", 0, -1, 0},
		{"fleet disabled", -1, 0, 0},
		{"exit override beats fleet-disabled", -1, 300, 300},
		{"exit disabled beats fleet floor", 500, -1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := FleetSection{MinEgressThroughputKBytes: c.fleet}
			e := ExitConfig{MinEgressThroughputKBytes: c.exit}
			if got := f.EgressThroughputFloorKBytes(e); got != c.want {
				t.Errorf("floor(fleet=%d,exit=%d) = %d, want %d", c.fleet, c.exit, got, c.want)
			}
		})
	}
}
