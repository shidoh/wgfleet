package config

import (
	"strings"
	"testing"
)

func cfgWithExits(reserve []string) ControllerConfig {
	return ControllerConfig{
		Fleet: FleetSection{
			Masters: []MasterConfig{{
				Name:     "master-xa-1",
				MgmtAddr: "172.29.3.10",
				Routing:  MasterRouting{Balance: "consistent-hashing", ReserveExits: reserve},
			}},
			Exits: []ExitConfig{
				{Name: "vn1", MgmtAddr: "172.29.3.23"},
				{Name: "anz3", MgmtAddr: "172.29.3.20"},
			},
		},
	}
}

func TestReserveExitsAcceptsDeclaredExit(t *testing.T) {
	if err := cfgWithExits([]string{"anz3"}).validateReserveExits(); err != nil {
		t.Fatalf("declared exit rejected: %v", err)
	}
}

func TestReserveExitsRejectsUnknownName(t *testing.T) {
	err := cfgWithExits([]string{"anz3", "typo-node"}).validateReserveExits()
	if err == nil {
		t.Fatal("expected an error for an exit name that matches no declared exit")
	}
	if !strings.Contains(err.Error(), "typo-node") {
		t.Errorf("error must name the offending entry, got: %v", err)
	}
}

func TestReserveExitsEmptyIsValid(t *testing.T) {
	if err := cfgWithExits(nil).validateReserveExits(); err != nil {
		t.Fatalf("empty reserve_exits must be valid: %v", err)
	}
}
