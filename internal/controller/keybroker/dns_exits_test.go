package keybroker

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// mixedDNSFleet has two exits, only one of which runs a resolver.
func mixedDNSFleet(masterDNS bool) config.FleetSection {
	fleet := testFleet()
	fleet.Masters[0].DNSFilter = masterDNS
	second := fleet.Exits[0]
	second.Name = "exit-nl-1"
	second.Region = "nl"
	second.AddressPool = "10.82.0.0/24"
	second.DNSFilter = false
	fleet.Exits = append(fleet.Exits, second)
	return fleet
}

func seedMixedDNSFleet(t *testing.T, masterDNS bool) *Broker {
	t.Helper()
	b, st := newBrokerWithFleet(t, mixedDNSFleet(masterDNS))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	seedNode(t, st, "exit-nl-1", "10.20.0.6", "198.51.100.8", "uJ8kbwXkS1Tm9KUhJeKqQ0bTP1ZIUGUQ9xg8bLiM7FA=", domain.RoleExit)
	return b
}

func TestMasterResolverForwardsOnlyToExitsThatRunOne(t *testing.T) {
	b := seedMixedDNSFleet(t, true)

	spec, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := spec.DNS.Upstreams; len(got) != 1 || got[0] != "10.20.0.5" {
		t.Errorf("master resolver upstreams = %v, want [10.20.0.5]: exit-nl-1 runs no resolver", got)
	}
}

func TestClientsAreHandedOnlyExitsThatRunAResolver(t *testing.T) {
	b := seedMixedDNSFleet(t, false)

	spec, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := spec.Master.Compose.ClientDNS; len(got) != 1 || got[0] != "10.20.0.5" {
		t.Errorf("client DNS = %v, want [10.20.0.5]: exit-nl-1 runs no resolver", got)
	}
}
