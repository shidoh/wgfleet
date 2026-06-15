package routing

import (
	"fmt"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestDumpWARPRouting(t *testing.T) {
	spec := domain.RoutingSpec{
		EgressInterface: "wgcf",
		MasterIP:        "10.20.25.254",
		DirectCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		FwMark:          0,
	}
	steps, err := Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		fmt.Printf("BE=%v  %s\n", s.BestEffort, joinArgs(s.Argv))
	}
	fmt.Println("--- ManagedPrefs:", ManagedPrefs(spec))
}

func joinArgs(a []string) string {
	out := ""
	for i, x := range a {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}
