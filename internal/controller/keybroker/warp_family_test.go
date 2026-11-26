package keybroker

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// The exit's spec carries the resolved WARP family; auto stays off the wire so
// a fleet that never sets the knob renders exactly as before.
func TestExitSpecCarriesWARPIPFamily(t *testing.T) {
	cases := []struct {
		name, fleet, exit string
		want              domain.WARPIPFamily
	}{
		{"unset", "", "", ""},
		{"fleet auto", "auto", "", ""},
		{"fleet default", "ipv4", "", domain.WARPIPFamilyIPv4},
		{"exit override", "ipv4", "ipv6", domain.WARPIPFamilyIPv6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			fleet := testFleet()
			fleet.WARPIPFamily = c.fleet
			fleet.Exits[0].WARPIPFamily = c.exit
			b := New(st, fleet, slog.New(slog.NewTextHandler(io.Discard, nil)))
			seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
			seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

			spec, err := b.RenderNodeSpec(context.Background(), "exit-de-1")
			if err != nil {
				t.Fatal(err)
			}
			if spec.WARPIPFamily != c.want {
				t.Errorf("WARPIPFamily = %q, want %q", spec.WARPIPFamily, c.want)
			}
		})
	}
}
