package api

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

func TestUplinkProbeTargetsRoundTrip(t *testing.T) {
	targets := []domain.UplinkProbeTarget{
		{Name: "master-xa-2", Addr: netip.MustParseAddrPort("203.0.113.2:8443")},
		{Name: "master-xa-3", Addr: netip.MustParseAddrPort("198.51.100.3:443")},
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{UplinkProbeTargets: targets}}
	got := SpecFromProto(SpecToProto(spec))
	if !reflect.DeepEqual(got.Master.UplinkProbeTargets, targets) {
		t.Fatalf("targets after round trip = %+v, want %+v", got.Master.UplinkProbeTargets, targets)
	}
}

// The wire is input from the network: a target the agent cannot dial is dropped
// on the way in, so the prober never sees it, and the good ones still arrive.
func TestUplinkProbeTargetsFromProtoDropsUnusable(t *testing.T) {
	p := SpecToProto(domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	p.Master.UplinkProbeTargets = []*pb.UplinkProbeTarget{
		{Name: "ok", Addr: "203.0.113.2:8443"},
		{Name: "no-port", Addr: "203.0.113.3"},
		{Name: "zero-port", Addr: "203.0.113.4:0"},
		{Name: "", Addr: "203.0.113.5:443"},
		{Name: "hostname", Addr: "master.example:443"},
		{Name: "loopback", Addr: "127.0.0.1:443"},
		{Name: "unspecified", Addr: "0.0.0.0:443"},
		{Name: "link-local", Addr: "169.254.169.254:80"},
		{Name: strings.Repeat("n", 65), Addr: "203.0.113.6:443"},
	}
	got := SpecFromProto(p).Master.UplinkProbeTargets
	want := []domain.UplinkProbeTarget{{Name: "ok", Addr: netip.MustParseAddrPort("203.0.113.2:8443")}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %+v, want only the usable one %+v", got, want)
	}
}

// A target list is bounded: the agent dials every entry every 30 s.
func TestUplinkProbeTargetsFromProtoAreCapped(t *testing.T) {
	p := SpecToProto(domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	for i := range 100 {
		p.Master.UplinkProbeTargets = append(p.Master.UplinkProbeTargets,
			&pb.UplinkProbeTarget{Name: fmt.Sprintf("m%d", i), Addr: fmt.Sprintf("203.0.113.%d:443", i+1)})
	}
	if got := len(SpecFromProto(p).Master.UplinkProbeTargets); got != maxUplinkProbeTargets {
		t.Fatalf("kept %d targets, want the cap %d", got, maxUplinkProbeTargets)
	}
}
