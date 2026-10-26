package api

import (
	"net/netip"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

func uplinkTargetsToProto(ts []domain.UplinkProbeTarget) []*pb.UplinkProbeTarget {
	if len(ts) == 0 {
		return nil
	}
	out := make([]*pb.UplinkProbeTarget, 0, len(ts))
	for _, t := range ts {
		out = append(out, &pb.UplinkProbeTarget{Name: t.Name, Addr: t.Addr.String()})
	}
	return out
}

// uplinkTargetsFromProto keeps only targets the agent can dial: a name, a literal
// IP and a non-zero port. Anything else is dropped here rather than handed to the
// prober, so a bad entry costs one measurement, never the agent.
func uplinkTargetsFromProto(ts []*pb.UplinkProbeTarget) []domain.UplinkProbeTarget {
	var out []domain.UplinkProbeTarget
	for _, t := range ts {
		addr, err := netip.ParseAddrPort(t.GetAddr())
		if err != nil || addr.Port() == 0 || t.GetName() == "" {
			continue
		}
		out = append(out, domain.UplinkProbeTarget{Name: t.GetName(), Addr: addr})
	}
	return out
}
