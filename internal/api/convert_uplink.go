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

// Bounds on what the agent accepts from the wire: it dials every target every
// 30 s and labels a metric series with each name.
const (
	maxUplinkProbeTargets = 32
	maxUplinkProbeName    = 64
)

// uplinkTargetsFromProto keeps only targets the agent can and should dial: a
// short name, a literal routable IP and a non-zero port, at most
// maxUplinkProbeTargets of them. Anything else is dropped here rather than handed
// to the prober, so a bad entry costs one measurement, never the agent.
func uplinkTargetsFromProto(ts []*pb.UplinkProbeTarget) []domain.UplinkProbeTarget {
	var out []domain.UplinkProbeTarget
	for _, t := range ts {
		if len(out) == maxUplinkProbeTargets {
			break
		}
		name := t.GetName()
		addr, err := netip.ParseAddrPort(t.GetAddr())
		if err != nil || addr.Port() == 0 || name == "" || len(name) > maxUplinkProbeName {
			continue
		}
		ip := addr.Addr()
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			continue
		}
		out = append(out, domain.UplinkProbeTarget{Name: name, Addr: addr})
	}
	return out
}
