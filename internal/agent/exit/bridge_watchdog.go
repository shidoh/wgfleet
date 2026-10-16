package exit

import (
	"log/slog"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/health"
	"github.com/shidoh/wgfleet/internal/agent/sockwatch"
	"github.com/shidoh/wgfleet/internal/domain"
)

// BridgeStallAfter is how long a bridge socket may go without receiving data
// before it is killed. The portal sends a mux keepalive every ~10 s, so a live
// flow never goes this long; 30 s is three missed keepalives.
const BridgeStallAfter = 30 * time.Second

// NewBridgeWatchdog watches the reverse bridge's sockets to every portal
// (ADR-0038) by the kernel's lastrcv and kills one that received nothing for
// BridgeStallAfter; xray redials. Not a byte count: a flow frozen from its first
// segment has received nothing to count (seen on the stand). Kills are counted
// per master. bridge() nil ⇒ not in the mode, nothing watched.
func NewBridgeWatchdog(log *slog.Logger, bridge func() *domain.RealityBridgeSpec, opts ...sockwatch.Option) *sockwatch.Watchdog {
	return sockwatch.New(log, "bridge watchdog", BridgeStallAfter, func() sockwatch.Matcher {
		b := bridge()
		if b == nil {
			return nil
		}
		portals := health.PortalMasters(b)
		return func(s health.SSSocket) (string, time.Duration, bool) {
			master, ok := portals[s.Peer]
			return master, s.LastRcv, ok && s.HasLastRcv
		}
	}, opts...)
}
