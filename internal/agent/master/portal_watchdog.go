package master

import (
	"log/slog"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/health"
	"github.com/shidoh/wgfleet/internal/agent/sockwatch"
	"github.com/shidoh/wgfleet/internal/domain"
)

// PortalStallAfter is how long data the portal sent may go unacknowledged
// before its socket is killed. The portal sends a mux keepalive every ~10 s, so
// a live bridge acknowledges well inside it.
const PortalStallAfter = 30 * time.Second

// NewPortalWatchdog watches the reality portal's accepted sockets (ADR-0038) and
// kills one whose sent data has gone unacknowledged for PortalStallAfter. A
// bridge cut off for a while comes back on a new flow, but the exit's firewall
// drops the portal's segments for the old one without a reset, so the portal's
// socket stays ESTABLISHED for minutes and xray keeps sending streams into it
// (seen on the stand after a 60 s ban). Kills are counted per exit; name maps an
// exit's IP to its name ("" ⇒ the IP). portal() nil ⇒ nothing watched.
func NewPortalWatchdog(log *slog.Logger, portal func() *domain.RealityPortalSpec, name func(ip string) string, opts ...sockwatch.Option) *sockwatch.Watchdog {
	return sockwatch.New(log, "portal watchdog", PortalStallAfter, func() sockwatch.Matcher {
		p := portal()
		if p == nil || p.ListenPort == 0 {
			return nil
		}
		port := uint16(p.ListenPort)
		return func(s health.SSSocket) (string, time.Duration, bool) {
			if s.Local.Port() != port || !s.HasLastAck || !s.HasLastSnd {
				return "", 0, false
			}
			label := name(s.Peer.Addr().String())
			if label == "" {
				label = s.Peer.Addr().String()
			}
			// Nothing sent since the last ACK: idle, not stalled.
			if s.LastSnd >= s.LastAck {
				return label, 0, true
			}
			return label, s.LastAck, true
		}
	}, opts...)
}
