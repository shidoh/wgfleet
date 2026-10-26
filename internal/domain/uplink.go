package domain

import "net/netip"

// UplinkProbeTarget is one TCP endpoint a master connects to and closes, never
// sending data, to measure its own uplink. The controller renders one per other
// master, at a port that master's firewall opens to the world. A filter in front
// of one master shows as slow or failed connects FROM it while the reverse
// direction stays clean — the asymmetry is what names the guilty uplink.
type UplinkProbeTarget struct {
	// Name labels the measurement: the other master's node name.
	Name string
	Addr netip.AddrPort
}
