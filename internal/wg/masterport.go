package wg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// The band a master's pinned AWG port is drawn from when an exit starts the flow
// (transports.awg.exit_initiated). It sits below the kernel's default
// ip_local_port_range (32768–60999), so an ordinary outbound socket on the master
// never takes the port the exit is knocking on.
const (
	MasterPortLow  = 20000
	MasterPortHigh = 32767
)

// MasterPortFor derives the master's external UDP port for one master↔exit AWG
// tunnel. It must be stable: the exit keeps knocking on it, and a port that moved
// between renders would start a new flow — one the master opens, which is exactly
// what the RU filter cuts. The pair, not the exit alone, keys it, so a second
// master gets a tuple of its own.
func MasterPortFor(master, exit string) int {
	sum := sha256.Sum256([]byte("wgfleet|master-port|v1|" + master + "|" + exit))
	span := uint32(MasterPortHigh - MasterPortLow + 1)
	return MasterPortLow + int(binary.BigEndian.Uint32(sum[:4])%span)
}

// MasterPortForGen is MasterPortFor after gen rotations. Generation 0 is the
// port the tunnel already has; each later one is drawn afresh, so a flow the
// path filter poisoned or froze is replaced by one the exit opens anew.
func MasterPortForGen(master, exit string, gen int) int {
	if gen <= 0 {
		return MasterPortFor(master, exit)
	}
	return MasterPortFor(master, fmt.Sprintf("%s|gen%d", exit, gen))
}

// ExitInitiatedKeepaliveFor is the exit's keepalive toward a master it pins. A
// path filter forgets an idle flow, and after that whichever end speaks first
// becomes the flow's initiator; with the exit speaking every few seconds the
// flow never goes quiet long enough to be forgotten. Per-exit within 5–9 s so
// the period is no fleet-wide signature either.
func ExitInitiatedKeepaliveFor(identity string) int {
	sum := sha256.Sum256([]byte("wgfleet|keepalive-exit-initiated|v1|" + identity))
	return 5 + int(binary.BigEndian.Uint32(sum[:4])%5)
}
