package wg

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// DumpPeer is one peer line of `awg show <iface> dump`: what the KERNEL holds,
// as opposed to what the config file says it should.
type DumpPeer struct {
	PublicKey       string
	Endpoint        string   // "" when the kernel holds none
	AllowedIPs      []string // sorted, so two readings compare by value
	LatestHandshake time.Time
	Keepalive       int // seconds; 0 = off
}

// dumpPeerFields is the width of a peer line: public key, preshared key,
// endpoint, allowed-ips, latest-handshake, rx, tx, persistent-keepalive.
const dumpPeerFields = 8

// ParseShowDump parses `awg show <iface> dump`. The first line describes the
// interface and is skipped whatever its width — AmneziaWG appends its obfuscation
// parameters there. A peer line of any other width than eight is skipped: a
// misread peer would be edited or removed on the strength of it.
func ParseShowDump(out string) []DumpPeer {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		return nil
	}
	var peers []DumpPeer
	for _, line := range lines[1:] {
		f := strings.Split(line, "\t")
		if len(f) != dumpPeerFields {
			continue
		}
		p := DumpPeer{PublicKey: f[0]}
		if f[2] != "(none)" {
			p.Endpoint = f[2]
		}
		if f[3] != "(none)" && f[3] != "" {
			p.AllowedIPs = strings.Split(f[3], ",")
			sort.Strings(p.AllowedIPs)
		}
		if secs, err := strconv.ParseInt(f[4], 10, 64); err == nil && secs > 0 {
			p.LatestHandshake = time.Unix(secs, 0).UTC()
		}
		if n, err := strconv.Atoi(f[7]); err == nil && n > 0 {
			p.Keepalive = n
		}
		peers = append(peers, p)
	}
	return peers
}
