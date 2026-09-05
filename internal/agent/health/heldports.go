package health

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ephemeralRangePath is where the kernel publishes the port range it hands out to
// sockets that did not ask for a number. Read rather than assumed: the default is
// 32768-60999, but it is a tunable and a node whose operator narrowed it would
// otherwise have real service ports treated as noise.
const ephemeralRangePath = "/proc/sys/net/ipv4/ip_local_port_range"

// defaultEphemeralLow/High are the kernel's defaults, used when the range cannot
// be read. Erring towards the wider default range means an unreadable /proc makes
// this quieter, never noisier.
const (
	defaultEphemeralLow  = 32768
	defaultEphemeralHigh = 60999
)

// HeldUDPPorts lists the UDP ports this network namespace has a SERVICE on, read
// from the kernel rather than from a list in the code.
//
// That distinction is the whole point. The first draft of this feature carried a
// hardcoded set — the client WG port plus 443, 9993 and 9994 — which is the same
// mistake as the bug it was written to catch: the ports were guessed instead of
// observed. A service that binds a new UDP port tomorrow creates a new black hole
// for client traffic to that port, and only the kernel knows it happened.
//
// Service, not socket. Two kinds of entry in the table are deliberately dropped:
//
//   - a socket with a remote peer, which is one flow rather than a listener;
//   - a port inside the kernel's ephemeral range, which some process was handed a
//     second ago and will give back a second from now.
//
// Both are excluded for the same reason, and it is not tidiness. Each port this
// returns becomes a `port` label on a gauge and a candidate for a Degraded check.
// Left in, a busy master would mint a new time series every pass for every
// outbound datagram it sent, and the check would flap between healthy and broken
// on whichever high port happened to be open when it looked — an instrument whose
// readings change when nothing changed is not an instrument.
func HeldUDPPorts() ([]int, error) {
	lo, hi := ephemeralRange()
	seen := map[int]bool{}
	var firstErr error
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		f, err := os.Open(path)
		if err != nil {
			// udp6 is absent on an IPv6-less kernel; only fail if NEITHER could be read.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ports, perr := parseHeldUDPPorts(f)
		_ = f.Close()
		if perr != nil {
			if firstErr == nil {
				firstErr = perr
			}
			continue
		}
		for _, p := range ports {
			if p >= lo && p <= hi {
				continue
			}
			seen[p] = true
		}
		firstErr = nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// parseHeldUDPPorts extracts the local ports of LISTENING sockets from
// /proc/net/udp[6]. The local address column is `<hex address>:<hex port>`; the
// address is deliberately ignored, and that is a deliberate over-report rather
// than a claim about the kernel: a WILDCARD holder blocks every address on the
// port, while a holder bound to one address only blocks that address. Measured on
// the stand 2026-09-05 — the master holds 127.0.0.53:53 and the probe still opens
// a transparent socket on :53, while 0.0.0.0:443 refuses it. Which of the two a
// port is cannot be read from this table without also knowing the address mihomo
// will bind, which is the address of whichever server a client happened to dial.
// The bind probe answers the real question; this list only decides what to ask
// about. The remote column is not ignored: a non-zero peer
// means a connected socket, which is a conversation and not a service, and whose
// port is released when it ends.
func parseHeldUDPPorts(r io.Reader) ([]int, error) {
	var ports []int
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		_, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue // the header row, or a line we do not understand
		}
		if remAddr, remPort, ok := strings.Cut(fields[2], ":"); ok && !isHexZero(remAddr+remPort) {
			continue // connected: an outbound flow, not a listener
		}
		p, err := strconv.ParseUint(hexPort, 16, 32)
		if err != nil || p == 0 || p > 65535 {
			continue
		}
		ports = append(ports, int(p))
	}
	return ports, sc.Err()
}

// isHexZero reports whether a hex field is all zeroes, i.e. an unset address or
// port. A field we cannot read as hex is treated as non-zero, so an unparseable
// line drops out of the listener set rather than joining it on a guess.
func isHexZero(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}

// ephemeralRange reads the kernel's local port range, falling back to its
// documented defaults.
func ephemeralRange() (lo, hi int) {
	b, err := os.ReadFile(ephemeralRangePath)
	if err != nil {
		return defaultEphemeralLow, defaultEphemeralHigh
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return defaultEphemeralLow, defaultEphemeralHigh
	}
	lo, lerr := strconv.Atoi(fields[0])
	hi, herr := strconv.Atoi(fields[1])
	if lerr != nil || herr != nil || lo <= 0 || hi < lo {
		return defaultEphemeralLow, defaultEphemeralHigh
	}
	return lo, hi
}
