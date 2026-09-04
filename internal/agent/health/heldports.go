package health

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// HeldUDPPorts lists the UDP ports this network namespace currently has a socket
// on, read from the kernel rather than from a list in the code.
//
// That distinction is the whole point. The first draft of this feature carried a
// hardcoded set — the client WG port plus 443, 9993 and 9994 — which is the same
// mistake as the bug it was written to catch: the ports were guessed instead of
// observed. A service that binds a new UDP port tomorrow creates a new black hole
// for client traffic to that port, and only the kernel knows it happened.
func HeldUDPPorts() ([]int, error) {
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

// parseHeldUDPPorts extracts the local ports from /proc/net/udp[6]. The local
// address column is `<hex address>:<hex port>`; the address itself is deliberately
// ignored, because a conflict for the transparent bind is decided by the port
// alone — a wildcard holder and a specific-address holder collide the same way.
func parseHeldUDPPorts(r io.Reader) ([]int, error) {
	var ports []int
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		_, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue // the header row, or a line we do not understand
		}
		p, err := strconv.ParseUint(hexPort, 16, 32)
		if err != nil || p == 0 || p > 65535 {
			continue
		}
		ports = append(ports, int(p))
	}
	return ports, sc.Err()
}
