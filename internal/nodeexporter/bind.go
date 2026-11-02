package nodeexporter

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Bind is what the kernel says about the host-metrics port right now.
//
// It replaces the question the planner used to ask — "is our package installed
// and is its unit running" — with the question that actually matters: is
// something serving host metrics, and is it reachable only over the management
// overlay. The difference is the whole point of the 2026-09-21 incident:
// the operator upgraded the exporter out of band (distro package out, upstream
// node_exporter in, the package's unit masked so the two would not fight over the
// port), and the agent, which recognised only the package, spent twelve hours
// trying to start a masked unit and holding three nodes in Error. An optional
// component the operator is allowed to upgrade on their own schedule must be
// ADOPTED by what it does, not owned by how it was installed.
type Bind int

const (
	// BindNone — nothing is serving the port anywhere the fleet could scrape it.
	BindNone Bind = iota
	// BindMgmt — served on the management overlay only. This is the goal state,
	// whoever produced it.
	BindMgmt
	// BindExposed — served on a wildcard or on some other address, i.e. reachable
	// from outside the overlay. The exporter's output lists every listening
	// socket, mount and interface on the box (DESIGN §9).
	BindExposed
)

func (b Bind) String() string {
	switch b {
	case BindMgmt:
		return "mgmt"
	case BindExposed:
		return "exposed"
	default:
		return "none"
	}
}

// procTCP / procTCP6 are the kernel's TCP socket tables. Package variables so the
// tests can point them at fixtures.
var (
	procTCP  = "/proc/net/tcp"
	procTCP6 = "/proc/net/tcp6"
)

// tcpListen is the st column's value for TCP_LISTEN.
const tcpListen = "0A"

// ListenAddrs returns the local addresses of the sockets LISTENING on port,
// read from the kernel rather than probed with a connection.
//
// A connection cannot answer the question: dialling <mgmt>:9100 succeeds just as
// well when the exporter is bound to the wildcard, so the one bind that must be
// caught — the one open to the whole internet — is the one a dial calls healthy.
func ListenAddrs(port int) ([]string, error) {
	seen := map[string]bool{}
	var firstErr error
	for _, src := range []struct {
		path string
		v6   bool
	}{{procTCP, false}, {procTCP6, true}} {
		f, err := os.Open(src.path)
		if err != nil {
			// tcp6 is absent on an IPv6-less kernel; only fail if NEITHER could be read.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, a := range ListenAddrsFrom(f, port, src.v6) {
			seen[a] = true
		}
		_ = f.Close()
		firstErr = nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// ListenAddrsFrom parses one /proc/net/tcp[6] table. It is exported because the
// provisioner asks the same question of a REMOTE node, over the Runner, before
// there is a wgfleet agent on it to ask. The local address column is
// `<hex address>:<hex port>`; a socket with a peer is a conversation, not a
// listener, and the st column tells the two apart without guessing.
func ListenAddrsFrom(r io.Reader, port int, v6 bool) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != tcpListen {
			continue // the header row, or a socket that is not listening
		}
		hexAddr, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(hexPort, 16, 32)
		if err != nil || int(p) != port {
			continue
		}
		ip := parseHexAddr(hexAddr, v6)
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
	}
	if err := sc.Err(); err != nil {
		// A table read only half way can hide a listener, and the listener it hides
		// is as likely as not the exposed one. Answer "nothing", never "half": that
		// makes the planner re-assert the bind it wants, which is idempotent, where a
		// partial answer would let an exporter open to the internet read as correct.
		return nil
	}
	sort.Strings(out)
	return out
}

// parseHexAddr decodes /proc's address encoding: 32-bit words in host byte order,
// which on every platform wgfleet runs on is little-endian.
func parseHexAddr(s string, v6 bool) net.IP {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	if (v6 && len(raw) != 16) || (!v6 && len(raw) != 4) {
		return nil
	}
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return net.IP(raw)
}

// ClassifyBind turns the listening addresses into the one fact the planner acts
// on. Exposure wins over a correct bind: a process listening on both the overlay
// address and the wildcard is reachable from outside, and reporting the overlay
// bind it also has would be reporting the half that is not the problem.
//
// An unknown mgmt address can never read as BindMgmt — with nothing to compare
// against, "we do not know" must not become "it is fine".
func ClassifyBind(addrs []string, mgmtAddr string) Bind {
	onMgmt := false
	for _, a := range addrs {
		ip := net.ParseIP(a)
		switch {
		case ip == nil:
			return BindExposed // unreadable: assume the worse of the two
		case ip.IsUnspecified():
			return BindExposed
		case mgmtAddr != "" && a == mgmtAddr:
			onMgmt = true
		case ip.IsLoopback():
			// Not exposure, but not a scrapeable bind either: it is what the agent
			// falls back to when it does not know the overlay address.
		default:
			return BindExposed
		}
	}
	if onMgmt {
		return BindMgmt
	}
	return BindNone
}
