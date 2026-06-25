package metrics

import (
	"strconv"
	"strings"
)

// wgPeer is one peer line from `wg show <iface> dump` / `awg show <iface> dump`.
// Only the fields we export are kept.
type wgPeer struct {
	publicKey       string // base64 peer public key
	latestHandshake int64  // unix epoch seconds; 0 means "never"
	rxBytes         float64
	txBytes         float64
}

// parseWGDump parses the canonical `wg show <iface> dump` TSV. The FIRST line is
// the interface itself (private-key, public-key, listen-port, fwmark) and is
// skipped; every subsequent line is a peer:
//
//	public-key  preshared-key  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
//
// Malformed lines (too few fields, unparseable numbers) are skipped rather than
// failing the whole parse — a single odd line must not blank the iface's series.
func parseWGDump(out string) []wgPeer {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		return nil
	}
	var peers []wgPeer
	for _, line := range lines[1:] { // line 0 is the interface, not a peer
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		pub := strings.TrimSpace(fields[0])
		if pub == "" || pub == "(none)" {
			continue
		}
		hs, err := strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64)
		if err != nil {
			continue
		}
		rx, err := strconv.ParseFloat(strings.TrimSpace(fields[5]), 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseFloat(strings.TrimSpace(fields[6]), 64)
		if err != nil {
			continue
		}
		peers = append(peers, wgPeer{
			publicKey:       pub,
			latestHandshake: hs,
			rxBytes:         rx,
			txBytes:         tx,
		})
	}
	return peers
}

// shortPeerID derives a stable, low-cardinality label from a peer's base64
// public key: the first 8 chars. Enough to disambiguate peers on one node while
// keeping the raw key (a credential-adjacent identifier) out of metric labels.
func shortPeerID(publicKey string) string {
	const idLen = 8
	if len(publicKey) <= idLen {
		return publicKey
	}
	return publicKey[:idLen]
}
