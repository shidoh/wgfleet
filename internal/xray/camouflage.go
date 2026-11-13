package xray

// Camouflage switches a REALITY inbound to the node's own site (ADR-0039).
//
// The domain is accepted as SNI in both states, so a peer that was told the
// domain is never refused for it by a renamed list. Only the target moves: the
// local site while the agent's gate holds it open, the spec's fleet-default dest
// otherwise. A REALITY handshake completes through the target, and a third-party
// site refuses a foreign SNI, so peers send the domain only while the node reports
// the local target (the controller sees to that).
type Camouflage struct {
	Domain string // the node's own name
	Target string // the local site, "127.0.0.1:<port>"; "" keeps the spec's dest
}

// apply returns the target and server names an inbound renders with c applied.
func (c *Camouflage) apply(dest string, names []string) (string, []string) {
	if c == nil || c.Domain == "" {
		return dest, names
	}
	out := make([]string, 0, len(names)+1)
	inserted := false
	for _, n := range names {
		if n == c.Domain {
			continue
		}
		if n != "" && !inserted {
			out = append(out, c.Domain)
			inserted = true
		}
		out = append(out, n)
	}
	if !inserted {
		out = append(out, c.Domain)
	}
	if c.Target != "" {
		dest = c.Target
	}
	return dest, out
}
