package domain

// MasterTransport is the obfuscated transport carried over a master↔exit link
// (ADR-0025). An exit may run several at once (warm); the master places exactly
// one — the active transport — in its load-balance group at a time, and the
// operator switches the active one manually.
type MasterTransport string

const (
	// TransportAWG is kernel AmneziaWG: awg-quick awg0 on the exit, a mihomo
	// wireguard+amnezia-wg-option proxy on the master. The original and default
	// transport.
	TransportAWG MasterTransport = "awg"
	// TransportRealityXHTTP is VLESS+REALITY carried over XHTTP (packet-up): an
	// xray-core inbound on the exit, a mihomo vless+reality proxy on the master.
	// It camouflages the link as ordinary TLS to a real foreign site and splits
	// the upload into many short POSTs, surviving the foreign-datacenter
	// volume-freeze that kills AWG on some censored paths (ADR-0025).
	TransportRealityXHTTP MasterTransport = "reality-xhttp"
)

// DefaultMasterTransport is assumed when none is specified — the pre-ADR-0025
// behavior (AWG only), so an empty discriminator and old wire/spec data keep
// working unchanged.
const DefaultMasterTransport = TransportAWG

// Valid reports whether t is a known transport.
func (t MasterTransport) Valid() bool {
	switch t {
	case TransportAWG, TransportRealityXHTTP:
		return true
	default:
		return false
	}
}

func (t MasterTransport) String() string { return string(t) }

// OrDefault returns t when set, else DefaultMasterTransport. Lets a zero
// discriminator (old data, AWG-only exits) behave as AWG without special-casing
// at every call site.
func (t MasterTransport) OrDefault() MasterTransport {
	if t == "" {
		return DefaultMasterTransport
	}
	return t
}
