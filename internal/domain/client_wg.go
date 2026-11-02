package domain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ClientWGInterface is the name of the master's client-facing AmneziaWG
// interface, which the agent raises and owns.
const ClientWGInterface = "wg0"

// ClientWGSpec is the master-side desired state for the CLIENT-FACING AmneziaWG
// interface — the leg end users dial. The controller owns the credentials, the
// agent owns the interface (see the design doc, §3).
//
// The split from WGServerSpec (the master↔exit leg) is deliberate. That one
// describes a fleet-internal tunnel whose peers are exits; this one fronts MANY
// end users whose credentials are issued and revoked through the controller UI,
// exactly as ClientVLESSServerSpec does for the VLESS leg.
//
// It carries NO client private keys. The controller renders the .conf and the QR
// itself, so a client's private key never has a reason to reach the node — the
// peer view (WGClientPeer) is structurally incapable of holding one.
type ClientWGSpec struct {
	// ListenPort is the UDP port clients dial, world-facing.
	ListenPort int
	// AddressPool is the client subnet (CIDR). Addresses are handed out from it by
	// AllocateClientAddress; pools of different masters must not overlap, which
	// config validation enforces (ADR-0027 makes several masters real).
	AddressPool string
	// ServerAddress is the master's own address inside the pool (no mask), never
	// handed to a client.
	ServerAddress string
	// MTU of the client interface.
	MTU int
	// DNS is what the generated client configs point at (the master's blocky).
	DNS []string
	// AllowedIPs is what the generated client configs route into the tunnel. The
	// data plane is IPv4-only, so "::/0" is rejected rather than passed through:
	// it routes IPv6 into a dead tunnel and stalls dual-stack clients.
	AllowedIPs []string
	// AWG is the obfuscation for this interface (server end); nil ⇒ vanilla WG.
	AWG *AWGParams
	// Keepalive DELIBERATELY does not cross the wire — there is no field for it in
	// ClientWGSpec's proto message, and there should not be. The node renders the
	// interface; the CONTROLLER renders client configs, and this value only ever
	// appears in one of those. A round-trip through the wire therefore drops it,
	// which is correct and is asserted by TestClientWGSpecKeepaliveStaysOffTheWire.
	//
	// Keepalive is what generated client configs put in PersistentKeepalive.
	// Empty ⇒ the 25-second default. A bare number pins one value for everybody;
	// a "min-max" band gives each credential its OWN stable value, which is the
	// only shape available here — PersistentKeepalive is a static line in a file
	// the client app cannot redraw, unlike the AmneziaWG 3.x timers.
	Keepalive string
	// Backend selects what actually carries the interface: the kernel module (as
	// on the exits) or the userspace amneziawg-go daemon. Empty ⇒ kernel.
	Backend ClientWGBackend
	// IPv6Prefix is the master's client-facing IPv6 /64 (RFC 4193 unique-local,
	// derived from AddressPool by wg.ClientULAFor). Empty ⇒ the interface is
	// IPv4-only, which is the default.
	//
	// It is inseparable from AllowedIPs carrying "::/0": the prefix is what lets the
	// master address itself in v6 and answer a forwarded v6 packet with ICMPv6
	// administratively-prohibited, so a dual-stack client falls back to IPv4 at once
	// instead of stalling. Validate() refuses "::/0" without it, because that pairing
	// is the IPv6 black hole — a v6 default route into a data plane that drops it silently.
	IPv6Prefix string
	// Clients are the ENABLED peers only. A muted credential is absent here, so a
	// re-render drops it from the interface while the user's config stays valid.
	Clients []WGClientPeer
}

// ClientWGBackend selects the data-plane implementation for the client leg.
type ClientWGBackend string

const (
	// ClientWGBackendKernel runs the interface on the AmneziaWG kernel module,
	// like every exit. Needs a 3.x module on the master for AWG 3.x.
	ClientWGBackendKernel ClientWGBackend = "kernel"
	// ClientWGBackendUserspace runs it on the amneziawg-go daemon. Slower, but
	// independent of the host's kernel module generation.
	ClientWGBackendUserspace ClientWGBackend = "userspace"
)

// WGClient is one issued end-user credential as the CONTROLLER holds it. Unlike
// VLESSClient, it contains a secret: the client's private key, which the
// controller generates so it can re-render the config and the QR at any time
// (an operator decision). It is a controller secret —
// redacted in plan output, 0600 at rest, and carried in the age backup.
type WGClient struct {
	// ID is the stable identity of the credential. Renaming must not reissue keys
	// nor break a portal link, so identity is separate from the label (ADR-0028).
	ID string
	// Name is the operator-facing label, unique per master.
	Name string
	// Address is the client's address inside the master's pool, with mask.
	Address string
	// PublicKey is what the interface peers against.
	PublicKey string
	// PrivateKey is the client's secret. NEVER put it on the wire.
	PrivateKey string
	// PresharedKey is the optional symmetric key shared by both ends. Empty when
	// unused; carried for credentials imported in earlier versions, which may have one.
	PresharedKey string
	// Enabled false mutes the credential: the peer leaves the interface, the
	// config the user holds stays valid.
	Enabled   bool
	CreatedAt time.Time
	// LegacyLinkRetired is set, irreversibly, the first time the credential joins
	// a device. From then on its own portal link (/c/{id}) is dead for good: a
	// credential detached from a device — or whose device was deleted or rotated —
	// must not quietly come back to life through the ID it was once reachable by.
	LegacyLinkRetired bool
}

// WGClientPeer is the node-facing view of a credential: everything the agent
// needs to render a [Peer] block and nothing else. This type is the boundary
// that keeps client private keys inside the controller.
type WGClientPeer struct {
	Name         string
	PublicKey    string
	Address      string
	PresharedKey string
}

// PeersOf projects issued credentials onto the node-facing peer view, dropping
// muted ones. It is the ONLY way a WGClient becomes wire-bound data, so the
// private key cannot leak by someone adding a field in the wrong struct.
func PeersOf(clients []WGClient) []WGClientPeer {
	peers := make([]WGClientPeer, 0, len(clients))
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		peers = append(peers, WGClientPeer{
			Name:         c.Name,
			PublicKey:    c.PublicKey,
			Address:      c.Address,
			PresharedKey: c.PresharedKey,
		})
	}
	return peers
}

// ResolvedBackend returns the data-plane backend, defaulting an unset value to
// the kernel module (what the fleet already runs everywhere else).
func (s ClientWGSpec) ResolvedBackend() ClientWGBackend {
	if s.Backend == "" {
		return ClientWGBackendKernel
	}
	return s.Backend
}

// Validate checks the client-facing interface invariants. It runs from
// NodeSpec.Validate when the master carries a client WG spec.
func (s ClientWGSpec) Validate() error {
	var errs []error

	if s.ListenPort <= 0 || s.ListenPort > 65535 {
		errs = append(errs, fmt.Errorf("listen port %d out of range", s.ListenPort))
	}
	switch s.ResolvedBackend() {
	case ClientWGBackendKernel, ClientWGBackendUserspace:
	default:
		errs = append(errs, fmt.Errorf("unknown backend %q", s.Backend))
	}
	errs = append(errs, validateClientAllowedIPs(s.AllowedIPs, s.IPv6Prefix)...)
	if s.IPv6Prefix != "" {
		switch p, err := netip.ParsePrefix(s.IPv6Prefix); {
		case err != nil:
			errs = append(errs, fmt.Errorf("ipv6_prefix %q: %w", s.IPv6Prefix, err))
		case !p.Addr().Is6():
			errs = append(errs, fmt.Errorf("ipv6_prefix %q is not an IPv6 prefix", s.IPv6Prefix))
		case p.Bits() != 64:
			errs = append(errs, fmt.Errorf("ipv6_prefix %q must be a /64", s.IPv6Prefix))
		case p.Addr().As16()[0] != 0xfd:
			// Anything but unique-local would be an address range we do not own; a
			// client routing it into the tunnel would lose the real one.
			errs = append(errs, fmt.Errorf("ipv6_prefix %q is not inside fd00::/8 (RFC 4193 unique-local)", s.IPv6Prefix))
		}
	}
	if err := ValidateClientKeepalive(s.Keepalive); err != nil {
		errs = append(errs, err)
	}

	pool, err := netip.ParsePrefix(s.AddressPool)
	if err != nil {
		// Without a pool there is nothing to check addresses against, so report the
		// pool and stop: the per-client errors would all be noise from one cause.
		errs = append(errs, fmt.Errorf("address pool %q: %w", s.AddressPool, err))
		return errors.Join(errs...)
	}

	server, err := netip.ParseAddr(s.ServerAddress)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("server address %q: %w", s.ServerAddress, err))
	case !pool.Contains(server):
		errs = append(errs, fmt.Errorf("server address %s is outside the pool %s", server, pool))
	}

	seenName := make(map[string]struct{}, len(s.Clients))
	seenAddr := make(map[netip.Addr]struct{}, len(s.Clients))
	for i, c := range s.Clients {
		errs = append(errs, validateClientPeer(i, c, pool, server, seenName, seenAddr)...)
	}
	return errors.Join(errs...)
}

// validateClientPeer checks one peer against the interface's pool and the
// addresses/names already seen, recording its own as it goes.
func validateClientPeer(i int, c WGClientPeer, pool netip.Prefix, server netip.Addr,
	seenName map[string]struct{}, seenAddr map[netip.Addr]struct{}) []error {
	var errs []error

	switch {
	case c.Name == "":
		errs = append(errs, fmt.Errorf("client[%d]: missing name", i))
	case !ValidClientName(c.Name):
		// The name is written verbatim into the interface config as a comment. A
		// newline in it does not corrupt the file, it EXTENDS it — an imported
		// credential called "laptop\n[Peer]\nAllowedIPs = 0.0.0.0/0" adds an
		// attacker's peer to the master's live client interface. Credentials
		// imported in earlier versions arrived from outside the web layer, so the
		// charset is enforced here rather than only there.
		errs = append(errs, fmt.Errorf("client[%d] (%q): name must be 1-%d chars of letters, digits, '-', '_' or '.'",
			i, c.Name, MaxClientNameLen))
	default:
		if _, dup := seenName[c.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate client name %q", c.Name))
		}
		seenName[c.Name] = struct{}{}
	}

	if !ValidWireGuardKey(c.PublicKey) {
		errs = append(errs, fmt.Errorf("client[%d] (%s): malformed public key", i, c.Name))
	}
	// A preshared key is optional, but a present one is rendered verbatim next to
	// the public key and gets the same scrutiny.
	if c.PresharedKey != "" && !ValidWireGuardKey(c.PresharedKey) {
		errs = append(errs, fmt.Errorf("client[%d] (%s): malformed preshared key", i, c.Name))
	}

	addr, err := netip.ParsePrefix(c.Address)
	if err != nil {
		errs = append(errs, fmt.Errorf("client[%d] (%s): address %q: %w", i, c.Name, c.Address, err))
		return errs
	}
	ip := addr.Addr()
	// A host route, not a subnet. The address is written verbatim as this peer's
	// AllowedIPs on the interface, so a wider mask routes traffic that belongs to
	// other people at this one credential: "10.80.0.5/24" hands it the whole pool,
	// and "10.80.0.0/24" hands it everybody. Both producers emit /32 today; this is
	// the last check before the render, and the dedup below cannot catch it because
	// it keys on the base address alone.
	if addr.Bits() != ip.BitLen() {
		errs = append(errs, fmt.Errorf("client[%d] (%s): address %s must be a single host (/%d), not a subnet",
			i, c.Name, c.Address, ip.BitLen()))
	}
	switch {
	case !pool.Contains(ip):
		errs = append(errs, fmt.Errorf("client[%d] (%s): address %s is outside the pool %s", i, c.Name, ip, pool))
	case ip == server:
		errs = append(errs, fmt.Errorf("client[%d] (%s): address %s collides with the server address", i, c.Name, ip))
	}
	if _, dup := seenAddr[ip]; dup {
		errs = append(errs, fmt.Errorf("duplicate client address %s", ip))
	}
	seenAddr[ip] = struct{}{}
	return errs
}

// validateClientAllowedIPs rejects a malformed prefix and, specifically, an IPv6
// default route that nothing is prepared to answer.
//
// "::/0" on its own is a black hole: the data plane is IPv4-only, so a dual-stack
// client abandons its own working v6 path for one that drops silently, and pages
// stall in a way that reads as an MTU fault for days. Paired with ipv6Prefix it is
// the opposite — the master addresses itself in that prefix and answers forwarded
// v6 with ICMPv6 administratively-prohibited, so the client falls back to IPv4 in
// milliseconds. The route is not the hazard; the route without the answer is.
func validateClientAllowedIPs(allowed []string, ipv6Prefix string) []error {
	var errs []error
	for _, a := range allowed {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			errs = append(errs, fmt.Errorf("allowed IPs %q: %w", a, err))
			continue
		}
		if p.Addr().Is6() && p.Bits() == 0 && ipv6Prefix == "" {
			errs = append(errs, fmt.Errorf("allowed IPs %q: an IPv6 default route needs an ipv6_prefix for the master to answer from, "+
				"or it black-holes dual-stack clients", a))
		}
	}
	return errs
}

// MaxClientNameLen bounds the operator-facing label.
const MaxClientNameLen = 64

// ValidClientName reports whether a label is safe to render into a config file
// and to display. Deliberately narrow: letters, digits and the three separators
// people actually use in device names.
func ValidClientName(name string) bool {
	if name == "" || len(name) > MaxClientNameLen {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// ValidWireGuardKey reports whether s is a base64-encoded 32-byte key. The domain
// package cannot use internal/wg for this (that package imports domain), and the
// check is small enough that duplicating it beats inverting the dependency.
func ValidWireGuardKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// Keepalive bounds for generated client configs. The ceiling is the one that
// matters: clients sit behind NAT, and a mapping that expires before the next
// keepalive leaves the master unable to reach the client until the client speaks
// first. Common NAT UDP timeouts start at 30 seconds, which is why WireGuard's
// own documented value is 25. The floor only exists to stop a typo turning every
// phone on a fleet into a one-second beacon.
const (
	MinClientKeepalive = 5
	MaxClientKeepalive = 120
)

// ValidateClientKeepalive accepts "", a bare number, or "min-max" with both ends in
// range and min <= max.
func ValidateClientKeepalive(v string) error {
	if v == "" {
		return nil
	}
	lo, hi, isRange := strings.Cut(v, "-")
	loN, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil || loN < MinClientKeepalive || loN > MaxClientKeepalive {
		return fmt.Errorf("keepalive %q: want a number or \"min-max\" within %d-%d seconds",
			v, MinClientKeepalive, MaxClientKeepalive)
	}
	if !isRange {
		return nil
	}
	hiN, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil || hiN < MinClientKeepalive || hiN > MaxClientKeepalive {
		return fmt.Errorf("keepalive %q: want a number or \"min-max\" within %d-%d seconds",
			v, MinClientKeepalive, MaxClientKeepalive)
	}
	if hiN < loN {
		return fmt.Errorf("keepalive range %q is inverted (max < min)", v)
	}
	return nil
}
