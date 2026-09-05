package wg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Rendering for the CLIENT-facing leg: the interface the master raises, and the
// .conf an end user imports. Both live here because they are two halves of one
// agreement — change the obfuscation on one side and the other must move with it,
// which is much easier to keep true when the two renderers sit in one file.

// ClientKeepaliveSeconds is the PersistentKeepalive written into generated client
// configs. Clients sit behind NAT, so without a keepalive their mapping expires
// and the master can no longer reach them between their own transmissions.
const ClientKeepaliveSeconds = 25

// ClientInterfaceInput is everything needed to render the master's client-facing
// interface: the desired state plus the master's own private key, which stays on
// the node and never reaches the controller.
type ClientInterfaceInput struct {
	Spec       domain.ClientWGSpec
	PrivateKey string
}

// ClientConfigInput is everything needed to render ONE end user's .conf. Unlike
// the interface above this is rendered by the CONTROLLER, which holds the client's
// private key and therefore can hand out (or re-hand-out) a working config.
type ClientConfigInput struct {
	Spec            domain.ClientWGSpec
	Client          domain.WGClient
	ServerPublicKey string // the master's client-interface public key
	Endpoint        string // host:port the client dials
}

// RenderClientInterface renders the awg-quick config for the master's
// client-facing interface. Peers are end users: they dial us, so no peer carries
// an endpoint or a keepalive.
func RenderClientInterface(in ClientInterfaceInput) (string, error) {
	if in.PrivateKey == "" {
		return "", fmt.Errorf("wg render: client interface private key is required")
	}
	addr, err := clientInterfaceAddress(in.Spec)
	if err != nil {
		return "", err
	}
	// The master's own address inside the client-facing IPv6 prefix. It is the source
	// the ICMPv6 administratively-prohibited answer goes out from, and without it a
	// client handed "::/0" gets silence instead of a rejection — which is the whole
	// difference between blocking IPv6 and black-holing it.
	if v6, verr := interfaceV6Address(in.Spec); verr != nil {
		return "", verr
	} else if v6 != "" {
		addr += ", " + v6
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", in.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", addr)
	if in.Spec.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", in.Spec.ListenPort)
	}
	if in.Spec.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", in.Spec.MTU)
	}
	if in.Spec.AWG != nil {
		// Which validator applies is decided by what will CARRY this interface. The
		// <c>/<t> CPS tags are kernel-module features userspace WireGuard-Go cannot
		// parse, so on the userspace backend they are a config the node's own data
		// plane chokes on.
		if err := validateForBackend(*in.Spec.AWG, in.Spec.ResolvedBackend()); err != nil {
			return "", fmt.Errorf("wg render: client interface: %w", err)
		}
		writeAWG(&b, *in.Spec.AWG)
	}

	for _, p := range in.Spec.Clients {
		if p.PublicKey == "" {
			return "", fmt.Errorf("wg render: client %q has no public key", p.Name)
		}
		if p.Address == "" {
			return "", fmt.Errorf("wg render: client %q has no address", p.Name)
		}
		b.WriteString("\n[Peer]\n")
		if p.Name != "" {
			fmt.Fprintf(&b, "# %s\n", p.Name)
		}
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		// Omitted, never emitted empty: an empty value is a parse error to
		// amneziawg-tools, not "no preshared key".
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		allowed := p.Address
		// A peer is only reachable on the addresses listed here, so the rejection can
		// only be routed back to a client whose v6 address is one of them.
		if v6, verr := clientV6Address(in.Spec, p.Address); verr != nil {
			return "", verr
		} else if v6 != "" {
			allowed += ", " + v6
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	}
	return b.String(), nil
}

// interfaceV6Address returns the master's own address inside the client-facing
// IPv6 prefix, as "addr/64" so the interface owns the whole subnet route, or ""
// when the interface is IPv4-only.
func interfaceV6Address(spec domain.ClientWGSpec) (string, error) {
	if spec.IPv6Prefix == "" {
		return "", nil
	}
	prefix, err := netip.ParsePrefix(spec.IPv6Prefix)
	if err != nil {
		return "", fmt.Errorf("wg render: ipv6_prefix %q: %w", spec.IPv6Prefix, err)
	}
	gw, err := netip.ParseAddr(spec.ServerAddress)
	if err != nil {
		return "", fmt.Errorf("wg render: server address %q: %w", spec.ServerAddress, err)
	}
	v6, err := ClientV6For(prefix, gw)
	if err != nil {
		return "", fmt.Errorf("wg render: %w", err)
	}
	return v6.String() + "/64", nil
}

// RenderClientConfig renders one end user's .conf.
//
// The obfuscation is split by end on purpose: the SHARED params (S1-S4, H1-H4 and
// the 3.x block) must match the server interface byte for byte, while the LOCAL
// decoy (Jc/Jmin/Jmax, I1-I5) is this end's own and deliberately differs from the
// server's. Mixing the two up produces a config that looks right and never
// completes a handshake.
func RenderClientConfig(in ClientConfigInput) (string, error) {
	switch {
	case in.Client.PrivateKey == "":
		return "", fmt.Errorf("wg render: client %q has no private key", in.Client.Name)
	case in.Client.PublicKey == "":
		// The per-credential decoy is DERIVED from the public key, so without one
		// there is nothing stable to key on. The old code fell back to the master's
		// own profile, which is precisely the value a client must not send — the
		// whole point of the per-end split. Refuse instead of rendering a config
		// that looks right and correlates every client with the server.
		return "", fmt.Errorf("wg render: client %q has no public key", in.Client.Name)
	case in.Client.Address == "":
		return "", fmt.Errorf("wg render: client %q has no address", in.Client.Name)
	case in.ServerPublicKey == "":
		return "", fmt.Errorf("wg render: server public key is required")
	case in.Endpoint == "":
		return "", fmt.Errorf("wg render: endpoint is required")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", in.Client.PrivateKey)
	addr := in.Client.Address
	if v6, err := clientV6Address(in.Spec, in.Client.Address); err != nil {
		return "", err
	} else if v6 != "" {
		// Without a v6 address on its own interface the OS installs no ::/0 route, so
		// the "::/0" below would be inert and the device would go on preferring its
		// native IPv6 — the block would look configured and do nothing.
		addr += ", " + v6
	}
	fmt.Fprintf(&b, "Address = %s\n", addr)
	if dns := strings.Join(in.Spec.DNS, ", "); dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if in.Spec.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", in.Spec.MTU)
	}
	if in.Spec.AWG != nil {
		params := *in.Spec.AWG
		params.Local = clientDecoy(in.Spec, in.Client)
		// Unconditionally the USERSPACE rule, whatever the server backend is. The far
		// end of this leg is somebody's phone running WireGuard-Go, so a kernel-backed
		// interface may legitimately use <c>/<t> in its own decoy while the config it
		// hands out may not.
		if err := params.ValidateUserspace(); err != nil {
			return "", fmt.Errorf("wg render: client config: %w", err)
		}
		writeAWG(&b, params)
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", in.ServerPublicKey)
	if in.Client.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", in.Client.PresharedKey)
	}
	allowed := in.Spec.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "Endpoint = %s\n", in.Endpoint)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ClientKeepaliveFor(in.Spec.Keepalive, in.Client.ID))
	return b.String(), nil
}

// clientInterfaceAddress renders the master's own address as "ip/prefixlen",
// taking the prefix length from the client pool so the interface owns the whole
// subnet route.
func clientInterfaceAddress(s domain.ClientWGSpec) (string, error) {
	prefix, err := netip.ParsePrefix(s.AddressPool)
	if err != nil {
		return "", fmt.Errorf("wg render: parse client pool %q: %w", s.AddressPool, err)
	}
	addrStr := s.ServerAddress
	if addrStr == "" {
		first := prefix.Masked().Addr().Next()
		if !first.IsValid() || !prefix.Contains(first) {
			return "", fmt.Errorf("wg render: client pool %q too small for an interface address", s.AddressPool)
		}
		addrStr = first.String()
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return "", fmt.Errorf("wg render: parse client interface address %q: %w", addrStr, err)
	}
	return fmt.Sprintf("%s/%d", addr.String(), prefix.Bits()), nil
}

// validateForBackend applies the validator the data plane actually needs.
func validateForBackend(p domain.AWGParams, backend domain.ClientWGBackend) error {
	if backend == domain.ClientWGBackendUserspace {
		return p.ValidateUserspace()
	}
	return p.Validate()
}

// ClientKeepaliveFor resolves one credential's PersistentKeepalive.
//
// A band gives each credential its own value instead of one interval for the
// whole fleet. The gain is narrow and worth stating honestly: any keepalive is a
// beacon, and 25 seconds is what every WireGuard deployment on earth uses, so
// moving off it does not hide the beacon. What it removes is the CORRELATION —
// with one shared interval, an observer who picks out one of our clients has a
// handle that joins it to all the others.
//
// The draw is keyed by the credential ID and therefore stable: the config is
// re-rendered from scratch on every portal visit, and a value that moved between
// renders would hand the same person a different config each time they opened
// their own link. The ID is used rather than the name because renaming a
// credential must not change what it hands out.
func ClientKeepaliveFor(spec, clientID string) int {
	if spec == "" {
		// No operator range: derive one anyway. Returning the bare constant here is
		// what left every client in the fleet on the same 25-second beacon, because
		// client_awg.keepalive is unset in every shipped example — the correlation
		// this function exists to remove was removed only for operators who had
		// already thought about it.
		return KeepaliveFor("client|" + clientID)
	}
	lo, hi, isRange := strings.Cut(spec, "-")
	loN, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return ClientKeepaliveSeconds // validation rejects this at startup
	}
	if !isRange {
		return loN
	}
	hiN, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil || hiN <= loN {
		return loN
	}
	sum := sha256.Sum256([]byte("wgfleet|client-keepalive|" + clientID))
	return loN + int(binary.BigEndian.Uint32(sum[:4])%uint32(hiN-loN+1))
}

// clientDecoyPrefix separates this derivation from every other seeded stream in
// the fleet, so a client's decoy can never collide with a tunnel's parameters.
// Versioned: bumping it re-rolls every client's decoy on their next download.
const clientDecoyPrefix = "wgfleet|client-decoy|v1|"

// clientDecoy derives ONE client's own junk and signature profile.
//
// The local half of an AmneziaWG parameter set — Jc/Jmin/Jmax and I1-I5 — is what
// each end emits on its own; the peer ignores it. It therefore MAY differ per
// client, and where it may, it should: with one shared profile all of a master's
// clients emit identical junk and identical signature packets, so an observer who
// picks out one of them has a handle that joins it to the rest. Since the cover
// protocol (QUIC / STUN / DTLS) is itself drawn from this seed, clients of one
// master now imitate DIFFERENT protocols.
//
// Keyed on the credential's public key: unique per client, stable across renders
// (the config is re-rendered on every portal visit and must not change under the
// person holding the link), and already known to everyone who can see the
// interface — there is nothing secret here to protect.
//
// This changes nothing for a config already installed. The shared half is
// untouched, and a peer never validates the other end's decoy, so old and new
// configs interoperate with the same interface; a client picks up its own profile
// whenever it next re-imports.
func clientDecoy(spec domain.ClientWGSpec, c domain.WGClient) domain.AWGLocal {
	// No fallback: RenderClientConfig refuses a credential without a public key, so
	// the derivation always has its seed. The branch that used to be here read a
	// spec field nobody could reach and, failing that, handed the client the
	// SERVER's own decoy.
	// kernel=false: the far end is an app on WireGuard-Go, which cannot parse the
	// <c>/<t> CPS tags.
	local := DeriveAWGLocal(clientDecoyPrefix+c.PublicKey, false)
	if spec.AWG != nil {
		local = floorClientJunk(local, spec.AWG.Shared.S4)
	}
	return local
}

// floorClientJunk lifts a client's junk window clear of the shared S4.
//
// Deriving the local half directly skipped the floor DeriveAWGParamsForEnd
// applies to every other end, and the numbers made that a majority case rather
// than an edge one: DeriveAWGLocal draws Jmin from [8,40] against an S4 of
// [16,32], so most credentials sent junk short enough to underflow a receiver
// that strips S4 before length-checking it (domain.AWGJunkS4Margin).
//
// It shifts the whole window by a CONSTANT rather than clamping to the floor,
// because clamping maps every client below the floor onto the same Jmin — which
// would erase the per-credential junk profile this derivation exists to produce and
// make two people's traffic correlatable. A constant shift preserves the spread
// exactly.
//
// DeriveAWGParamsForEnd clamped for a while and now shifts too, for the same reason
// found the same way: measured across 2000 tunnels the clamp put 77% of ends on one
// value and left 17 distinct ones, turning Jmin into a function of the SHARED S4
// that is printed in every client config. This comment used to cite that clamp as
// the contrast; the two derivations now agree.
func floorClientJunk(local domain.AWGLocal, s4 int) domain.AWGLocal {
	if shift := s4 + domain.AWGJunkS4Margin - jminLow; shift > 0 {
		local.Jmin += shift
		local.Jmax += shift
	}
	return local
}

// clientV6Address returns one client's address inside the master's client-facing
// IPv6 prefix, or "" when the interface is IPv4-only.
//
// Derived from the client's IPv4 address rather than allocated: the store hands out
// exactly one address per credential, and two clients cannot collide in v6 without
// having already collided in v4, which the store's UNIQUE(master, address) makes
// impossible. One allocator, one place where "which address is this" is decided.
func clientV6Address(spec domain.ClientWGSpec, v4 string) (string, error) {
	if spec.IPv6Prefix == "" {
		return "", nil
	}
	prefix, err := netip.ParsePrefix(spec.IPv6Prefix)
	if err != nil {
		return "", fmt.Errorf("wg render: ipv6_prefix %q: %w", spec.IPv6Prefix, err)
	}
	host, err := netip.ParsePrefix(v4)
	if err != nil {
		return "", fmt.Errorf("wg render: client address %q: %w", v4, err)
	}
	v6, err := ClientV6For(prefix, host.Addr())
	if err != nil {
		return "", fmt.Errorf("wg render: %w", err)
	}
	return v6.String() + "/128", nil
}

// SyntheticPeerName is how the master's own path prober appears on the client
// interface. It is a real peer with a real address, and it is named so that an
// operator reading `awg show wg0` can tell it from an end user at a glance.
const SyntheticPeerName = "wgfleet-synthetic-probe"

// SyntheticClient builds the master's own client — the peer it uses to measure
// whether a packet entering the client interface comes back.
//
// It is an ordinary client in every respect, and that is the point: a prober that
// takes a shortcut measures the shortcut. It handshakes with the same obfuscation,
// gets the same MTU, traverses the same nftables chains and the same proxy as the
// people this fleet exists for. The only thing special about it is the address,
// which is reserved out of the allocator's reach (domain.SyntheticClientAddress).
//
// The keypair is generated and kept on the node. The controller never sees it and
// has no reason to: nobody has to be able to re-issue this config, and a private
// key that never leaves is one fewer thing to leak.
func SyntheticClient(address, privateKey, publicKey string) domain.WGClient {
	return domain.WGClient{
		ID:         SyntheticPeerName,
		Name:       SyntheticPeerName,
		Address:    address,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Enabled:    true,
	}
}

// WithSyntheticPeer returns spec with the prober added to its peer list. A spec
// that already carries it is returned unchanged, so the function is safe to apply
// on every pass.
//
// The peer is added by the AGENT rather than sent by the controller because the
// key is node-local. That has a consequence worth stating: the live interface then
// carries one peer the controller did not describe, so anything comparing live
// peers against the spec must compare against THIS spec, not the one off the wire.
func WithSyntheticPeer(spec domain.ClientWGSpec, peer domain.WGClient) domain.ClientWGSpec {
	if peer.PublicKey == "" || peer.Address == "" {
		return spec
	}
	for _, c := range spec.Clients {
		if c.PublicKey == peer.PublicKey {
			return spec
		}
	}
	out := spec
	out.Clients = append(append([]domain.WGClientPeer(nil), spec.Clients...), domain.WGClientPeer{
		Name:      peer.Name,
		PublicKey: peer.PublicKey,
		Address:   peer.Address,
	})
	return out
}

// SyntheticSetConfInput is what the master's own prober needs to configure its
// interface with `awg setconf`.
type SyntheticSetConfInput struct {
	Spec            domain.ClientWGSpec
	Client          domain.WGClient
	ServerPublicKey string
	Endpoint        string // where the prober dials the master's client interface
	ListenPort      int    // the prober's own source port; 0 ⇒ kernel picks
}

// RenderSyntheticSetConf renders the prober's interface in `awg setconf` form.
//
// It is a different shape from RenderClientConfig, not a different configuration:
// setconf understands the device (keys, obfuscation, peers) and rejects the lines
// awg-quick owns (Address, DNS, MTU), which are applied with `ip` instead. The
// split exists because the prober's interface has to be created in ONE network
// namespace and moved into another — WireGuard keeps its UDP socket in the
// namespace where the device was created, which is what lets the prober dial the
// master's own loopback while its decrypted side lives somewhere isolated — and
// awg-quick has no way to express that.
//
// The obfuscation is copied verbatim from the client spec. A prober configured
// with anything else would be measuring a tunnel no real client has.
func RenderSyntheticSetConf(in SyntheticSetConfInput) (string, error) {
	switch {
	case in.Client.PrivateKey == "":
		return "", fmt.Errorf("wg render: synthetic client has no private key")
	case in.ServerPublicKey == "":
		return "", fmt.Errorf("wg render: server public key is required")
	case in.Endpoint == "":
		return "", fmt.Errorf("wg render: endpoint is required")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", in.Client.PrivateKey)
	if in.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", in.ListenPort)
	}
	if in.Spec.AWG != nil {
		params := *in.Spec.AWG
		// The same per-credential decoy an end user gets: the junk profile is derived
		// from the credential, so a prober using the master's profile would present a
		// fingerprint no client presents.
		params.Local = clientDecoy(in.Spec, in.Client)
		writeAWG(&b, params)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", in.ServerPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", in.Endpoint)
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ClientKeepaliveSeconds)
	return b.String(), nil
}

// InterfaceSection returns the [Interface] half of a rendered client config —
// everything before the first [Peer].
//
// It exists so a caller can ask the one question that decides whether a change
// can be applied without recreating the device: did anything about the INTERFACE
// move? Addresses, the listen port, the MTU and the AmneziaWG obfuscation
// parameters are all set when the device is created and cannot be changed on a
// live one. Peers can.
func InterfaceSection(cfg string) string {
	if i := strings.Index(cfg, "[Peer]"); i >= 0 {
		return strings.TrimSpace(cfg[:i])
	}
	return strings.TrimSpace(cfg)
}
