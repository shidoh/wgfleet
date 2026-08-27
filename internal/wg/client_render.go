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
		fmt.Fprintf(&b, "AllowedIPs = %s\n", p.Address)
	}
	return b.String(), nil
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
	fmt.Fprintf(&b, "Address = %s\n", in.Client.Address)
	if dns := strings.Join(in.Spec.DNS, ", "); dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if in.Spec.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", in.Spec.MTU)
	}
	if in.Spec.AWG != nil {
		params := *in.Spec.AWG
		if in.Spec.ClientAWGLocal != nil {
			params.Local = *in.Spec.ClientAWGLocal
		}
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
		return ClientKeepaliveSeconds
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
