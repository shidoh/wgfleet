package domain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ClientWGSpec is the master-side desired state for the CLIENT-FACING AmneziaWG
// interface — the leg end users dial. It replaces wg-easy: the controller owns
// the credentials, the agent owns the interface (see the design doc, §3).
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
	// it routes IPv6 into a dead tunnel and stalls dual-stack clients (an earlier finding,
	// which we already paid for once through wg-easy's default).
	AllowedIPs []string
	// AWG is the obfuscation for this interface (server end); nil ⇒ vanilla WG.
	AWG *AWGParams
	// ClientAWGLocal is the per-end junk/signature profile the CLIENT must emit.
	// AWG allows these to differ per end, so where they may differ they MUST.
	// nil ⇒ fall back to AWG.Local.
	ClientAWGLocal *AWGLocal
	// Backend selects what actually carries the interface: the kernel module (as
	// on the exits) or the userspace amneziawg-go daemon. Empty ⇒ kernel.
	Backend ClientWGBackend
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
// (the operator chose parity with wg-easy's UX). It is a controller secret —
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
	// unused; carried because wg-easy issued them and the import must be lossless.
	PresharedKey string
	// Enabled false mutes the credential: the peer leaves the interface, the
	// config the user holds stays valid.
	Enabled   bool
	CreatedAt time.Time
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
	errs = append(errs, validateClientAllowedIPs(s.AllowedIPs)...)

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
		// attacker's peer to the master's live client interface. Names arrive from
		// wg-easy's database on import, which is exactly the source we no longer
		// trust to have a stable shape, so the charset is enforced here rather than
		// only at the web layer.
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

// validateClientAllowedIPs rejects a malformed prefix and, specifically, the IPv6
// default route: the data plane is IPv4-only and "::/0" black-holes dual-stack
// clients.
func validateClientAllowedIPs(allowed []string) []error {
	var errs []error
	for _, a := range allowed {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			errs = append(errs, fmt.Errorf("allowed IPs %q: %w", a, err))
			continue
		}
		if p.Addr().Is6() && p.Bits() == 0 {
			errs = append(errs, fmt.Errorf("allowed IPs %q: the data plane is IPv4-only, an IPv6 default route black-holes clients", a))
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
// Exported because the importer must apply the same rule to values it copies out
// of wg-easy's database before they can reach a rendered config.
func ValidWireGuardKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}
