package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// LifelineInterface is the fixed name of the reserve client-facing AmneziaWG
// interface an exit carries. It is a constant, not a manifest field, because
// exactly one lifeline can exist per exit and nothing benefits from making its
// name configurable — unlike WGServer's interface, which fronts a fleet-internal
// tunnel whose naming already varies by role.
const LifelineInterface = "awgl0"

// LifelineSpec is the desired state of an exit's lifeline interface: the same
// client population as the master's real ClientWG interface, kept warm on an
// exit so the fleet survives the master itself being blocked or unreachable
// (the "flot sam perezhivaet blokirovku" promise — see product.md boundary 3).
//
// It embeds ClientWGSpec rather than duplicating its fields: a lifeline is
// structurally the same kind of interface as the master's client leg (same
// listen port shape, same AWG obfuscation, same peer view), just rendered on a
// different node with a shifted address pool so the two never collide if a
// client ever sees both at once. Egress is lifeline-specific: unlike the
// master, which only forwards into mihomo, the lifeline interface egresses
// traffic itself, exactly as an exit's normal WGServer does.
type LifelineSpec struct {
	ClientWGSpec
	// Egress selects how the lifeline interface releases traffic to the
	// internet, mirroring NodeSpec.Egress for the exit's primary interface.
	Egress EgressMethod
}

// LifelineAddress shifts a client's address from the master's client pool into
// the lifeline pool, preserving the host offset: "10.80.0.7/24" in a
// 10.80.0.0/24 master pool becomes "10.98.77.7/32" in a 10.98.77.0/24 lifeline
// pool. Deriving the lifeline address this way — rather than allocating it
// independently — needs no separate allocation state on the exit and keeps a
// given client's lifeline peer trivially reproducible from its master-side
// record.
//
// The result is always a /32 HOST prefix, whatever masks the two pools carry.
// The pools are only a base to measure the offset from and a bound to check it
// against; they are not the peer's mask. This address is written verbatim as the
// peer's AllowedIPs (see wg/client_render.go and validateClientPeer), so a pool
// mask here would hand one credential everybody else's traffic — "10.98.77.5/24"
// claims the whole lifeline pool — and ClientWGSpec.Validate, promoted onto
// LifelineSpec through the embedding, refuses it outright. The master's own
// allocator emits /32 for the same reason.
//
// addr may carry a mask (as WGClient.Address does) or be bare; either way its
// host bits, relative to masterPool, are what get carried over. Both pools
// must be IPv4 — the data plane is IPv4-only (see ClientWGSpec.AllowedIPs),
// so there is no IPv6 case to shift.
func LifelineAddress(addr string, masterPool, lifelinePool netip.Prefix) (string, error) {
	ip, err := parseAddrMaybeMasked(addr)
	if err != nil {
		return "", fmt.Errorf("lifeline address %q: %w", addr, err)
	}
	if !ip.Is4() || !masterPool.Addr().Is4() || !lifelinePool.Addr().Is4() {
		return "", fmt.Errorf("lifeline address %q: only IPv4 is supported", addr)
	}
	if !masterPool.Contains(ip) {
		return "", fmt.Errorf("lifeline address %s is outside the master pool %s", ip, masterPool)
	}

	offset := ipToUint32(ip) - ipToUint32(masterPool.Masked().Addr())
	shifted := uint32ToIP(ipToUint32(lifelinePool.Masked().Addr()) + offset)
	if !lifelinePool.Contains(shifted) {
		return "", fmt.Errorf("lifeline address for %s (offset %d) falls outside the lifeline pool %s",
			addr, offset, lifelinePool)
	}
	return netip.PrefixFrom(shifted, shifted.BitLen()).String(), nil
}

// parseAddrMaybeMasked accepts either a bare address or a masked prefix and
// returns the address alone — WGClient.Address is always masked, but callers
// (including tests) also pass bare pool/server addresses.
func parseAddrMaybeMasked(s string) (netip.Addr, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// ipToUint32 and uint32ToIP convert between an IPv4 netip.Addr and its
// big-endian uint32 form, the arithmetic LifelineAddress needs to shift a host
// offset from one pool into another.
func ipToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToIP(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// lifelinePSKDomain namespaces the HMAC message so a lifeline PSK can never
// collide with a PSK derived for some other purpose from the same key.
const lifelinePSKDomain = "wgfleet|lifeline|"

// LifelinePSK derives the preshared key a lifeline peer uses on a given exit
// from the client's real (master-side) preshared key. It is HMAC-SHA256, keyed
// with the decoded master PSK, over "wgfleet|lifeline|<exitID>", base64-encoded
// — 32 bytes, a valid WireGuard PSK.
//
// Deriving rather than reusing the master's PSK verbatim means a lifeline PSK
// leaking from one exit (or the exit being malicious) does not hand over the
// credential that authenticates against the master's real client interface,
// and a different exitID yields a different PSK per exit — so exits cannot
// impersonate each other's lifeline peers either.
//
// An empty psk (the common case: most credentials have none) yields an empty
// result rather than an error, matching WGClient.PresharedKey's own "" ⇒
// unused convention.
func LifelinePSK(psk, exitID string) (string, error) {
	if psk == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		return "", fmt.Errorf("lifeline psk: %w", err)
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(lifelinePSKDomain + exitID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// LifelineSkip names one credential that could not be projected onto a lifeline,
// and why. It exists so the caller can report the skip against the credential it
// happened to — a joined error would say the same words while losing the ID the
// log has to be keyed on, and would tempt the caller back into failing the whole
// render.
type LifelineSkip struct {
	ID     string
	Name   string
	Reason error
}

// LifelinePeersOf projects issued credentials onto the lifeline interface's
// peer view for one exit: the same enabled/muted rule as PeersOf, plus the
// address shift (LifelineAddress) and the per-exit PSK derivation
// (LifelinePSK). Like PeersOf, this is the only path from a WGClient to
// wire-bound data, so the private key stays structurally unreachable here too.
//
// A credential that cannot be projected is SKIPPED and returned in the second
// result, never allowed to fail the batch. The failure it would otherwise cause
// is out of all proportion to its cause: one address left outside the master pool
// by a pool the operator narrowed — a manifest edit, not an outage — would fail
// the exit's whole NodeSpec, and the agent refuses a spec entire, so nftables,
// routing, the exit's own AWG server and its egress would all stop converging
// because ONE person's reserve peer could not be computed. Every other client
// keeps its lifeline peer; the caller says out loud which one it dropped.
func LifelinePeersOf(clients []WGClient, masterPool, lifelinePool netip.Prefix, exitID string) ([]WGClientPeer, []LifelineSkip) {
	peers := make([]WGClientPeer, 0, len(clients))
	var skipped []LifelineSkip
	skip := func(c WGClient, err error) {
		skipped = append(skipped, LifelineSkip{ID: c.ID, Name: c.Name, Reason: err})
	}
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		addr, err := LifelineAddress(c.Address, masterPool, lifelinePool)
		if err != nil {
			skip(c, err)
			continue
		}
		psk, err := LifelinePSK(c.PresharedKey, exitID)
		if err != nil {
			skip(c, err)
			continue
		}
		peers = append(peers, WGClientPeer{
			Name:         c.Name,
			PublicKey:    c.PublicKey,
			Address:      addr,
			PresharedKey: psk,
		})
	}
	return peers, skipped
}
