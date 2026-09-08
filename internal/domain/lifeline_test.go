package domain

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q) failed: %v", s, err)
	}
	return p
}

// LifelineAddress must preserve the host offset when shifting a client address
// from the master's pool into the lifeline pool, and hand back a HOST prefix: the
// result becomes the peer's AllowedIPs verbatim, so a pool mask would give one
// credential the whole pool.
func TestLifelineAddressSameOffset(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")

	got, err := LifelineAddress("10.80.0.7/24", masterPool, lifelinePool)
	if err != nil {
		t.Fatalf("LifelineAddress() = %v, want nil error", err)
	}
	if got != "10.98.77.7/32" {
		t.Fatalf("LifelineAddress() = %q, want %q", got, "10.98.77.7/32")
	}
}

// The pools may carry different masks; only the host offset matters, and neither
// pool's mask reaches the result — it is always a /32.
func TestLifelineAddressDifferentMasks(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/28") // small enough to still fit .0/.7? use .0-.15 offsets

	got, err := LifelineAddress("10.80.0.3/24", masterPool, lifelinePool)
	if err != nil {
		t.Fatalf("LifelineAddress() = %v, want nil error", err)
	}
	if got != "10.98.77.3/32" {
		t.Fatalf("LifelineAddress() = %q, want %q", got, "10.98.77.3/32")
	}
}

// A bare address (no mask) must be accepted exactly like a masked one.
func TestLifelineAddressBareAddress(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")

	got, err := LifelineAddress("10.80.0.7", masterPool, lifelinePool)
	if err != nil {
		t.Fatalf("LifelineAddress() = %v, want nil error", err)
	}
	if got != "10.98.77.7/32" {
		t.Fatalf("LifelineAddress() = %q, want %q", got, "10.98.77.7/32")
	}
}

// An address outside the master pool cannot be shifted at all.
func TestLifelineAddressOutsideMasterPool(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")

	_, err := LifelineAddress("10.90.0.7/24", masterPool, lifelinePool)
	if err == nil {
		t.Fatal("LifelineAddress() = nil error, want an error for an address outside the master pool")
	}
}

// An offset that lands outside the lifeline pool (e.g. the lifeline pool is
// smaller than the master pool) must also fail, not wrap around.
func TestLifelineAddressOffsetBeyondLifelinePool(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/28") // only .0-.15 valid offsets

	_, err := LifelineAddress("10.80.0.20/24", masterPool, lifelinePool)
	if err == nil {
		t.Fatal("LifelineAddress() = nil error, want an error when the offset overflows the lifeline pool")
	}
}

// Only IPv4 pools/addresses are supported; the data plane is IPv4-only.
func TestLifelineAddressRejectsIPv6(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")

	_, err := LifelineAddress("fd00::7/64", masterPool, lifelinePool)
	if err == nil {
		t.Fatal("LifelineAddress() = nil error, want an error for an IPv6 address")
	}
}

// LifelinePSK must be a deterministic function of (psk, exitID).
func TestLifelinePSKDeterministic(t *testing.T) {
	psk := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got1, err := LifelinePSK(psk, "exit-a")
	if err != nil {
		t.Fatalf("LifelinePSK() = %v, want nil error", err)
	}
	got2, err := LifelinePSK(psk, "exit-a")
	if err != nil {
		t.Fatalf("LifelinePSK() = %v, want nil error", err)
	}
	if got1 != got2 {
		t.Fatalf("LifelinePSK() is not deterministic: %q != %q", got1, got2)
	}
	if !ValidWireGuardKey(got1) {
		t.Fatalf("LifelinePSK() = %q, want a valid base64 32-byte key", got1)
	}
}

// A different exit must derive a different PSK from the same master PSK, so a
// compromised lifeline peer on one exit cannot be replayed against another.
func TestLifelinePSKDiffersPerExit(t *testing.T) {
	psk := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got1, err := LifelinePSK(psk, "exit-a")
	if err != nil {
		t.Fatalf("LifelinePSK() = %v, want nil error", err)
	}
	got2, err := LifelinePSK(psk, "exit-b")
	if err != nil {
		t.Fatalf("LifelinePSK() = %v, want nil error", err)
	}
	if got1 == got2 {
		t.Fatalf("LifelinePSK() gave the same PSK for different exits: %q", got1)
	}
}

// An empty input PSK (the common, unused case) must map to an empty output,
// not an error, matching WGClient.PresharedKey's own "" ⇒ unused convention.
func TestLifelinePSKEmptyInEmptyOut(t *testing.T) {
	got, err := LifelinePSK("", "exit-a")
	if err != nil {
		t.Fatalf("LifelinePSK(\"\", ...) = %v, want nil error", err)
	}
	if got != "" {
		t.Fatalf("LifelinePSK(\"\", ...) = %q, want \"\"", got)
	}
}

// Invalid base64 input must be rejected rather than silently HMAC'd as garbage.
func TestLifelinePSKInvalidBase64(t *testing.T) {
	_, err := LifelinePSK("not-valid-base64!!!", "exit-a")
	if err == nil {
		t.Fatal("LifelinePSK() = nil error, want an error for invalid base64 input")
	}
}

// LifelinePeersOf must drop disabled credentials, exactly like PeersOf.
func TestLifelinePeersOfSkipsDisabled(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")
	clients := []WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.2/24", PublicKey: testClientPub1, PrivateKey: "priv-a", Enabled: true},
		{ID: "b", Name: "phone", Address: "10.80.0.3/24", PublicKey: testClientPub2, PrivateKey: "priv-b", Enabled: false},
	}

	peers, skipped := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if len(skipped) != 0 {
		t.Fatalf("LifelinePeersOf() skipped %+v, want nothing skipped", skipped)
	}
	if len(peers) != 1 {
		t.Fatalf("LifelinePeersOf() returned %d peers, want 1: %+v", len(peers), peers)
	}
}

// LifelinePeersOf must keep the name and public key, and shift the address.
func TestLifelinePeersOfKeepsNameAndPubkey(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")
	clients := []WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.7/24", PublicKey: testClientPub1, PrivateKey: "priv-a", Enabled: true},
	}

	peers, skipped := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if len(skipped) != 0 {
		t.Fatalf("LifelinePeersOf() skipped %+v, want nothing skipped", skipped)
	}
	if len(peers) != 1 {
		t.Fatalf("LifelinePeersOf() returned %d peers, want 1", len(peers))
	}
	got := peers[0]
	if got.Name != "laptop" || got.PublicKey != testClientPub1 {
		t.Fatalf("LifelinePeersOf() = %+v, want name %q and pubkey %q preserved", got, "laptop", testClientPub1)
	}
	if got.Address != "10.98.77.7/32" {
		t.Fatalf("LifelinePeersOf() address = %q, want %q", got.Address, "10.98.77.7/32")
	}
}

// The lifeline peer view is what travels to the exit's lifeline interface. It
// must be structurally incapable of carrying a client's private key, mirroring
// TestWGClientPeerCarriesNoPrivateKey — asserted here against the struct
// itself (reflection over field names) rather than against one value, since
// LifelinePeersOf returns the same WGClientPeer type PeersOf does and the
// guarantee is a property of the type, not of any single call.
func TestLifelinePeerViewHasNoPrivateKeyField(t *testing.T) {
	rt := reflect.TypeOf(WGClientPeer{})
	for i := range rt.NumField() {
		name := strings.ToLower(rt.Field(i).Name)
		if strings.Contains(name, "private") {
			t.Fatalf("WGClientPeer has field %q: the lifeline peer view must never carry a private key", rt.Field(i).Name)
		}
	}
}

// A peer address is what the interface writes as that peer's AllowedIPs, so it
// must be a single host however wide the lifeline pool is. This is the assertion
// that keeps LifelinePeersOf's output acceptable to ClientWGSpec.Validate, which
// LifelineSpec inherits through the embedding.
func TestLifelinePeersOfEmitsHostPrefixes(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")
	clients := []WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.5/32", PublicKey: testClientPub1, Enabled: true},
	}

	peers, skipped := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if len(skipped) != 0 || len(peers) != 1 {
		t.Fatalf("LifelinePeersOf() = %+v, skipped %+v; want one peer and no skips", peers, skipped)
	}
	p, err := netip.ParsePrefix(peers[0].Address)
	if err != nil {
		t.Fatalf("peer address %q does not parse: %v", peers[0].Address, err)
	}
	if p.Bits() != p.Addr().BitLen() {
		t.Fatalf("peer address = %q, want a single host (/%d)", peers[0].Address, p.Addr().BitLen())
	}
}

// One credential that cannot be projected must cost exactly itself.
//
// It reaches the exit's whole NodeSpec otherwise, and the agent refuses a spec
// entire: an address left outside the master pool by a manifest edit would stop
// nftables, routing and the exit's own AWG server from converging. So the batch
// survives, and the caller is handed the ID and the reason to say so with.
func TestLifelinePeersOfSkipsTheUnprojectableAndKeepsTheRest(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")
	clients := []WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.5/32", PublicKey: testClientPub1, Enabled: true},
		{ID: "b", Name: "stray", Address: "192.0.2.9/32", PublicKey: testClientPub2, Enabled: true},
	}

	peers, skipped := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if len(peers) != 1 || peers[0].Name != "laptop" {
		t.Fatalf("peers = %+v, want only the projectable credential", peers)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %+v, want exactly the stray credential", skipped)
	}
	if skipped[0].ID != "b" || skipped[0].Name != "stray" {
		t.Errorf("skipped[0] = %+v, want the credential identified by ID and name", skipped[0])
	}
	if skipped[0].Reason == nil {
		t.Error("a skip must carry the reason it was skipped")
	}
}

// A malformed preshared key is the other way a single credential can fail, and
// it must be skipped on the same terms rather than failing the batch.
func TestLifelinePeersOfSkipsAMalformedPresharedKey(t *testing.T) {
	masterPool := mustPrefix(t, "10.80.0.0/24")
	lifelinePool := mustPrefix(t, "10.98.77.0/24")
	clients := []WGClient{
		{ID: "a", Name: "laptop", Address: "10.80.0.5/32", PublicKey: testClientPub1, Enabled: true},
		{ID: "b", Name: "broken", Address: "10.80.0.6/32", PublicKey: testClientPub2,
			PresharedKey: "not-valid-base64!!!", Enabled: true},
	}

	peers, skipped := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if len(peers) != 1 || peers[0].Name != "laptop" {
		t.Fatalf("peers = %+v, want only the good credential", peers)
	}
	if len(skipped) != 1 || skipped[0].ID != "b" {
		t.Fatalf("skipped = %+v, want exactly the credential with the bad PSK", skipped)
	}
}
