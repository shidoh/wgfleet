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

	peers, err := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if err != nil {
		t.Fatalf("LifelinePeersOf() = %v, want nil error", err)
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

	peers, err := LifelinePeersOf(clients, masterPool, lifelinePool, "exit-a")
	if err != nil {
		t.Fatalf("LifelinePeersOf() = %v, want nil error", err)
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
