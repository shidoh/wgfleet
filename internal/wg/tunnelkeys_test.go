package wg

import "testing"

// masterKey is a fixed, throwaway WireGuard private key. It is test-only material —
// never a key any node has held.
const masterKey = "aFq0kZ0mvVQvWjJHnbnCoJqQGGF0vJ5xJHqZ7pXqJ2s="

func TestDeriveTunnelKeyIsDeterministic(t *testing.T) {
	for _, tunnel := range []string{"anz3", "1cnode004", "pn8", "vn1", "vn2"} {
		t.Run(tunnel, func(t *testing.T) {
			first, err := DeriveTunnelKey(masterKey, tunnel)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			second, err := DeriveTunnelKey(masterKey, tunnel)
			if err != nil {
				t.Fatalf("re-derive: %v", err)
			}
			if first != second {
				t.Fatalf("derivation not deterministic: %+v vs %+v", first, second)
			}
			// The pubkey the master publishes must be the one the peer's kernel
			// computes from the private key we render into mihomo. If clamping were
			// skipped these could disagree for a non-canonical scalar.
			pub, err := PublicKeyOf(first.PrivateKey)
			if err != nil {
				t.Fatalf("public key of derived private key: %v", err)
			}
			if pub != first.PublicKey {
				t.Fatalf("public key mismatch: derived %q, recomputed %q", first.PublicKey, pub)
			}
			if !ValidKey(first.PrivateKey) || !ValidKey(first.PublicKey) {
				t.Fatalf("derived key is not a well-formed WG key: %+v", first)
			}
		})
	}
}

func TestDeriveTunnelKeyIsDistinctPerTunnelAndPerMaster(t *testing.T) {
	// The whole point of ADR-0030: no two exits may see the same master pubkey, or
	// they can be linked as one fleet by comparing one string.
	seen := map[string]string{}
	for _, tunnel := range []string{"anz3", "1cnode004", "pn8", "vn1", "vn2"} {
		kp, err := DeriveTunnelKey(masterKey, tunnel)
		if err != nil {
			t.Fatalf("derive %q: %v", tunnel, err)
		}
		if prev, dup := seen[kp.PublicKey]; dup {
			t.Fatalf("tunnels %q and %q derived the same public key", prev, tunnel)
		}
		seen[kp.PublicKey] = tunnel
	}

	// A per-tunnel key must also differ from the master's shared identity, otherwise
	// the migration would be a no-op that looks done.
	sharedPub, err := PublicKeyOf(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, collides := seen[sharedPub]; collides {
		t.Fatal("a derived per-tunnel key collides with the shared master key")
	}

	// Different masters must not derive the same per-tunnel identity either.
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a, err := DeriveTunnelKey(masterKey, "anz3")
	if err != nil {
		t.Fatal(err)
	}
	bkp, err := DeriveTunnelKey(other.PrivateKey, "anz3")
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey == bkp.PublicKey {
		t.Fatal("two different masters derived the same per-tunnel key")
	}
}

func TestDeriveTunnelKeyRejectsBadInput(t *testing.T) {
	tests := []struct {
		name   string
		master string
		tunnel string
	}{
		{"empty tunnel", masterKey, ""},
		{"empty master key", "", "anz3"},
		{"malformed master key", "not-a-key", "anz3"},
		{"wrong-length master key", "c2hvcnQ=", "anz3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DeriveTunnelKey(tc.master, tc.tunnel); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
