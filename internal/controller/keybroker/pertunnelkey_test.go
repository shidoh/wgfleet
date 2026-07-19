package keybroker

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// masterSharedKey is the master's legacy single identity in these tests.
const masterSharedKey = "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc="

// fleetWithPhase returns the standard test fleet with the exit pinned to phase.
func fleetWithPhase(phase domain.PerTunnelKeyPhase) config.FleetSection {
	f := testFleet()
	f.Exits[0].PerTunnelKey = string(phase)
	return f
}

// seedTunnelKey registers a per-tunnel master pubkey, deriving it the same way the
// master agent would so the test exercises the real value.
func seedTunnelKey(t *testing.T, st store.Store, masterID, tunnel, masterPriv string) string {
	t.Helper()
	kp, err := wg.DeriveTunnelKey(masterPriv, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeTunnelKey(context.Background(), masterID, tunnel, kp.PublicKey); err != nil {
		t.Fatal(err)
	}
	return kp.PublicKey
}

// peerByKey finds the rendered peer carrying publicKey.
func peerByKey(peers []domain.PeerSpec, publicKey string) (domain.PeerSpec, bool) {
	for _, p := range peers {
		if p.PublicKey == publicKey {
			return p, true
		}
	}
	return domain.PeerSpec{}, false
}

func TestExitPeersPerPhase(t *testing.T) {
	// A throwaway master private key whose PUBLIC key is what the exit peers as the
	// legacy identity, so the derived per-tunnel key is genuinely a different value.
	masterPriv, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		phase      domain.PerTunnelKeyPhase
		wantLegacy bool
		wantPerTun bool
	}{
		{"off keeps only the legacy peer", domain.PerTunnelKeyOff, true, false},
		{"dual carries both peers", domain.PerTunnelKeyDual, true, true},
		{"switch still carries both peers", domain.PerTunnelKeySwitch, true, true},
		{"on drops the legacy peer", domain.PerTunnelKeyOn, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			b, st := newBrokerWithFleet(t, fleetWithPhase(tc.phase))
			seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", masterPriv.PublicKey, domain.RoleMaster)
			seedNode(t, st, "exit-de-1", "10.20.25.1", "198.51.100.1", "", domain.RoleExit)
			perTunnelPub := seedTunnelKey(t, st, "master-xa-1", "exit-de-1", masterPriv.PrivateKey)

			spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
			if err != nil {
				t.Fatalf("render exit spec: %v", err)
			}

			legacy, gotLegacy := peerByKey(spec.Peers, masterPriv.PublicKey)
			perTun, gotPerTun := peerByKey(spec.Peers, perTunnelPub)
			if gotLegacy != tc.wantLegacy {
				t.Errorf("legacy peer present = %v, want %v (peers: %+v)", gotLegacy, tc.wantLegacy, spec.Peers)
			}
			if gotPerTun != tc.wantPerTun {
				t.Errorf("per-tunnel peer present = %v, want %v (peers: %+v)", gotPerTun, tc.wantPerTun, spec.Peers)
			}

			// The invariant that makes two-peer coexistence work at all: WireGuard
			// AllowedIPs is a routing trie, so the two master peers must never claim
			// the same address or the second silently steals the first's /32.
			if gotLegacy && gotPerTun {
				if legacy.AllowedIPs[0] == perTun.AllowedIPs[0] {
					t.Fatalf("legacy and per-tunnel peers share allowed-ip %q — the trie would drop one",
						legacy.AllowedIPs[0])
				}
				if legacy.AllowedIPs[0] != "10.81.0.2/32" {
					t.Errorf("legacy peer allowed-ip = %q, want 10.81.0.2/32", legacy.AllowedIPs[0])
				}
				if perTun.AllowedIPs[0] != "10.81.0.3/32" {
					t.Errorf("per-tunnel peer allowed-ip = %q, want 10.81.0.3/32", perTun.AllowedIPs[0])
				}
			}
		})
	}
}

func TestExitFallsBackToLegacyKeyWhenPerTunnelKeyUnpublished(t *testing.T) {
	// Mid-migration reality: the operator sets `dual` before the master's next
	// reconcile pass has published the key. The exit must still render the legacy
	// peer rather than losing its only way in.
	ctx := context.Background()
	b, st := newBrokerWithFleet(t, fleetWithPhase(domain.PerTunnelKeyDual))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", masterSharedKey, domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.25.1", "198.51.100.1", "", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render exit spec: %v", err)
	}
	if len(spec.Peers) != 1 {
		t.Fatalf("want exactly the legacy peer, got %d peers: %+v", len(spec.Peers), spec.Peers)
	}
	if spec.Peers[0].PublicKey != masterSharedKey {
		t.Fatalf("peer key = %q, want the shared master key", spec.Peers[0].PublicKey)
	}
}

func TestMasterTunnelKeySelectionPerPhase(t *testing.T) {
	tests := []struct {
		name          string
		phase         domain.PerTunnelKeyPhase
		wantKeyTunnel string
		wantTunnelIP  string
	}{
		{"off dials with the shared key at .2", domain.PerTunnelKeyOff, "", "10.81.0.2"},
		{"dual still dials with the shared key at .2", domain.PerTunnelKeyDual, "", "10.81.0.2"},
		{"switch flips to the per-tunnel key at .3", domain.PerTunnelKeySwitch, "exit-de-1", "10.81.0.3"},
		{"on stays on the per-tunnel key at .3", domain.PerTunnelKeyOn, "exit-de-1", "10.81.0.3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			b, st := newBrokerWithFleet(t, fleetWithPhase(tc.phase))
			seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", masterSharedKey, domain.RoleMaster)
			seedNode(t, st, "exit-de-1", "10.20.25.1", "198.51.100.1",
				"n1YvVJqTJfJ0pxTQFvVYqNFhKlCcm4dGZUZ8oVLPjHM=", domain.RoleExit)

			spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
			if err != nil {
				t.Fatalf("render master spec: %v", err)
			}
			if spec.Master == nil || len(spec.Master.ExitTunnels) != 1 {
				t.Fatalf("want one exit tunnel, got %+v", spec.Master)
			}
			tun := spec.Master.ExitTunnels[0]
			if tun.MasterKeyTunnel != tc.wantKeyTunnel {
				t.Errorf("MasterKeyTunnel = %q, want %q", tun.MasterKeyTunnel, tc.wantKeyTunnel)
			}
			// Key and address must move together: the exit peers the two identities on
			// two different /32s, so dialing with the new key from the old address
			// would be dropped by the peer's allowed-ips check.
			if tun.TunnelIP != tc.wantTunnelIP {
				t.Errorf("TunnelIP = %q, want %q", tun.TunnelIP, tc.wantTunnelIP)
			}
		})
	}
}

func TestRegisterTunnelKey(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", masterSharedKey, domain.RoleMaster)
	valid := "n1YvVJqTJfJ0pxTQFvVYqNFhKlCcm4dGZUZ8oVLPjHM="

	t.Run("stores a valid key for a declared exit", func(t *testing.T) {
		if err := b.RegisterTunnelKey(ctx, "master-xa-1", "exit-de-1", valid); err != nil {
			t.Fatalf("register: %v", err)
		}
		keys, err := st.ListNodeTunnelKeys(ctx, "master-xa-1")
		if err != nil {
			t.Fatal(err)
		}
		if keys["exit-de-1"] != valid {
			t.Fatalf("stored %q, want %q", keys["exit-de-1"], valid)
		}
	})

	t.Run("re-publishing the same tunnel replaces the key", func(t *testing.T) {
		other, err := wg.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := b.RegisterTunnelKey(ctx, "master-xa-1", "exit-de-1", other.PublicKey); err != nil {
			t.Fatalf("re-register: %v", err)
		}
		keys, err := st.ListNodeTunnelKeys(ctx, "master-xa-1")
		if err != nil {
			t.Fatal(err)
		}
		if keys["exit-de-1"] != other.PublicKey {
			t.Fatalf("upsert did not replace the key: got %q", keys["exit-de-1"])
		}
		if len(keys) != 1 {
			t.Fatalf("want 1 key after upsert, got %d", len(keys))
		}
	})

	t.Run("rejects bad input", func(t *testing.T) {
		bad := []struct {
			name   string
			tunnel string
			key    string
		}{
			{"empty key", "exit-de-1", ""},
			// A malformed key would be rendered verbatim as `PublicKey = <value>` into
			// awg0.conf, which awg-quick executes — config injection on the peer.
			{"malformed key", "exit-de-1", "not-a-key"},
			{"multi-line injection", "exit-de-1", valid + "\nPostUp = /bin/sh -c evil"},
			{"unknown exit", "not-in-manifest", valid},
		}
		for _, tc := range bad {
			t.Run(tc.name, func(t *testing.T) {
				if err := b.RegisterTunnelKey(ctx, "master-xa-1", tc.tunnel, tc.key); err == nil {
					t.Fatal("expected an error, got nil")
				}
			})
		}
	})
}
