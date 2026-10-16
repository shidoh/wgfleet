package main

import (
	"os"
	"slices"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/exit"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// The portal key is the master's alone: generated on first apply, kept 0600,
// and the same key on every later pass — a new one would redial every bridge.
func TestEnsureRealityPortalKeyPersistsAndIsStable(t *testing.T) {
	a := quietAgent(t)
	priv, pub, eph, err := a.ensureRealityPortalKey(true)
	if err != nil || eph {
		t.Fatalf("ensureRealityPortalKey(true) = eph %v, err %v", eph, err)
	}
	if got, _ := xray.PublicKeyFor(priv); got != pub {
		t.Fatalf("public key %q does not match the private key", pub)
	}
	fi, err := os.Stat(a.masterPaths().RealityPortalKey)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", fi.Mode().Perm())
	}
	priv2, pub2, _, err := a.ensureRealityPortalKey(true)
	if err != nil || priv2 != priv || pub2 != pub {
		t.Fatalf("second pass changed the key (err %v)", err)
	}
	// Separate from the client VLESS key, which end users pin.
	if _, err := os.Stat(a.masterPaths().ClientVLESSKey); err == nil {
		t.Error("ensuring the portal key wrote the client VLESS key")
	}
}

// A plan run never writes a key.
func TestEnsureRealityPortalKeyPlanIsEphemeral(t *testing.T) {
	a := quietAgent(t)
	_, pub, eph, err := a.ensureRealityPortalKey(false)
	if err != nil || !eph || pub == "" {
		t.Fatalf("ensureRealityPortalKey(false) = pub %q eph %v err %v", pub, eph, err)
	}
	if _, err := os.Stat(a.masterPaths().RealityPortalKey); err == nil {
		t.Error("a plan run wrote the portal key")
	}
}

// The support bundle refuses to ship a file holding the portal key.
func TestGatherSecretsCoversTheRealityPortalKey(t *testing.T) {
	a := quietAgent(t)
	priv, _, _, err := a.ensureRealityPortalKey(true)
	if err != nil {
		t.Fatal(err)
	}
	secrets := gatherSecrets(domain.RoleMaster, exit.PathsUnder(a.stateDir), a.masterPaths())
	if !slices.Contains(secrets, priv) {
		t.Error("gatherSecrets misses the reality portal key")
	}
}
