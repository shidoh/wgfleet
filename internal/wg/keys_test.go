package wg

import (
	"os"
	"path/filepath"
	"testing"
)

// A torn write must not wedge the node permanently.
//
// The key was written with a bare os.WriteFile, so a node that lost power or hit a
// full disk mid-write kept a zero-length file. That file EXISTS, so the branch that
// generates a key never ran again, and every pass afterwards failed to parse it —
// forever, until a human deleted it. An empty file carries no key and no intent; it
// is the same fact as no file at all.
func TestAnEmptyKeyFileIsTreatedAsNoKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg.key")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	kp, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("a zero-length key file wedged the node: %v", err)
	}
	if !created || kp.PrivateKey == "" {
		t.Fatal("no key was generated to replace the empty file")
	}
	again, created, err := LoadOrCreateKey(path)
	if err != nil || created || again.PrivateKey != kp.PrivateKey {
		t.Fatalf("the replacement key did not persist: %v %v", created, err)
	}
}

// But a file with content we do not understand stays an error: it may be one
// somebody meant to put there, and silently replacing a key is how an identity
// disappears.
func TestAKeyFileWithJunkIsStillAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg.key")
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a key file with junk in it was silently replaced")
	}
}
