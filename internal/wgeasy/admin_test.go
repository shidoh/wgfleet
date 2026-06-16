package wgeasy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != adminPasswordLen {
		t.Errorf("password length = %d, want %d", len(a), adminPasswordLen)
	}
	b, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated passwords should differ")
	}
	for _, c := range a {
		if !containsRune(base62, c) {
			t.Errorf("password contains non-base62 rune %q", c)
		}
	}
}

func TestLoadOrCreateAdminPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "wg-easy-admin-password")

	// First call generates and persists.
	pass, created, err := LoadOrCreateAdminPassword(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("first call should report created=true")
	}
	if pass == "" {
		t.Fatal("empty password generated")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("password file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("password file perm = %o, want 600", perm)
	}

	// Second call loads the same password without regenerating.
	pass2, created2, err := LoadOrCreateAdminPassword(path)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Error("second call should report created=false")
	}
	if pass2 != pass {
		t.Errorf("password changed across calls: %q != %q", pass2, pass)
	}
}

func TestReadAdminPasswordMissing(t *testing.T) {
	_, err := ReadAdminPassword(filepath.Join(t.TempDir(), "nope"))
	if !os.IsNotExist(err) {
		t.Errorf("want os.ErrNotExist, got %v", err)
	}
}

func TestReadAdminPasswordEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAdminPassword(path); err == nil {
		t.Error("expected error for empty password file")
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
