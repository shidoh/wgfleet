package main

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
)

func TestSetAdminPassword(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := setAdminPassword(st, "admin", "first-password-12"); err != nil {
		t.Fatal(err)
	}
	rec, _ := st.GetAuth(context.Background())
	if rec.Username != "admin" || !auth.CheckPassword(rec.PasswordHash, "first-password-12") {
		t.Fatal("initial set failed")
	}
	first := rec.SessionSecret

	// Reset: new password, rotated secret, keeps acting as upsert.
	if err := setAdminPassword(st, "admin", "second-password-1"); err != nil {
		t.Fatal(err)
	}
	rec, _ = st.GetAuth(context.Background())
	if !auth.CheckPassword(rec.PasswordHash, "second-password-1") || string(rec.SessionSecret) == string(first) {
		t.Fatal("reset did not rotate hash/secret")
	}

	// Too-short password is rejected.
	if err := setAdminPassword(st, "admin", "short"); err == nil {
		t.Fatal("short password must be rejected")
	}
}
