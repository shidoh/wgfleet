package auth

import (
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery staple") {
		t.Error("correct password rejected")
	}
	if CheckPassword(h, "wrong") {
		t.Error("wrong password accepted")
	}
	if CheckPassword("not-a-hash", "anything") {
		t.Error("malformed hash must not authenticate")
	}
}

func TestSessionSignVerify(t *testing.T) {
	secret, _ := NewSecret()
	tok := Sign(secret, "admin", time.Now().Add(time.Hour))
	if u, ok := Verify(secret, tok); !ok || u != "admin" {
		t.Fatalf("Verify = %q, %v; want admin, true", u, ok)
	}
	// Expired.
	if _, ok := Verify(secret, Sign(secret, "admin", time.Now().Add(-time.Minute))); ok {
		t.Error("expired token accepted")
	}
	// Wrong secret.
	other, _ := NewSecret()
	if _, ok := Verify(other, tok); ok {
		t.Error("token verified under a different secret")
	}
	// Tampered.
	if _, ok := Verify(secret, tok+"x"); ok {
		t.Error("tampered token accepted")
	}
	if _, ok := Verify(secret, "garbage"); ok {
		t.Error("garbage token accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, 50*time.Millisecond)
	if !l.Allowed() {
		t.Fatal("fresh limiter should allow")
	}
	l.Fail()
	l.Fail()
	if !l.Allowed() {
		t.Fatal("under threshold should allow")
	}
	l.Fail() // 3rd failure trips the lock
	if l.Allowed() {
		t.Fatal("locked after maxFails")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allowed() {
		t.Fatal("lock should expire")
	}
	l.Fail()
	l.Reset()
	if !l.Allowed() {
		t.Fatal("Reset should clear failures")
	}
}
