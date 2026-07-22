package auth

import (
	"fmt"
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

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter(3, 50*time.Millisecond, 128)
	const a, b = "10.0.0.1", "10.0.0.2"

	if !l.Allowed(a) {
		t.Fatal("fresh IP should allow")
	}
	l.Fail(a)
	l.Fail(a)
	if !l.Allowed(a) {
		t.Fatal("under threshold should allow")
	}
	l.Fail(a) // trips the lock for a only
	if l.Allowed(a) {
		t.Fatal("a should be locked after maxFails")
	}
	if !l.Allowed(b) {
		t.Fatal("a's failures must NOT lock out b (per-IP isolation)")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allowed(a) {
		t.Fatal("lock should expire")
	}
	l.Fail(a)
	l.Reset(a)
	if !l.Allowed(a) {
		t.Fatal("Reset should clear a's failures")
	}
}

func TestIPLimiterEvictsWhenFull(t *testing.T) {
	// The tracked-IP map is bounded: adding beyond the cap must not grow without
	// limit (a spray of distinct source IPs is otherwise a memory-exhaustion lever).
	l := NewIPLimiter(3, time.Hour, 4)
	for i := range 100 {
		l.Fail(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	if n := l.Tracked(); n > 4 {
		t.Fatalf("tracked IPs = %d, want <= cap 4", n)
	}
}
