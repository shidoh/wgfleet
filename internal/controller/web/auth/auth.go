// Package auth provides the web panel's password hashing, stateless signed
// session tokens, and a small login rate-limiter. It has no HTTP or store
// dependency so it can be unit-tested in isolation.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLen is the minimum admin password length enforced at setup/change.
const MinPasswordLen = 12

// bcryptCost is deliberately above the library default (10) for an admin login.
const bcryptCost = 12

// HashPassword returns a bcrypt hash of pw.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(b), err
}

// CheckPassword reports whether pw matches the bcrypt hash. A malformed hash
// returns false (never panics).
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// NewSecret returns 32 cryptographically-random bytes for HMAC signing.
func NewSecret() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

type payload struct {
	U string `json:"u"`
	E int64  `json:"e"`
}

// Sign returns "b64(payload).b64(HMAC-SHA256(payload))" for user/exp.
func Sign(secret []byte, user string, exp time.Time) string {
	p, _ := json.Marshal(payload{U: user, E: exp.Unix()})
	body := base64.RawURLEncoding.EncodeToString(p)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig
}

// Verify checks the signature + expiry and returns the user. ok=false on any
// tamper, bad format, wrong secret, or expiry.
func Verify(secret []byte, token string) (string, bool) {
	body, sig, found := strings.Cut(token, ".")
	if !found {
		return "", false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", false
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", false
	}
	if time.Now().After(time.Unix(p.E, 0)) {
		return "", false
	}
	return p.U, true
}

// Limiter is an in-process login throttle: after maxFails consecutive failures
// it locks for `lock`, until a Reset (successful login) or the lock expires.
type Limiter struct {
	mu       sync.Mutex
	maxFails int
	lock     time.Duration
	fails    int
	until    time.Time
}

func NewLimiter(maxFails int, lock time.Duration) *Limiter {
	return &Limiter{maxFails: maxFails, lock: lock}
}

// Allowed reports whether a login attempt may proceed now.
func (l *Limiter) Allowed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().After(l.until)
}

// Fail records a failed attempt, arming the lock at the threshold.
func (l *Limiter) Fail() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails++
	if l.fails >= l.maxFails {
		l.until = time.Now().Add(l.lock)
		l.fails = 0
	}
}

// Reset clears the failure count + lock after a successful login.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails = 0
	l.until = time.Time{}
}
