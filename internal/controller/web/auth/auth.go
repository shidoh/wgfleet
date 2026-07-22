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
	"fmt"
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
	p, err := json.Marshal(payload{U: user, E: exp.Unix()})
	if err != nil {
		panic(fmt.Sprintf("auth.Sign: marshal payload: %v", err))
	}
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

// IPLimiter is a per-source-IP variant of Limiter for endpoints served to MANY
// independent callers (e.g. the client subscription fetch): a global lock there
// would let one bad actor lock out every legitimate client, so each IP gets its own
// consecutive-fail counter. The tracked-IP map is bounded by `max` so a spray of
// distinct source IPs cannot exhaust memory; at the cap, expired entries are dropped
// first and, if still full, the whole map is cleared (a rare, self-healing reset).
type IPLimiter struct {
	mu       sync.Mutex
	maxFails int
	lock     time.Duration
	max      int
	entries  map[string]*ipEntry
}

type ipEntry struct {
	fails int
	until time.Time
}

// NewIPLimiter builds a per-IP throttle: maxFails consecutive failures lock an IP
// for `lock`; at most `max` IPs are tracked at once.
func NewIPLimiter(maxFails int, lock time.Duration, max int) *IPLimiter {
	return &IPLimiter{maxFails: maxFails, lock: lock, max: max, entries: make(map[string]*ipEntry)}
}

// Allowed reports whether a request from ip may proceed now.
func (l *IPLimiter) Allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	return e == nil || time.Now().After(e.until)
}

// Fail records a failed attempt from ip, arming its lock at the threshold.
func (l *IPLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		l.evictLocked()
		e = &ipEntry{}
		l.entries[ip] = e
	}
	e.fails++
	if e.fails >= l.maxFails {
		e.until = time.Now().Add(l.lock)
		e.fails = 0
	}
}

// Reset clears ip's failure count + lock after a successful fetch.
func (l *IPLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// Tracked returns the number of IPs currently held (for tests / metrics).
func (l *IPLimiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evictLocked keeps the map under `max`: it first drops entries whose lock has
// expired (dead weight), and if the map is still at the cap, clears it wholesale.
// Caller holds l.mu.
func (l *IPLimiter) evictLocked() {
	if len(l.entries) < l.max {
		return
	}
	now := time.Now()
	for ip, e := range l.entries {
		if now.After(e.until) {
			delete(l.entries, ip)
		}
	}
	if len(l.entries) >= l.max {
		l.entries = make(map[string]*ipEntry)
	}
}
