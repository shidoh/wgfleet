package main

import (
	"testing"
	"time"
)

func TestResolveMetricsBind(t *testing.T) {
	tests := []struct {
		name    string
		flagVal string
		mgmt    string
		want    string
	}{
		{"default from mgmt", "", "10.20.3.21", "10.20.3.21:9301"},
		{"default ipv6 from mgmt", "", "fd00::1", "[fd00::1]:9301"},
		{"no flag no mgmt disables", "", "", ""},
		{"whitespace flag defaults to mgmt", "   ", "10.20.3.21", "10.20.3.21:9301"},
		{"off disables", "off", "10.20.3.21", ""},
		{"OFF case-insensitive", "OFF", "10.20.3.21", ""},
		{"none disables", "none", "10.20.3.21", ""},
		{"dash disables", "-", "10.20.3.21", ""},
		{"explicit override wins", "10.0.0.5:9999", "10.20.3.21", "10.0.0.5:9999"},
		{"explicit override trimmed", "  10.0.0.5:9999  ", "10.20.3.21", "10.0.0.5:9999"},
		{"explicit override with no mgmt", "10.0.0.5:9999", "", "10.0.0.5:9999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveMetricsBind(tt.flagVal, tt.mgmt); got != tt.want {
				t.Fatalf("resolveMetricsBind(%q, %q) = %q, want %q", tt.flagVal, tt.mgmt, got, tt.want)
			}
		})
	}
}

// The renewal window is ~110 days wide and the reconcile loop runs every 30 seconds,
// so a deterministic failure — a controller below wire 10, or one with no CA loaded —
// meant ~316k identical WARN lines, keygens and RPCs before the certificate lapsed.
// Backoff is what makes a stuck node legible instead of loud.
func TestRenewBackoffDoublesToAnHour(t *testing.T) {
	got := nextRenewBackoff(0)
	if got != 30*time.Second {
		t.Errorf("first backoff = %v, want one reconcile pass", got)
	}
	steps := 0
	for got < time.Hour && steps < 20 {
		next := nextRenewBackoff(got)
		if next <= got {
			t.Fatalf("backoff stopped growing at %v", got)
		}
		got = next
		steps++
	}
	if got != time.Hour {
		t.Errorf("backoff settled at %v, want an hour", got)
	}
	if n := nextRenewBackoff(time.Hour); n != time.Hour {
		t.Errorf("backoff grew past its cap: %v", n)
	}
	// Roughly a day of failures should cost tens of lines, not tens of thousands.
	var elapsed time.Duration
	attempts := 0
	for d := time.Duration(0); elapsed < 24*time.Hour; attempts++ {
		d = nextRenewBackoff(d)
		elapsed += d
	}
	if attempts > 40 {
		t.Errorf("%d attempts in 24h; the failure drowns itself again", attempts)
	}
}
