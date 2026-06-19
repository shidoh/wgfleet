package main

import "testing"

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
