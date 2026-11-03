package clientcfg

import (
	"strings"
	"testing"
)

func TestParseUserAgent(t *testing.T) {
	for _, tc := range []struct {
		ua   string
		want ClientAgent
	}{
		// What mihomo 1.19.33 sends when it refreshes a proxy provider (captured).
		{"clash.meta/v1.19.33", ClientAgent{CoreVersion: "1.19.33"}},
		{"mihomo/1.19.40", ClientAgent{CoreVersion: "1.19.40"}},
		{"clash-verge/v2.5.9", ClientAgent{App: "clash-verge", AppVersion: "2.5.9"}},
		{"FlClash/v0.9.2 clash.meta/v1.19.33 Platform/android",
			ClientAgent{App: "FlClash", AppVersion: "0.9.2", CoreVersion: "1.19.33"}},
		{"curl/8.7.1", ClientAgent{App: "curl", AppVersion: "8.7.1"}},
		{"", ClientAgent{}},
		{"no version here", ClientAgent{}},
	} {
		if got := ParseUserAgent(tc.ua); got != tc.want {
			t.Errorf("ParseUserAgent(%q) = %+v, want %+v", tc.ua, got, tc.want)
		}
	}
}

func TestSanitizeUserAgentDropsControlBytesAndCapsLength(t *testing.T) {
	if got := SanitizeUserAgent("clash\x00-verge\n/v2é"); got != "clash-verge/v2" {
		t.Errorf("SanitizeUserAgent = %q", got)
	}
	if got := SanitizeUserAgent(strings.Repeat("a", 500)); len(got) != maxUserAgent {
		t.Errorf("length = %d, want %d", len(got), maxUserAgent)
	}
}
