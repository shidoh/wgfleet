package mihomo

import (
	"strings"
	"testing"
)

const diffOld = `
dns:
  listen: 127.0.0.1:1053
  nameserver: [10.73.0.1]
proxies:
  - name: vn0
    type: wireguard
    server: 198.51.100.1
    port: 51820
    private-key: SECRETKEYOLD==
  - name: vn1
    type: wireguard
    server: 198.51.100.2
    port: 51820
proxy-groups:
  - name: wg-best
    type: load-balance
    proxies: [vn0, vn1]
rules:
  - MATCH,wg-best
`

// Every difference is named by its key path and never by its value: this string
// lands in the journal next to the redacted plan.
func TestDescribeChangeNamesKeyPathsNotValues(t *testing.T) {
	newer := strings.NewReplacer(
		"server: 198.51.100.2", "server: 198.51.100.9",
		"SECRETKEYOLD==", "SECRETKEYNEW==",
		"proxies: [vn0, vn1]", "proxies: [vn0]",
		"nameserver: [10.73.0.1]", "nameserver: [10.73.0.2]",
	).Replace(diffOld)
	got := DescribeChange([]byte(diffOld), []byte(newer))
	for _, want := range []string{"proxies: vn0 (private-key), vn1 (server)", "proxy-groups: wg-best (proxies)", "dns: nameserver"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	for _, secret := range []string{"SECRETKEYNEW", "SECRETKEYOLD", "198.51.100.9", "10.73.0.2"} {
		if strings.Contains(got, secret) {
			t.Errorf("value %q leaked into the description %q", secret, got)
		}
	}
	if strings.Contains(got, "rules") {
		t.Errorf("unchanged section reported: %q", got)
	}
}

func TestDescribeChangeAddedAndRemovedEntries(t *testing.T) {
	newer := strings.Replace(diffOld, "  - name: vn1\n    type: wireguard\n    server: 198.51.100.2\n    port: 51820\n",
		"  - name: vn2\n    type: wireguard\n    server: 198.51.100.3\n    port: 51820\n", 1)
	got := DescribeChange([]byte(diffOld), []byte(newer))
	if !strings.Contains(got, "vn1 (removed)") || !strings.Contains(got, "vn2 (added)") {
		t.Errorf("got %q", got)
	}
}

func TestDescribeChangeIsEmptyWhenEqual(t *testing.T) {
	if got := DescribeChange([]byte(diffOld), []byte(diffOld)); got != "" {
		t.Errorf("equal documents described as %q", got)
	}
	// A first-ever write has no old document: everything is new, and that is what
	// the description should say rather than crashing or claiming equality.
	if got := DescribeChange(nil, []byte(diffOld)); got == "" {
		t.Error("first write described as no change")
	}
}
