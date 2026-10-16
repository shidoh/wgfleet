package netfw

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func portalFWInput() RenderInput {
	return RenderInput{
		Firewall:       domain.FirewallSpec{WGPort: 443},
		Role:           domain.RoleMaster,
		NetnsHostIface: "mih-host",
	}
}

// mihomo in its namespace dials the portal's SOCKS inbound on the host end of
// the link: TCP for streams; UDP to the SOCKS port and to the relay port xray
// answers an ASSOCIATE with — a fresh one from the host's ephemeral range each
// time (seen on the stand: 36934, 56860, 43726). Nothing wider: a wholesale
// accept on the veth once let every client reach the controller.
func TestPortalSocksAcceptIsExactlyTwoRules(t *testing.T) {
	in := portalFWInput()
	in.PortalSocks = netip.MustParseAddrPort("100.127.255.1:10808")
	in.PortalUDPRelay = [2]uint16{32768, 60999}
	out, err := RenderRuleset(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`iifname "mih-host" ip daddr 100.127.255.1 tcp dport 10808 accept`,
		`iifname "mih-host" ip daddr 100.127.255.1 udp dport { 10808, 32768-60999 } accept`,
	}
	for _, w := range want {
		if strings.Count(out, w) != 1 {
			t.Errorf("ruleset has %q %d times:\n%s", w, strings.Count(out, w), out)
		}
	}
	if n := strings.Count(out, "10808"); n != 2 {
		t.Errorf("10808 appears %d times, want 2", n)
	}
}

func TestPortalSocksAcceptAbsentWithoutPortalOrNamespace(t *testing.T) {
	base, err := RenderRuleset(portalFWInput())
	if err != nil {
		t.Fatal(err)
	}
	// No portal: the ruleset is what it was before the mode existed.
	in := portalFWInput()
	in.PortalSocks = netip.AddrPort{}
	if out, _ := RenderRuleset(in); out != base {
		t.Error("an unset portal changed the ruleset")
	}
	// mihomo on the host reaches the loopback through `iif lo accept`.
	in = portalFWInput()
	in.NetnsHostIface = ""
	in.PortalSocks = netip.MustParseAddrPort("100.127.255.1:10808")
	if out, _ := RenderRuleset(in); strings.Contains(out, "10808") {
		t.Error("portal accept rendered with mihomo on the host")
	}
}
