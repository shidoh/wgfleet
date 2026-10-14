package mihomo

import (
	"slices"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func siteProfile(t *testing.T, sites ...domain.ClientSite) map[string]any {
	t.Helper()
	return renderProfile(t, ClientProfileInput{
		MgmtCIDRs: []string{"172.29.0.0/16"},
		Sites:     sites,
		Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0"), DNS: []string{"10.80.0.1"},
			RouteThrough: []string{"10.0.0.0/8"}, ClientPool: "10.80.0.0/24"}},
	})
}

func group(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	for _, g := range doc["proxy-groups"].([]any) {
		if m := g.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

var home = domain.ClientSite{Name: "home", CIDRs: []string{"172.18.0.0/21", "172.26.1.0/24"},
	ProbeURL: "http://172.26.1.100/", ProbeInterval: 30}

// At home the probe answers directly, so the fallback stays on DIRECT; away it
// does not, and the fallback moves to the tunnel. The select on top is the
// person's override for when the guess is wrong, "auto" first so it is the
// default.
func TestClientProfileSiteWithProbe(t *testing.T) {
	doc := siteProfile(t, home)
	auto := group(t, doc, "home-auto")
	if auto == nil {
		t.Fatal("no home-auto group")
	}
	if auto["type"] != "fallback" || auto["url"] != "http://172.26.1.100/" || auto["interval"] != 30 {
		t.Errorf("home-auto = %v", auto)
	}
	if got := toStrings(auto["proxies"].([]any)); !slices.Equal(got, []string{"DIRECT", "wgfleet"}) {
		t.Errorf("home-auto proxies = %v, want DIRECT then wgfleet", got)
	}
	sel := group(t, doc, "home")
	if sel == nil || sel["type"] != "select" {
		t.Fatalf("home = %v", sel)
	}
	if got := toStrings(sel["proxies"].([]any)); !slices.Equal(got, []string{"home-auto", "DIRECT", "wgfleet"}) {
		t.Errorf("home proxies = %v", got)
	}
}

func TestClientProfileSiteWithoutProbeIsManual(t *testing.T) {
	doc := siteProfile(t, domain.ClientSite{Name: "office", CIDRs: []string{"192.168.50.0/24"}})
	if group(t, doc, "office-auto") != nil {
		t.Error("office-auto rendered without a probe")
	}
	sel := group(t, doc, "office")
	if got := toStrings(sel["proxies"].([]any)); !slices.Equal(got, []string{"DIRECT", "wgfleet"}) {
		t.Errorf("office proxies = %v, want DIRECT first (today's behaviour)", got)
	}
}

func TestClientProfileSiteProbeIntervalDefault(t *testing.T) {
	s := home
	s.ProbeInterval = 0
	if got := group(t, siteProfile(t, s), "home-auto")["interval"]; got != ClientSiteProbeInterval {
		t.Errorf("interval = %v, want %d", got, ClientSiteProbeInterval)
	}
}

// Site nets sit inside RFC1918 and may sit inside route_through_cidrs too; their
// rules come first or the broader rules swallow them. Only the proxy endpoints'
// own rules precede them: a master on a site's LAN still must not carry its own
// tunnel's packets.
func TestClientProfileSiteRulesComeFirst(t *testing.T) {
	rules := toStrings(siteProfile(t, home)["rules"].([]any))
	for len(rules) > 0 && strings.HasPrefix(rules[0], "AND,") && strings.HasSuffix(rules[0], ",DIRECT") {
		rules = rules[1:]
	}
	want := []string{"IP-CIDR,172.18.0.0/21,home", "IP-CIDR,172.26.1.0/24,home"}
	if !slices.Equal(rules[:2], want) {
		t.Errorf("first rules = %v, want %v", rules[:2], want)
	}
}

func TestClientProfileSiteNamesCannotCollide(t *testing.T) {
	for _, name := range []string{"", "auto", "wgfleet", "DIRECT", "REJECT", "m1", "m1-awg", "m1-vless", "a,b", "a#b"} {
		_, err := RenderClientProfile(ClientProfileInput{
			Sites:   []domain.ClientSite{{Name: name, CIDRs: []string{"192.168.1.0/24"}}},
			Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0")}},
		})
		if err == nil {
			t.Errorf("site %q accepted", name)
		}
	}
	_, err := RenderClientProfile(ClientProfileInput{
		Sites: []domain.ClientSite{{Name: "home", CIDRs: []string{"192.168.1.0/24"}},
			{Name: "home-auto", CIDRs: []string{"192.168.2.0/24"}}},
		Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0")}},
	})
	if err == nil || !strings.Contains(err.Error(), "home-auto") {
		t.Errorf("a site named like another site's auto group: err = %v", err)
	}
}

func TestClientProfileSiteAutoGroupCannotShadowMaster(t *testing.T) {
	_, err := RenderClientProfile(ClientProfileInput{
		Sites:   []domain.ClientSite{{Name: "home", CIDRs: []string{"192.168.1.0/24"}, ProbeURL: "http://192.168.1.1/"}},
		Masters: []ClientProfileMaster{{Name: "home-auto", AWG: profileAWG(t, "2.0")}},
	})
	if err == nil {
		t.Error("site home beside master home-auto rendered")
	}
}
