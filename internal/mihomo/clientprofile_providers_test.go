package mihomo

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

const testProviderURL = "http://192.0.2.10:9001/c/0123456789abcdef/mihomo/proxies"

func providerFixture(t *testing.T) ClientProfileInput {
	t.Helper()
	return ClientProfileInput{Masters: []ClientProfileMaster{
		{Name: "m1", AWG: profileAWG(t, "2.0"), VLESS: profileVLESS(domain.RealityModeXHTTP), VLESSLastResort: true, DNS: []string{"10.80.0.1"}},
		{Name: "m1-x", AWG: profileAWG(t, "2.0"), VLESS: profileVLESS(domain.RealityModeXHTTP)},
		{Name: "m3", VLESS: profileVLESS(domain.RealityModeXHTTP)},
	}}
}

// expand resolves a group's members the way mihomo does: `proxies:` first, then
// each provider in `use` order, filtered by the group's regex. The AmneziaWG
// provider's content is what the portal serves for it.
func expand(t *testing.T, doc map[string]any, awg []any, group string) []string {
	t.Helper()
	g := groupNamed(t, doc, group)
	var out []string
	if ps, ok := g["proxies"].([]any); ok {
		out = append(out, toStrings(ps)...)
	}
	var filter *regexp.Regexp
	if f, ok := g["filter"].(string); ok {
		filter = regexp.MustCompile(f)
	}
	providers := doc["proxy-providers"].(map[string]any)
	for _, u := range toStrings(asSlice(g["use"])) {
		p := providers[u].(map[string]any)
		payload := asSlice(p["payload"])
		if p["type"] == "http" {
			payload = awg
		}
		for _, x := range payload {
			name := x.(map[string]any)["name"].(string)
			if filter == nil || filter.MatchString(name) {
				out = append(out, name)
			}
		}
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func providerAWG(t *testing.T, in ClientProfileInput) []any {
	t.Helper()
	out, err := RenderClientProviderProxies(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	return doc["proxies"].([]any)
}

// The provider form must be the inline profile with its proxies moved, not a new
// policy: every group, expanded as mihomo expands it, holds the same proxies in
// the same order — plus the reject proxy closing it.
func TestProviderProfileGroupsMatchTheInlineProfile(t *testing.T) {
	in := providerFixture(t)
	inline := renderProfile(t, in)
	in.ProviderURL = testProviderURL
	prov := renderProfile(t, in)
	awg := providerAWG(t, in)

	for _, name := range []string{"m1", "m1-x", "m3", ClientProfileAutoGroup} {
		want := append(toStrings(groupNamed(t, inline, name)["proxies"].([]any)), ClientProfileBlockedProxy)
		if got := expand(t, prov, awg, name); !reflect.DeepEqual(got, want) {
			t.Errorf("group %s = %v, want %v", name, got, want)
		}
	}
	want := toStrings(groupNamed(t, inline, ClientProfileSelectGroup)["proxies"].([]any))
	if got := expand(t, prov, awg, ClientProfileSelectGroup); !reflect.DeepEqual(got, want) {
		t.Errorf("select = %v, want %v (no reject proxy to pick by hand)", got, want)
	}
	// Same proxies, not lookalikes: the provider serves exactly what the inline
	// profile carried.
	for _, p := range awg {
		name := p.(map[string]any)["name"].(string)
		if !reflect.DeepEqual(p, proxyNamed(t, inline, name)) {
			t.Errorf("provider proxy %s differs from the inline one", name)
		}
	}
	if _, has := prov["proxies"]; has {
		t.Error("provider profile still carries top-level proxies: a group lists them before its providers")
	}
	// Everything outside the proxies is untouched.
	for _, k := range []string{"rules", "dns", "mode", "ipv6"} {
		if !reflect.DeepEqual(prov[k], inline[k]) {
			t.Errorf("%s differs between the inline and the provider profile", k)
		}
	}
}

func TestProviderProfileFetchesAWGThroughTheFallback(t *testing.T) {
	in := providerFixture(t)
	in.ProviderURL = testProviderURL
	doc := renderProfile(t, in)
	p := doc["proxy-providers"].(map[string]any)[ClientProviderAWG].(map[string]any)
	if p["type"] != "http" || p["url"] != testProviderURL || p["proxy"] != ClientProfileAutoGroup ||
		p["interval"] != ClientProviderInterval {
		t.Errorf("awg provider = %v", p)
	}
	guard := doc["proxy-providers"].(map[string]any)[ClientProviderGuard].(map[string]any)
	if !strings.Contains(strings.Join(nameTypes(guard["payload"]), ","), ClientProfileBlockedProxy+":reject") {
		t.Errorf("guard provider = %v, want a reject proxy", guard)
	}
}

func nameTypes(v any) []string {
	var out []string
	for _, x := range asSlice(v) {
		m := x.(map[string]any)
		out = append(out, m["name"].(string)+":"+m["type"].(string))
	}
	return out
}

// Without VLESS the provider could never be fetched — it is reached through the
// tunnel, and before its first fetch there is no AmneziaWG proxy to reach it
// over. Such a device keeps the inline profile.
func TestProviderProfileNeedsVLESSToBootstrap(t *testing.T) {
	in := ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0")}}}
	inline, err := RenderClientProfile(in)
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderURL = testProviderURL
	got, err := RenderClientProfile(in)
	if err != nil {
		t.Fatal(err)
	}
	if got != inline {
		t.Errorf("an AmneziaWG-only device got the provider form:\n%s", got)
	}
}

// A profile with no AmneziaWG gets no provider to fetch, and no empty inline
// provider either.
func TestProviderProfileVLESSOnlyHasNoAWGProvider(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{ProviderURL: testProviderURL,
		Masters: []ClientProfileMaster{{Name: "m1", VLESS: profileVLESS(domain.RealityModeXHTTP)}}})
	providers := doc["proxy-providers"].(map[string]any)
	for _, absent := range []string{ClientProviderAWG, ClientProviderLastResort} {
		if _, has := providers[absent]; has {
			t.Errorf("provider %s rendered with nothing in it", absent)
		}
	}
	if _, err := RenderClientProviderProxies(ClientProfileInput{
		Masters: []ClientProfileMaster{{Name: "m1", VLESS: profileVLESS(domain.RealityModeXHTTP)}}}); err == nil {
		t.Error("RenderClientProviderProxies served an empty provider")
	}
}

func TestProfileRefusesASiteNamedLikeTheBlockedProxy(t *testing.T) {
	_, err := RenderClientProfile(ClientProfileInput{
		Masters: []ClientProfileMaster{{Name: "m1", VLESS: profileVLESS(domain.RealityModeXHTTP)}},
		Sites:   []domain.ClientSite{{Name: ClientProfileBlockedProxy, CIDRs: []string{"192.168.1.0/24"}}},
	})
	if err == nil {
		t.Error("a site named like the reject proxy was accepted")
	}
}
