package mihomo

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

func awgFor(jc int) *domain.AWGParams {
	return &domain.AWGParams{
		Shared: domain.AWGShared{
			H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
			H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
			H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
			H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
			S1: 102, S2: 67, S3: 143, S4: 38,
		},
		Local: domain.AWGLocal{Jc: jc, Jmin: 60, Jmax: 900, I1: "<r 2><b 0xdeadbeef>"},
	}
}

func sampleInput() RenderInput {
	return RenderInput{
		PrivateKey: "MASTERPRIVKEYbase64ExampleValueForTestingABC=",
		Spec: domain.MasterSpec{
			BindAddress:        "10.80.0.1",
			RedirPort:          7895,
			ExternalController: "10.20.25.254:9090",
			Balance:            "consistent-hashing",
			DirectCIDRs:        []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			DirectGeo:          []string{"RU"},
			SnifferSkip:        []string{"+.themoviedb.org", "+.cloudfront.net"},
			ExitTunnels: []domain.ExitTunnel{
				{
					Name: "exit-a", Endpoint: "exit-a.example.net:36050",
					ServerPublicKey: "tonqJKi1LFkgd150tF0eNEJDGyeRqT40QlUCtnWUh3A=",
					TunnelIP:        "10.81.0.2", MTU: 1380, AWG: awgFor(7),
				},
				{
					Name: "exit-b", Endpoint: "exit-b.example.net:57102",
					ServerPublicKey: "H5MvraCiOLEIP6z+EHobf33Nt9EUdtjTRfO0vftZomg=",
					TunnelIP:        "10.82.0.2", MTU: 1380, AWG: awgFor(5),
				},
			},
		},
	}
}

func TestRenderConfigStructure(t *testing.T) {
	out, err := RenderConfig(sampleInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	// Parse it back to assert structure (mirrors the real ru-gw config).
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("rendered config is not valid YAML: %v\n%s", err, out)
	}

	if cfg["mode"] != "rule" || cfg["bind-address"] != "10.80.0.1" {
		t.Errorf("base settings wrong: mode=%v bind=%v", cfg["mode"], cfg["bind-address"])
	}
	if cfg["external-controller"] != "10.20.25.254:9090" {
		t.Errorf("external-controller = %v", cfg["external-controller"])
	}

	proxies, _ := cfg["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}
	p0, _ := proxies[0].(map[string]any)
	if p0["type"] != "wireguard" || p0["name"] != "exit-a" || p0["ip"] != "10.81.0.2" {
		t.Errorf("proxy[0] wrong: %+v", p0)
	}
	awg, ok := p0["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatalf("proxy[0] missing amnezia-wg-option: %+v", p0)
	}
	// H ranges must render as "min-max" strings.
	if awg["h1"] != "15384729-145384729" {
		t.Errorf("h1 = %v, want range string", awg["h1"])
	}
	if awg["jc"] != 7 {
		t.Errorf("exit-a jc = %v, want 7 (per-tunnel local param)", awg["jc"])
	}

	// Load-balance group over both exits.
	groups, _ := cfg["proxy-groups"].([]any)
	g0, _ := groups[0].(map[string]any)
	if g0["type"] != "load-balance" || g0["strategy"] != "consistent-hashing" {
		t.Errorf("LB group wrong: %+v", g0)
	}

	// Rules: direct-networks + RU geo + MATCH wg-best.
	rules, _ := cfg["rules"].([]any)
	joined := strings.Join(toStrings(rules), "\n")
	for _, want := range []string{"RULE-SET,direct-networks,DIRECT", "GEOSITE,category-ru,DIRECT", "GEOIP,RU,DIRECT,no-resolve", "MATCH,wg-best"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rules missing %q:\n%s", want, joined)
		}
	}
}

func TestRenderConfigExternalUIAndGeodata(t *testing.T) {
	// sampleInput has external-controller set and DirectGeo=["RU"].
	out, err := RenderConfig(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}

	// External dashboard is served alongside the API, downloaded via DIRECT.
	if cfg["external-ui"] != "ui" {
		t.Errorf("external-ui = %v, want ui", cfg["external-ui"])
	}
	if cfg["external-ui-download-detour"] != "DIRECT" {
		t.Errorf("external-ui-download-detour = %v, want DIRECT", cfg["external-ui-download-detour"])
	}
	if s, _ := cfg["external-ui-url"].(string); !strings.Contains(s, "zashboard") {
		t.Errorf("external-ui-url = %v", cfg["external-ui-url"])
	}

	// Geo databases are configured because DirectGeo is set, so the GEOSITE/GEOIP
	// rules can actually resolve.
	if cfg["geodata-mode"] != true {
		t.Errorf("geodata-mode = %v, want true", cfg["geodata-mode"])
	}
	geox, ok := cfg["geox-url"].(map[string]any)
	if !ok || geox["geoip"] == nil || geox["geosite"] == nil {
		t.Errorf("geox-url missing/incomplete: %v", cfg["geox-url"])
	}

	// Without geo rules, no geodata config and no UI when the API is off.
	noGeo := sampleInput()
	noGeo.Spec.DirectGeo = nil
	noGeo.Spec.ExternalController = ""
	out2, _ := RenderConfig(noGeo)
	var cfg2 map[string]any
	_ = yaml.Unmarshal([]byte(out2), &cfg2)
	if _, ok := cfg2["geox-url"]; ok {
		t.Error("geox-url should be absent when DirectGeo is empty")
	}
	if _, ok := cfg2["external-ui"]; ok {
		t.Error("external-ui should be absent when external-controller is unset")
	}
}

func TestRenderConfigDeterministic(t *testing.T) {
	a, _ := RenderConfig(sampleInput())
	b, _ := RenderConfig(sampleInput())
	if a != b {
		t.Error("render must be deterministic for stable dry-run diffs")
	}
}

func TestOverridesDeepMerge(t *testing.T) {
	in := sampleInput()
	in.Spec.Custom = domain.CustomConfig{
		Overrides: map[string]any{
			"log-level": "debug", // replace scalar
			"dns": map[string]any{ // merge into existing map
				"listen": "0.0.0.0:53",
			},
			"experimental": map[string]any{ // brand-new key
				"sniff-tls-sni": true,
			},
		},
	}
	out, err := RenderConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(out), &cfg)

	if cfg["log-level"] != "debug" {
		t.Errorf("override scalar failed: log-level=%v", cfg["log-level"])
	}
	dns, _ := cfg["dns"].(map[string]any)
	if dns["listen"] != "0.0.0.0:53" {
		t.Errorf("override merge failed: dns.listen=%v", dns["listen"])
	}
	// Merge must preserve untouched sibling keys.
	if dns["enable"] != true {
		t.Errorf("deep merge dropped sibling key dns.enable: %+v", dns)
	}
	exp, _ := cfg["experimental"].(map[string]any)
	if exp["sniff-tls-sni"] != true {
		t.Errorf("new override key missing: %+v", cfg["experimental"])
	}
}

func TestRenderRejectsUserspaceUnsafeAWG(t *testing.T) {
	in := sampleInput()
	in.Spec.ExitTunnels[0].AWG.Local.I4 = "<r 24><c>" // <c> breaks userspace
	if _, err := RenderConfig(in); err == nil {
		t.Fatal("expected error: mihomo is userspace, <c> tag must be rejected")
	}
}

func TestRenderDirectNetworks(t *testing.T) {
	out, err := RenderDirectNetworks(sampleInput().Spec)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := yaml.Unmarshal([]byte(out), &f); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	payload, _ := f["payload"].([]any)
	if len(payload) != 3 || payload[0] != "10.0.0.0/8" {
		t.Errorf("direct-networks payload wrong: %+v", payload)
	}
}

func TestRedactConfigMasksKeys(t *testing.T) {
	in := sampleInput()
	in.Spec.ExitTunnels[0].PresharedKey = "PSKsecretValue=="
	out, _ := RenderConfig(in)
	red := RedactConfig(out)

	if strings.Contains(red, in.PrivateKey) {
		t.Error("redaction leaked private key")
	}
	if strings.Contains(red, "PSKsecretValue==") {
		t.Error("redaction leaked preshared key")
	}
	if !strings.Contains(red, "private-key: <redacted>") {
		t.Errorf("private-key redaction marker missing:\n%s", red)
	}
}

func TestRenderRequiresExitsAndKey(t *testing.T) {
	in := sampleInput()
	in.PrivateKey = ""
	if _, err := RenderConfig(in); err == nil {
		t.Error("expected error without master private key")
	}
	in = sampleInput()
	in.Spec.ExitTunnels = nil
	if _, err := RenderConfig(in); err == nil {
		t.Error("expected error with no exit tunnels")
	}
}

func toStrings(s []any) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if str, ok := v.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func TestRenderDrainExcludesFromLBGroup(t *testing.T) {
	in := sampleInput()
	in.Spec.ExitTunnels[0].Drained = true // drain exit-a, keep exit-b

	out, err := RenderConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(out), &cfg)

	// Both proxies still rendered (existing connections survive).
	proxies, _ := cfg["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("drained proxy must still be rendered: %d proxies", len(proxies))
	}
	// LB group excludes the drained one.
	groups, _ := cfg["proxy-groups"].([]any)
	g0, _ := groups[0].(map[string]any)
	members := toStrings(g0["proxies"].([]any))
	if len(members) != 1 || members[0] != "exit-b" {
		t.Errorf("LB members = %v, want [exit-b] (exit-a drained)", members)
	}
}

func TestRenderRejectsAllDrained(t *testing.T) {
	in := sampleInput()
	for i := range in.Spec.ExitTunnels {
		in.Spec.ExitTunnels[i].Drained = true
	}
	if _, err := RenderConfig(in); err == nil {
		t.Fatal("expected error when all exits are drained (empty LB group)")
	}
}
