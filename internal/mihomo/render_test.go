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

func wgBestGroupOf(t *testing.T, balance string) map[string]any {
	t.Helper()
	in := sampleInput()
	in.Spec.Balance = balance
	out, err := RenderConfig(in)
	if err != nil {
		t.Fatalf("render(%q): %v", balance, err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	groups, _ := cfg["proxy-groups"].([]any)
	g, _ := groups[0].(map[string]any)
	return g
}

func TestRenderWGBestGroupKinds(t *testing.T) {
	// url-test → its own group type with a tolerance, no load-balance strategy.
	ut := wgBestGroupOf(t, "url-test")
	if ut["type"] != "url-test" {
		t.Errorf("url-test: type = %v, want url-test", ut["type"])
	}
	if ut["tolerance"] != urlTestToleranceMS {
		t.Errorf("url-test: tolerance = %v, want %d", ut["tolerance"], urlTestToleranceMS)
	}
	if _, ok := ut["strategy"]; ok {
		t.Errorf("url-test must not carry a load-balance strategy: %+v", ut)
	}

	// fallback → its own type, no strategy/tolerance.
	fb := wgBestGroupOf(t, "fallback")
	if fb["type"] != "fallback" {
		t.Errorf("fallback: type = %v, want fallback", fb["type"])
	}
	if _, ok := fb["strategy"]; ok {
		t.Errorf("fallback must not carry a strategy: %+v", fb)
	}

	// sticky-sessions / round-robin / empty → load-balance with that strategy.
	for in, want := range map[string]string{"sticky-sessions": "sticky-sessions", "round-robin": "round-robin", "": "round-robin"} {
		g := wgBestGroupOf(t, in)
		if g["type"] != "load-balance" || g["strategy"] != want {
			t.Errorf("balance %q → %+v, want load-balance/%s", in, g, want)
		}
		if _, ok := g["tolerance"]; ok {
			t.Errorf("load-balance must not emit tolerance: %+v", g)
		}
	}

	// Every kind keeps the health check that evicts dead exits.
	for _, b := range []string{"url-test", "fallback", "consistent-hashing"} {
		g := wgBestGroupOf(t, b)
		if g["url"] == nil || g["interval"] == nil {
			t.Errorf("balance %q lost its health check: %+v", b, g)
		}
	}
}

func TestRenderConfigHealthInterval(t *testing.T) {
	// Unset → DefaultHealthInterval.
	if g := wgBestGroupOf(t, "url-test"); g["interval"] != DefaultHealthInterval {
		t.Errorf("default health interval = %v, want %d", g["interval"], DefaultHealthInterval)
	}
	// Set → rendered verbatim (seconds).
	in := sampleInput()
	in.Spec.HealthCheckInterval = 30
	out, err := RenderConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	groups, _ := cfg["proxy-groups"].([]any)
	g, _ := groups[0].(map[string]any)
	if g["interval"] != 30 {
		t.Errorf("custom health interval = %v, want 30", g["interval"])
	}
}

func TestRenderConfigRejectsOwnRedirAddress(t *testing.T) {
	want := "IP-CIDR,10.80.0.1/32,REJECT,no-resolve" // sampleInput BindAddress

	firstRule := func(in RenderInput) any {
		out, err := RenderConfig(in)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatal(err)
		}
		rules, _ := cfg["rules"].([]any)
		if len(rules) == 0 {
			t.Fatal("no rules rendered")
		}
		return rules[0]
	}

	// Base: the reject of the bind address is the first rule.
	if got := firstRule(sampleInput()); got != want {
		t.Fatalf("first rule = %v, want %q", got, want)
	}
	// It must survive an operator rules-override (which replaces the whole list),
	// since the guard is injected after the override merge.
	in := sampleInput()
	in.Spec.Custom.Overrides = map[string]any{"rules": []any{"MATCH,wg-best"}}
	if got := firstRule(in); got != want {
		t.Fatalf("reject must survive a rules override as first rule, got %v", got)
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

	// Keepalive is a PROXY-level field in mihomo, not a peer field — assert it sits
	// on the proxy and NOT inside the peer (where mihomo would silently drop it).
	if p0["persistent-keepalive"] != 25 {
		t.Errorf("proxy[0] persistent-keepalive = %v, want 25 (proxy-level)", p0["persistent-keepalive"])
	}
	peers, _ := p0["peers"].([]any)
	peer0, _ := peers[0].(map[string]any)
	if _, ok := peer0["persistent-keepalive"]; ok {
		t.Errorf("peer must NOT carry persistent-keepalive (no such mihomo peer field): %+v", peer0)
	}

	// Load-balance group over both exits.
	groups, _ := cfg["proxy-groups"].([]any)
	g0, _ := groups[0].(map[string]any)
	if g0["type"] != "load-balance" || g0["strategy"] != "consistent-hashing" {
		t.Errorf("LB group wrong: %+v", g0)
	}
	// `tolerance` is a url-test-only key; it must not appear on a load-balance group.
	if _, ok := g0["tolerance"]; ok {
		t.Errorf("load-balance group must not emit `tolerance` (url-test only): %+v", g0)
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

	// The dashboard dir is served alongside the API, but the config must NOT carry a
	// download URL or detour: the agent populates the dir and mihomo only serves it
	// (mihomo's own download follows the proxy rules and stalls — see dashboardPlanner).
	if cfg["external-ui"] != "ui" {
		t.Errorf("external-ui = %v, want ui", cfg["external-ui"])
	}
	if _, ok := cfg["external-ui-url"]; ok {
		t.Errorf("external-ui-url must not be emitted (agent downloads the dashboard)")
	}
	if _, ok := cfg["external-ui-download-detour"]; ok {
		t.Errorf("external-ui-download-detour must not be emitted")
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
	outNoGeo, _ := RenderConfig(noGeo)
	var cfgNoGeo map[string]any
	_ = yaml.Unmarshal([]byte(outNoGeo), &cfgNoGeo)
	if _, ok := cfgNoGeo["geox-url"]; ok {
		t.Error("geox-url should be absent when DirectGeo is empty")
	}
	if _, ok := cfgNoGeo["external-ui"]; ok {
		t.Error("external-ui should be absent when external-controller is unset")
	}
}

func TestRenderDashboardURLOverrideAndDisable(t *testing.T) {
	// A DashboardURL override drives the AGENT's download, not the rendered config:
	// the config still just serves the dir, and never carries the URL.
	in := sampleInput()
	in.Spec.DashboardURL = "https://mirror.example.ru/metacubexd.tgz"
	out, err := RenderConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(out), &cfg)
	if cfg["external-ui"] != "ui" {
		t.Errorf("dashboard should still be served with an override: %v", cfg["external-ui"])
	}
	if _, ok := cfg["external-ui-url"]; ok {
		t.Errorf("external-ui-url must never be emitted, even with a DashboardURL override")
	}

	// Disabled → no external-ui / external-ui-url, but the API still binds.
	in2 := sampleInput()
	in2.Spec.DashboardDisabled = true
	out2, err := RenderConfig(in2)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 map[string]any
	_ = yaml.Unmarshal([]byte(out2), &cfg2)
	if _, ok := cfg2["external-ui"]; ok {
		t.Errorf("disabled dashboard must not emit external-ui")
	}
	if _, ok := cfg2["external-ui-url"]; ok {
		t.Errorf("disabled dashboard must not emit external-ui-url")
	}
	if _, ok := cfg2["external-ui-download-detour"]; ok {
		t.Errorf("disabled dashboard must not emit external-ui-download-detour")
	}
	if cfg2["external-controller"] != "10.20.25.254:9090" {
		t.Errorf("API must still bind when only the dashboard is disabled: %v", cfg2["external-controller"])
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

func proxyByName(t *testing.T, cfg string, name string) map[string]any {
	t.Helper()
	var c map[string]any
	if err := yaml.Unmarshal([]byte(cfg), &c); err != nil {
		t.Fatal(err)
	}
	for _, p := range c["proxies"].([]any) {
		m := p.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func TestRenderRealityProxy(t *testing.T) {
	in := sampleInput()
	// A REALITY/XHTTP standby beside the two AWG exits: rendered as a proxy but
	// drained ⇒ kept out of the wg-best group (ADR-0025 warm standby).
	in.Spec.ExitTunnels = append(in.Spec.ExitTunnels, domain.ExitTunnel{
		Name: "exit-a-reality", Endpoint: "exit-a.example.net:443",
		Transport: domain.TransportRealityXHTTP, Drained: true,
		Reality: &domain.RealityTunnel{
			UUID: "11111111-2222-3333-4444-555555555555", PublicKey: "RPUBKEYbase64==",
			ShortID: "0badc0de", ServerName: "www.microsoft.com", XHTTPPath: "/down",
		},
	})
	out, err := RenderConfig(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	p := proxyByName(t, out, "exit-a-reality")
	if p == nil {
		t.Fatal("reality proxy not rendered")
	}
	if p["type"] != "vless" || p["network"] != "xhttp" || p["tls"] != true {
		t.Errorf("reality proxy core fields wrong: %+v", p)
	}
	if p["servername"] != "www.microsoft.com" {
		t.Errorf("servername wrong: %v", p["servername"])
	}
	// client-fingerprint is a TOP-LEVEL key (defaults to chrome), not under reality-opts.
	if p["client-fingerprint"] != "chrome" {
		t.Errorf("client-fingerprint = %v, want chrome (top-level)", p["client-fingerprint"])
	}
	// Vision must NOT be set — incompatible with XHTTP.
	if _, hasFlow := p["flow"]; hasFlow {
		t.Error("reality+xhttp proxy must not set flow (Vision is incompatible with XHTTP)")
	}
	ro, _ := p["reality-opts"].(map[string]any)
	if ro == nil || ro["public-key"] != "RPUBKEYbase64==" || ro["short-id"] != "0badc0de" {
		t.Errorf("reality-opts wrong: %+v", ro)
	}
	xo, _ := p["xhttp-opts"].(map[string]any)
	if xo == nil || xo["mode"] != "packet-up" || xo["path"] != "/down" {
		t.Errorf("xhttp-opts wrong: %+v", xo)
	}

	// Drained ⇒ excluded from wg-best; the two AWG exits remain.
	var c map[string]any
	_ = yaml.Unmarshal([]byte(out), &c)
	g := c["proxy-groups"].([]any)[0].(map[string]any)
	members := g["proxies"].([]any)
	for _, m := range members {
		if m == "exit-a-reality" {
			t.Error("drained reality proxy must not be in wg-best")
		}
	}
	if len(members) != 2 {
		t.Errorf("wg-best members = %d, want 2 (the AWG exits)", len(members))
	}
}

func TestRenderRealityFingerprintAndEmptySNI(t *testing.T) {
	mk := func(tune func(*domain.RealityTunnel)) map[string]any {
		in := sampleInput()
		rt := &domain.RealityTunnel{
			UUID: "u", PublicKey: "PK", ShortID: "0badc0de",
			ServerName: "www.microsoft.com", XHTTPPath: "/down",
		}
		tune(rt)
		in.Spec.ExitTunnels = append(in.Spec.ExitTunnels, domain.ExitTunnel{
			Name: "exit-a-reality", Endpoint: "203.0.113.7:443",
			Transport: domain.TransportRealityXHTTP, Drained: true, Reality: rt,
		})
		out, err := RenderConfig(in)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		return proxyByName(t, out, "exit-a-reality")
	}

	// firefox fingerprint passes through.
	if p := mk(func(rt *domain.RealityTunnel) { rt.Fingerprint = "firefox" }); p["client-fingerprint"] != "firefox" {
		t.Errorf("fingerprint = %v, want firefox", p["client-fingerprint"])
	}
	// "none" omits client-fingerprint entirely (Go-default uTLS).
	if p := mk(func(rt *domain.RealityTunnel) { rt.Fingerprint = "none" }); func() bool { _, ok := p["client-fingerprint"]; return ok }() {
		t.Errorf("fingerprint=none must omit client-fingerprint, got %v", p["client-fingerprint"])
	}
	// empty ⇒ chrome default (back-compat).
	if p := mk(func(rt *domain.RealityTunnel) {}); p["client-fingerprint"] != "chrome" {
		t.Errorf("default fingerprint = %v, want chrome", p["client-fingerprint"])
	}
	// EmptySNI ⇒ servername set to the exit IP placeholder (so uTLS omits SNI).
	if p := mk(func(rt *domain.RealityTunnel) { rt.EmptySNI = true }); p["servername"] != "203.0.113.7" {
		t.Errorf("EmptySNI servername = %v, want 203.0.113.7 (IP placeholder)", p["servername"])
	}
}
