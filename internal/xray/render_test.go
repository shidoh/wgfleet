package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func sampleSpec() domain.RealityServerSpec {
	return domain.RealityServerSpec{
		ListenPort: 443,
		UUID:       "11111111-2222-3333-4444-555555555555",
		ShortID:    "0badc0de",
		ServerName: "www.microsoft.com",
		Dest:       "www.microsoft.com:443",
		XHTTPPath:  "/down",
	}
}

func TestRenderConfigStructure(t *testing.T) {
	out, err := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "PRIVKEY", EgressMark: EgressMark})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var c map[string]any
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("rendered config is not valid JSON: %v\n%s", err, out)
	}
	inb := c["inbounds"].([]any)[0].(map[string]any)
	if inb["protocol"] != "vless" || inb["port"].(float64) != 443 {
		t.Errorf("inbound core wrong: %+v", inb)
	}
	ss := inb["streamSettings"].(map[string]any)
	if ss["network"] != "xhttp" || ss["security"] != "reality" {
		t.Errorf("streamSettings wrong: %+v", ss)
	}
	rs := ss["realitySettings"].(map[string]any)
	if rs["target"] != "www.microsoft.com:443" {
		t.Errorf("target wrong: %v", rs["target"])
	}
	if rs["privateKey"] != "PRIVKEY" {
		t.Errorf("private key not injected: %v", rs["privateKey"])
	}
	names := rs["serverNames"].([]any)
	if len(names) != 1 || names[0] != "www.microsoft.com" {
		t.Errorf("serverNames wrong: %v", names)
	}
	// shortIds carries only the configured one: "" would admit a client that
	// sends no short-id at all.
	sids := rs["shortIds"].([]any)
	if len(sids) != 1 || sids[0] != "0badc0de" {
		t.Errorf("shortIds wrong: %v", sids)
	}
	xs := ss["xhttpSettings"].(map[string]any)
	if xs["mode"] != "packet-up" || xs["path"] != "/down" {
		t.Errorf("xhttpSettings wrong: %+v", xs)
	}
	// The freedom outbound must mark sockets for the WARP egress path.
	outb := c["outbounds"].([]any)[0].(map[string]any)
	mark := outb["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["mark"].(float64)
	if int(mark) != EgressMark {
		t.Errorf("egress mark = %v, want %d", mark, EgressMark)
	}
}

func TestRenderConfigEmptySNI(t *testing.T) {
	s := sampleSpec()
	s.AllowEmptySNI = true
	out, err := RenderConfig(RenderInput{Spec: s, PrivateKey: "K"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var c map[string]any
	_ = json.Unmarshal([]byte(out), &c)
	rs := c["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	names := rs["serverNames"].([]any)
	if len(names) != 2 || names[0] != "" || names[1] != "www.microsoft.com" {
		t.Errorf("AllowEmptySNI serverNames = %v, want [\"\", www.microsoft.com]", names)
	}
}

func TestRenderConfigIPv4Pin(t *testing.T) {
	// Default (AllowIPv6 false) ⇒ dns.queryStrategy UseIPv4 + freedom domainStrategy UseIPv4.
	out, _ := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K", EgressMark: EgressMark})
	var c map[string]any
	_ = json.Unmarshal([]byte(out), &c)
	dns, _ := c["dns"].(map[string]any)
	if dns == nil || dns["queryStrategy"] != "UseIPv4" {
		t.Errorf("expected dns.queryStrategy UseIPv4, got %v", c["dns"])
	}
	fs, _ := c["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	if fs == nil || fs["domainStrategy"] != "UseIPv4" {
		t.Errorf("expected freedom domainStrategy UseIPv4, got %v", fs)
	}

	// AllowIPv6 true ⇒ no dns block; freedom still resolves (UseIP) so its block
	// list sees the address a name points at.
	s := sampleSpec()
	s.AllowIPv6 = true
	out2, _ := RenderConfig(RenderInput{Spec: s, PrivateKey: "K"})
	var c2 map[string]any
	_ = json.Unmarshal([]byte(out2), &c2)
	if _, has := c2["dns"]; has {
		t.Error("AllowIPv6 must omit the dns block")
	}
}

func TestRenderConfigVisionMode(t *testing.T) {
	s := sampleSpec()
	s.Mode = domain.RealityModeVision
	out, err := RenderConfig(RenderInput{Spec: s, PrivateKey: "K"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var c map[string]any
	_ = json.Unmarshal([]byte(out), &c)
	ss := c["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if ss["network"] != "tcp" {
		t.Errorf("vision network = %v, want tcp", ss["network"])
	}
	if _, has := ss["xhttpSettings"]; has {
		t.Error("vision mode must omit xhttpSettings")
	}
	cl := c["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	if cl["flow"] != "xtls-rprx-vision" {
		t.Errorf("vision client flow = %v, want xtls-rprx-vision", cl["flow"])
	}
}

func TestRenderConfigDeterministic(t *testing.T) {
	a, _ := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K", EgressMark: 0})
	b, _ := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K", EgressMark: 0})
	if a != b {
		t.Error("render is not deterministic")
	}
	// EgressMark 0 ⇒ no sockopt block (direct egress).
	if strings.Contains(a, "sockopt") {
		t.Error("EgressMark 0 must not emit a sockopt block")
	}
}

func TestRenderConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		in   RenderInput
		want string
	}{
		{"no key", RenderInput{Spec: sampleSpec()}, "private key"},
		{"bad port", RenderInput{Spec: func() domain.RealityServerSpec { s := sampleSpec(); s.ListenPort = 0; return s }(), PrivateKey: "K"}, "listen port"},
		{"no uuid", RenderInput{Spec: func() domain.RealityServerSpec { s := sampleSpec(); s.UUID = ""; return s }(), PrivateKey: "K"}, "uuid"},
		{"no sni", RenderInput{Spec: func() domain.RealityServerSpec { s := sampleSpec(); s.ServerName = ""; return s }(), PrivateKey: "K"}, "server name"},
		{"no dest", RenderInput{Spec: func() domain.RealityServerSpec { s := sampleSpec(); s.Dest = ""; return s }(), PrivateKey: "K"}, "dest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RenderConfig(tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRedactConfig(t *testing.T) {
	out, _ := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "SECRETKEY", EgressMark: 0})
	red := RedactConfig(out)
	if strings.Contains(red, "SECRETKEY") {
		t.Error("private key leaked through redaction")
	}
	if !strings.Contains(red, "REDACTED") {
		t.Error("redaction marker missing")
	}
}

// The exit's proxied egress may not reach its own loopback, private or other
// special ranges: whoever holds the tunnel's credentials gets the internet
// through the exit, not the exit's host and neighbours. Same list as the bridge.
func TestRenderConfigFreedomBlocksSpecialRanges(t *testing.T) {
	for _, allowIPv6 := range []bool{false, true} {
		s := sampleSpec()
		s.AllowIPv6 = allowIPv6
		out, err := RenderConfig(RenderInput{Spec: s, PrivateKey: "K", EgressMark: EgressMark})
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		var c struct {
			Outbounds []struct {
				Protocol string `json:"protocol"`
				Settings struct {
					DomainStrategy string `json:"domainStrategy"`
					FinalRules     []struct {
						Action string   `json:"action"`
						IP     []string `json:"ip"`
					} `json:"finalRules"`
				} `json:"settings"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(out), &c); err != nil {
			t.Fatal(err)
		}
		f := c.Outbounds[0]
		if f.Protocol != "freedom" {
			t.Fatalf("first outbound is %q, want freedom", f.Protocol)
		}
		// A name must be resolved before the rules run, or it reaches 127.0.0.1 unseen.
		if f.Settings.DomainStrategy == "" || f.Settings.DomainStrategy == "AsIs" {
			t.Errorf("allowIPv6=%v: freedom domainStrategy %q lets names past the block list", allowIPv6, f.Settings.DomainStrategy)
		}
		rules := f.Settings.FinalRules
		if len(rules) != 2 || rules[0].Action != "block" || rules[1].Action != "allow" {
			t.Fatalf("allowIPv6=%v: finalRules = %+v, want block list then allow", allowIPv6, rules)
		}
		for _, cidr := range []string{"127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7"} {
			if !strings.Contains(strings.Join(rules[0].IP, " "), cidr) {
				t.Errorf("allowIPv6=%v: %s is not blocked", allowIPv6, cidr)
			}
		}
	}
}
