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
	// shortIds carries "" plus the configured one.
	sids := rs["shortIds"].([]any)
	if len(sids) != 2 || sids[0] != "" || sids[1] != "0badc0de" {
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
