package xray

import (
	"slices"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func bridgeInput() BridgeRenderInput {
	return BridgeRenderInput{
		Spec: domain.RealityServerSpec{Image: "img", Bridge: &domain.RealityBridgeSpec{Portals: []domain.RealityPortalPeer{
			{Master: "xa-1", Address: "203.0.113.1:48123", PublicKey: "pk1", UUID: "u1", ShortID: "0a0b", ServerName: "www.python.org"},
			{Master: "xa-2", Address: "203.0.113.2:41000", PublicKey: "pk2", UUID: "u2", ShortID: "0c0d", ServerName: "a.example", Fingerprint: "firefox"},
		}}},
		EgressMark: EgressMark,
	}
}

func TestRenderBridge(t *testing.T) {
	out, err := RenderBridgeConfig(bridgeInput())
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	if _, ok := m["inbounds"]; ok {
		t.Error("the bridge listens on something")
	}
	obs := at(m, "outbounds").([]any)
	if len(obs) != 3 {
		t.Fatalf("outbounds = %v, want freedom + one per portal", obs)
	}

	// Freedom first: anything no rule claims leaves through the egress, never
	// back up a reverse flow.
	direct := obs[0]
	if at(direct, "tag") != "direct" || at(direct, "protocol") != "freedom" {
		t.Fatalf("outbound 0 = %v, want the freedom egress", direct)
	}
	if at(direct, "streamSettings", "sockopt", "mark").(float64) != EgressMark {
		t.Errorf("freedom sockopt = %v, want the egress mark", at(direct, "streamSettings", "sockopt"))
	}
	if at(direct, "settings", "domainStrategy") != "UseIPv4" {
		t.Errorf("freedom settings = %v", at(direct, "settings"))
	}
	// Freedom blocks everything from a reverse link unless told otherwise, and the
	// master's streams must not reach the exit's own private ranges.
	fr := at(direct, "settings", "finalRules").([]any)
	if len(fr) != 2 || at(fr[0], "action") != "block" || at(fr[1], "action") != "allow" {
		t.Fatalf("finalRules = %v, want block then allow", fr)
	}
	var blocked []string
	for _, c := range at(fr[0], "ip").([]any) {
		blocked = append(blocked, c.(string))
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
		"100.64.0.0/10", "0.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128",
		"::/128", "::ffff:0:0/96", "64:ff9b::/96", "fec0::/10", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"} {
		if !slices.Contains(blocked, want) {
			t.Errorf("finalRules block list misses %s: %v", want, blocked)
		}
	}

	p1 := obs[1]
	if at(p1, "tag") != "to-xa-1" || at(p1, "protocol") != "vless" {
		t.Errorf("outbound 1 = %v", p1)
	}
	// Xray takes reverse only on the simplified outbound form; vnext is refused.
	st := at(p1, "settings")
	if at(st, "address") != "203.0.113.1" || at(st, "port").(float64) != 48123 || at(st, "id") != "u1" ||
		at(st, "encryption") != "none" || at(st, "reverse", "tag") != "r-xa-1" {
		t.Errorf("portal outbound settings = %v", st)
	}
	if _, ok := st.(map[string]any)["vnext"]; ok {
		t.Error("portal outbound uses vnext")
	}
	rs := at(p1, "streamSettings", "realitySettings")
	if at(rs, "serverName") != "www.python.org" || at(rs, "fingerprint") != "chrome" || at(rs, "publicKey") != "pk1" || at(rs, "shortId") != "0a0b" {
		t.Errorf("reality client = %v", rs)
	}
	if at(obs[2], "streamSettings", "realitySettings", "fingerprint") != "firefox" {
		t.Error("explicit fingerprint not used")
	}
	// No mark: an unmarked host socket never enters the egress (WARP) table, so
	// the bridge reaches the master over the exit's own uplink.
	so := at(p1, "streamSettings", "sockopt").(map[string]any)
	if _, marked := so["mark"]; marked {
		t.Errorf("portal dial carries a mark: %v", so)
	}
	if so["tcpKeepAliveIdle"].(float64) != 10 || so["tcpKeepAliveInterval"].(float64) != 5 || so["tcpUserTimeout"].(float64) != 20000 {
		t.Errorf("portal dial sockopt = %v", so)
	}

	rules := at(m, "routing", "rules").([]any)
	if len(rules) != 1 || at(rules[0], "outboundTag") != "direct" {
		t.Fatalf("rules = %v, want every reverse tag to the egress", rules)
	}
	tags := at(rules[0], "inboundTag").([]any)
	if len(tags) != 2 || tags[0] != "r-xa-1" || tags[1] != "r-xa-2" {
		t.Errorf("reverse tags routed = %v", tags)
	}
}

func TestRenderBridgeDirectEgressHasNoMark(t *testing.T) {
	in := bridgeInput()
	in.EgressMark = 0
	in.Spec.AllowIPv6 = true
	out, err := RenderBridgeConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	direct := at(decode(t, out), "outbounds", 0).(map[string]any)
	if _, ok := direct["streamSettings"]; ok {
		t.Errorf("direct egress carries sockopt: %v", direct)
	}
	// Domains are still resolved before the block list applies: AsIs would hand
	// freedom a name the IP rules never see.
	if at(direct, "settings", "domainStrategy") != "UseIP" {
		t.Errorf("freedom domainStrategy = %v, want UseIP", at(direct, "settings", "domainStrategy"))
	}
	if strings.Contains(out, "UseIPv4") {
		t.Error("IPv4 pinned although IPv6 is allowed")
	}
}

func TestRenderBridgeRefusesAnInvalidBridge(t *testing.T) {
	for name, mutate := range map[string]func(*BridgeRenderInput){
		"no bridge":  func(in *BridgeRenderInput) { in.Spec.Bridge = nil },
		"no portals": func(in *BridgeRenderInput) { in.Spec.Bridge = &domain.RealityBridgeSpec{} },
		"bad addr":   func(in *BridgeRenderInput) { in.Spec.Bridge.Portals[0].Address = "x" },
	} {
		t.Run(name, func(t *testing.T) {
			in := bridgeInput()
			mutate(&in)
			if _, err := RenderBridgeConfig(in); err == nil {
				t.Fatal("rendered anyway")
			}
		})
	}
}
