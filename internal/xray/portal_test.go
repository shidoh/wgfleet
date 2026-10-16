package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func portalInput() PortalRenderInput {
	return PortalRenderInput{
		Spec: domain.RealityPortalSpec{
			ListenPort: 48123, ServerName: "www.python.org", Dest: "www.python.org:443", Image: "img",
			Clients: []domain.RealityPortalClient{
				{Exit: "vn0", UUID: "11111111-0000-4000-8000-000000000001", ShortID: "0a0b"},
				{Exit: "1cx0", UUID: "11111111-0000-4000-8000-000000000002", ShortID: "0c0d"},
			},
		},
		PrivateKey:     "cHJpdmF0ZQ",
		SocksAddr:      "100.127.255.1",
		SocksPasswords: map[string]string{"vn0": "pw-vn0", "1cx0": "pw-1cx0"},
	}
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return m
}

func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func TestRenderPortal(t *testing.T) {
	out, err := RenderPortalConfig(portalInput())
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)

	in := at(m, "inbounds", 0)
	if at(in, "tag") != "portal" || at(in, "port").(float64) != 48123 || at(in, "listen") != "0.0.0.0" || at(in, "protocol") != "vless" {
		t.Errorf("portal inbound = %v", in)
	}
	if at(in, "streamSettings", "network") != "raw" || at(in, "streamSettings", "security") != "reality" {
		t.Errorf("portal stream = %v", at(in, "streamSettings"))
	}
	if _, ok := at(in, "streamSettings").(map[string]any)["xhttpSettings"]; ok {
		t.Error("portal carries XHTTP")
	}
	rs := at(in, "streamSettings", "realitySettings")
	if at(rs, "target") != "www.python.org:443" || at(rs, "privateKey") != "cHJpdmF0ZQ" {
		t.Errorf("reality settings = %v", rs)
	}
	if ids := at(rs, "shortIds").([]any); len(ids) != 2 || ids[0] != "0a0b" || ids[1] != "0c0d" {
		t.Errorf("shortIds = %v, want only the issued ones", ids)
	}
	so := at(in, "streamSettings", "sockopt")
	if at(so, "tcpKeepAliveIdle").(float64) != 10 || at(so, "tcpKeepAliveInterval").(float64) != 5 || at(so, "tcpUserTimeout").(float64) != 20000 {
		t.Errorf("portal sockopt = %v", so)
	}
	c0 := at(in, "settings", "clients", 0)
	if at(c0, "id") != "11111111-0000-4000-8000-000000000001" || at(c0, "email") != "bridge:vn0" || at(c0, "reverse", "tag") != "r-vn0" {
		t.Errorf("client 0 = %v", c0)
	}
	if _, ok := c0.(map[string]any)["flow"]; ok {
		t.Error("portal client has a vision flow")
	}

	socks := at(m, "inbounds", 1)
	if at(socks, "tag") != "socks" || at(socks, "listen") != "100.127.255.1" || at(socks, "port").(float64) != domain.RealityPortalSocksPort {
		t.Errorf("socks inbound = %v", socks)
	}
	// The UDP ASSOCIATE reply carries settings.ip; left unset it names 127.0.0.1,
	// which mihomo in its namespace cannot reach.
	if at(socks, "settings", "ip") != "100.127.255.1" || at(socks, "settings", "udp") != true || at(socks, "settings", "auth") != "password" {
		t.Errorf("socks settings = %v", at(socks, "settings"))
	}
	if a := at(socks, "settings", "accounts", 1); at(a, "user") != "1cx0" || at(a, "pass") != "pw-1cx0" {
		t.Errorf("socks account 1 = %v", a)
	}

	rules := at(m, "routing", "rules").([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %v, want one per exit", rules)
	}
	r1 := rules[1]
	if at(r1, "outboundTag") != "r-1cx0" || at(r1, "user", 0) != "1cx0" || at(r1, "inboundTag", 0) != "socks" {
		t.Errorf("rule 1 = %v", r1)
	}
	if at(m, "dns", "queryStrategy") != "UseIPv4" {
		t.Errorf("dns = %v, want IPv4 pinning by default", at(m, "dns"))
	}
}

// Nothing reaching the portal may leave the master: the only outbound is a
// blackhole (first, so it is the default), the reverse tags are the only other
// destinations.
func TestRenderPortalHasNoDirectOutbound(t *testing.T) {
	out, err := RenderPortalConfig(portalInput())
	if err != nil {
		t.Fatal(err)
	}
	obs := at(decode(t, out), "outbounds").([]any)
	if len(obs) != 1 || at(obs[0], "protocol") != "blackhole" {
		t.Fatalf("outbounds = %v, want exactly one blackhole", obs)
	}
	for _, banned := range []string{`"freedom"`, `"direct"`} {
		if strings.Contains(out, banned) {
			t.Errorf("portal config mentions %s", banned)
		}
	}
}

// An exit with no password would be served unauthenticated by nothing — refuse
// to render rather than drop it silently.
func TestRenderPortalRefuses(t *testing.T) {
	cases := map[string]func(*PortalRenderInput){
		"no private key":   func(in *PortalRenderInput) { in.PrivateKey = "" },
		"no socks addr":    func(in *PortalRenderInput) { in.SocksAddr = "" },
		"missing password": func(in *PortalRenderInput) { delete(in.SocksPasswords, "1cx0") },
		"bad spec":         func(in *PortalRenderInput) { in.Spec.ListenPort = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := portalInput()
			in.SocksPasswords = map[string]string{"vn0": "pw-vn0", "1cx0": "pw-1cx0"}
			mutate(&in)
			if _, err := RenderPortalConfig(in); err == nil {
				t.Fatal("rendered anyway")
			}
		})
	}
}

// A portal with no exit yet admits nobody: xray refuses an empty shortIds list,
// and "" would admit anyone holding the public key.
func TestRenderPortalWithoutClientsAdmitsNobody(t *testing.T) {
	in := portalInput()
	in.Spec.Clients = nil
	out, err := RenderPortalConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	ids := at(decode(t, out), "inbounds", 0, "streamSettings", "realitySettings", "shortIds").([]any)
	if len(ids) != 1 || ids[0] == "" {
		t.Errorf("shortIds = %v, want one unissued id", ids)
	}
}
