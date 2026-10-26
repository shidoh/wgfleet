package mihomo

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func profileAWG(t *testing.T, mode string) *wg.ClientConfigInput {
	t.Helper()
	seed := wg.TunnelSeed("m1", "clients", "wgfleet-awg-v1")
	p := wg.DeriveAWGParams(seed)
	switch mode {
	case "timers":
		p = wg.WithAWG3Timers(p, seed)
	case "full":
		p = wg.WithAWG3HeaderProtection(wg.WithAWG3Timers(p, seed), seed, "fleet-secret")
	}
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := wg.GenerateKeyPair()
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return &wg.ClientConfigInput{
		Spec: domain.ClientWGSpec{
			ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1", MTU: 1360,
			DNS: []string{"10.80.0.1"}, AllowedIPs: []string{"0.0.0.0/0"}, AWG: &p,
		},
		Client: domain.WGClient{ID: "c-" + mode, Name: "laptop", Address: "10.80.0.2/32",
			PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey, PresharedKey: psk, Enabled: true},
		ServerPublicKey: srv.PublicKey,
		Endpoint:        "203.0.113.1:443",
	}
}

func profileVLESS(mode string) *domain.ClientVLESSEndpoint {
	cv := domain.ClientVLESSServerSpec{ListenPort: 49443, ServerName: "www.python.org",
		AllowEmptySNI: true, Mode: mode, Mux: true}
	e := cv.EndpointFor("203.0.113.1", "PBKEY", domain.VLESSClient{Name: "laptop",
		UUID: "11111111-1111-4111-8111-111111111111", ShortID: "0badc0de"})
	return &e
}

func renderProfile(t *testing.T, in ClientProfileInput) map[string]any {
	t.Helper()
	out, err := RenderClientProfile(in)
	if err != nil {
		t.Fatalf("RenderClientProfile: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("profile is not YAML: %v\n%s", err, out)
	}
	return doc
}

func proxyNamed(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	for _, p := range doc["proxies"].([]any) {
		if m := p.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no proxy %q", name)
	return nil
}

func groupNamed(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	for _, g := range doc["proxy-groups"].([]any) {
		if m := g.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no group %q", name)
	return nil
}

// parseConf reads an awg-quick config into its two sections. strings.Cut splits
// at the FIRST '=', so base64 padding survives.
func parseConf(t *testing.T, cfg string) (iface, peer map[string]string) {
	t.Helper()
	iface, peer = map[string]string{}, map[string]string{}
	var cur map[string]string
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "[Interface]":
			cur = iface
		case line == "[Peer]":
			cur = peer
		case line == "" || strings.HasPrefix(line, "#"):
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || cur == nil {
				t.Fatalf("unparseable line %q", line)
			}
			cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return iface, peer
}

// The spec's invariant: the AWG proxy says exactly what the .conf says — except
// AllowedIPs, see TestClientProfileAWGCarriesWhateverTheRulesSend.
func TestClientProfileAWGEqualsTheConf(t *testing.T) {
	awgKeys := map[string]string{
		"Jc": "jc", "Jmin": "jmin", "Jmax": "jmax", "S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
		"H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4",
		"I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
		"HeaderProtectionKey": "header-protection-key", "ContentPaddingAddition": "content-padding-addition",
		"RekeyAfterTime": "rekey-after-time", "RekeyTimeout": "rekey-timeout", "RejectAfterTime": "reject-after-time",
		"KeepaliveTimeout": "keepalive-timeout", "MaxHandshakeAttempts": "max-handshake-attempts",
	}
	for _, mode := range []string{"2.0", "timers", "full"} {
		t.Run(mode, func(t *testing.T) {
			in := profileAWG(t, mode)
			conf, err := wg.RenderClientConfig(*in)
			if err != nil {
				t.Fatal(err)
			}
			iface, peer := parseConf(t, conf)
			doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", AWG: in, DNS: in.Spec.DNS}}})
			px := proxyNamed(t, doc, "m1-awg")
			pp := px["peers"].([]any)[0].(map[string]any)
			opt := px["amnezia-wg-option"].(map[string]any)
			eq := func(what, confVal string, yamlVal any) {
				t.Helper()
				if fmt.Sprint(yamlVal) != confVal {
					t.Errorf("%s: conf %q, profile %v", what, confVal, yamlVal)
				}
			}
			eq("PrivateKey", iface["PrivateKey"], px["private-key"])
			eq("Address", strings.TrimSuffix(iface["Address"], "/32"), px["ip"])
			eq("MTU", iface["MTU"], px["mtu"])
			eq("PublicKey", peer["PublicKey"], pp["public-key"])
			eq("PresharedKey", peer["PresharedKey"], pp["pre-shared-key"])
			eq("Endpoint", peer["Endpoint"], net.JoinHostPort(fmt.Sprint(pp["server"]), fmt.Sprint(pp["port"])))
			eq("PersistentKeepalive", peer["PersistentKeepalive"], px["persistent-keepalive"])
			for confKey, optKey := range awgKeys {
				confVal, inConf := iface[confKey]
				optVal, inOpt := opt[optKey]
				if !inConf {
					if inOpt && fmt.Sprint(optVal) != "0" {
						t.Errorf("%s: absent from .conf but %v in profile", confKey, optVal)
					}
					continue
				}
				eq(confKey, confVal, optVal)
			}
			if _, has := opt["version"]; has != (mode != "2.0") {
				t.Errorf("version: 3 present=%v for mode %s", has, mode)
			}
			ns := strings.Join(toStrings(doc["dns"].(map[string]any)["nameserver"].([]any)), ",")
			if ns != "tcp://"+iface["DNS"]+":53#m1" {
				t.Errorf("DNS: conf %q, profile nameserver %s", iface["DNS"], ns)
			}
		})
	}
}

// A split AllowedIPs (client_awg.exclude_from_tunnel) is a ROUTING table for
// wg-quick; in mihomo the rules route, and the same list on the proxy is a
// filter: whatever a rule sends to the proxy outside it is dropped, not sent
// DIRECT. A site's networks are exactly that — RFC1918, cut out of the .conf's
// list, sent to the tunnel by the site's rule — so on AWG the site was dead and
// its own probe through the tunnel never answered.
func TestClientProfileAWGCarriesWhateverTheRulesSend(t *testing.T) {
	in := profileAWG(t, "2.0")
	in.Spec.AllowedIPs = []string{"0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "172.29.0.0/16"}
	doc := renderProfile(t, ClientProfileInput{
		Masters: []ClientProfileMaster{{Name: "m1", AWG: in, DNS: in.Spec.DNS}},
		Sites: []domain.ClientSite{{Name: "home", CIDRs: []string{"172.18.0.0/21"},
			ProbeURL: "http://172.18.0.1/", ProbeInterval: 60}},
	})
	pp := proxyNamed(t, doc, "m1-awg")["peers"].([]any)[0].(map[string]any)
	if got := strings.Join(toStrings(pp["allowed-ips"].([]any)), ", "); got != "0.0.0.0/0" {
		t.Errorf("allowed-ips = %q, want 0.0.0.0/0: the site rule sends 172.18.0.0/21 to this proxy", got)
	}
	conf, err := wg.RenderClientConfig(*in)
	if err != nil {
		t.Fatal(err)
	}
	if _, peer := parseConf(t, conf); peer["AllowedIPs"] != strings.Join(in.Spec.AllowedIPs, ", ") {
		t.Errorf(".conf AllowedIPs = %q, the split list must stay there", peer["AllowedIPs"])
	}
}

// The second invariant: the VLESS proxy dials what the vless:// link dials.
func TestClientProfileVLESSEqualsTheLink(t *testing.T) {
	for _, mode := range []string{domain.RealityModeXHTTP, domain.RealityModeVision} {
		t.Run(mode, func(t *testing.T) {
			e := profileVLESS(mode)
			u, err := url.Parse(e.Link("m1-laptop"))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", VLESS: e}}})
			px := proxyNamed(t, doc, "m1-vless")
			ro := px["reality-opts"].(map[string]any)
			port, _ := strconv.Atoi(u.Port())
			for _, c := range []struct {
				what      string
				link, got any
			}{
				{"server", u.Hostname(), px["server"]},
				{"port", port, px["port"]},
				{"uuid", u.User.Username(), px["uuid"]},
				{"pbk", q.Get("pbk"), ro["public-key"]},
				{"sid", q.Get("sid"), ro["short-id"]},
				{"fp", q.Get("fp"), px["client-fingerprint"]},
			} {
				if fmt.Sprint(c.link) != fmt.Sprint(c.got) {
					t.Errorf("%s: link %v, profile %v", c.what, c.link, c.got)
				}
			}
			if q.Get("sni") != "" || px["servername"] != u.Hostname() {
				t.Errorf("empty-SNI: link sni=%q, profile servername=%v", q.Get("sni"), px["servername"])
			}
			if mode == domain.RealityModeVision {
				if px["network"] != "tcp" || px["flow"] != q.Get("flow") {
					t.Errorf("vision: %v / %v", px["network"], px["flow"])
				}
				return
			}
			xo := px["xhttp-opts"].(map[string]any)
			if px["network"] != "xhttp" || xo["path"] != q.Get("path") || xo["mode"] != q.Get("mode") {
				t.Errorf("xhttp: network %v opts %v, link %v", px["network"], xo, q)
			}
			if _, ok := xo["reuse-settings"]; !ok {
				t.Error("Mux on but no reuse-settings")
			}
		})
	}
}

func TestClientProfileGroups(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{
		{Name: "m1", AWG: profileAWG(t, "2.0"), VLESS: profileVLESS(domain.RealityModeXHTTP), DNS: []string{"10.80.0.1"}},
		{Name: "m2", AWG: profileAWG(t, "2.0"), DNS: []string{"10.81.0.1"}},
	}})
	auto := groupNamed(t, doc, "auto")
	if auto["type"] != "fallback" || auto["url"] != ClientProfileHealthURL || fmt.Sprint(auto["interval"]) != "60" {
		t.Errorf("auto = %v", auto)
	}
	// AmneziaWG on every master before any VLESS: a wedged WG device is one proxy's,
	// the next master's is a different one, and VLESS is TCP over TCP. With m1-vless
	// second, a stuck m1-awg sent everyone to the slowest path on the same master.
	if got := strings.Join(toStrings(auto["proxies"].([]any)), ","); got != "m1-awg,m2-awg,m1-vless" {
		t.Errorf("fallback order = %s, want every AWG before any VLESS", got)
	}
	sel := groupNamed(t, doc, "wgfleet")
	if sel["type"] != "select" || strings.Join(toStrings(sel["proxies"].([]any)), ",") != "auto,m1-awg,m2-awg,m1-vless" {
		t.Errorf("select = %v", sel)
	}
	if m1 := groupNamed(t, doc, "m1"); m1["type"] != "fallback" || strings.Join(toStrings(m1["proxies"].([]any)), ",") != "m1-awg,m1-vless" {
		t.Errorf("per-master group = %v", m1)
	}
	ns := strings.Join(toStrings(doc["dns"].(map[string]any)["nameserver"].([]any)), ",")
	if ns != "tcp://10.80.0.1:53#m1,tcp://10.81.0.1:53#m2" {
		t.Errorf("each master's resolver must go through that master: %s", ns)
	}
	if _, has := doc["tun"]; has {
		t.Error("profile carries a tun block: TUN is the app's switch, not ours")
	}
}

// Review Focus #2: everything that must reach the tunnel precedes the rule that
// sends RFC1918 direct — the portal on the mgmt overlay, the client pool, the
// operator's internal nets all live in RFC1918.
func TestClientProfileTunnelRulesPrecedePrivateDirect(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{
		MgmtCIDRs: []string{"172.29.0.0/16"},
		Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0"), DNS: []string{"10.80.0.1"},
			RouteThrough: []string{"10.20.0.0/16"}, ClientPool: "10.80.0.0/24"}},
	})
	rules := toStrings(doc["rules"].([]any))
	index := func(r string) int {
		for i, x := range rules {
			if x == r {
				return i
			}
		}
		t.Fatalf("rule %q missing from %v", r, rules)
		return -1
	}
	firstDirect := index("IP-CIDR,10.0.0.0/8,DIRECT")
	for _, r := range []string{
		"IP-CIDR,10.20.0.0/16,wgfleet",
		"IP-CIDR,172.29.0.0/16,wgfleet",
		"IP-CIDR,10.80.0.0/24,m1",
	} {
		if index(r) > firstDirect {
			t.Errorf("%q comes after the private DIRECT rules: %v", r, rules)
		}
	}
	for _, cidr := range []string{"172.16.0.0/12", "192.168.0.0/16"} {
		index("IP-CIDR," + cidr + ",DIRECT")
	}
	if rules[len(rules)-1] != "MATCH,wgfleet" {
		t.Errorf("last rule = %q", rules[len(rules)-1])
	}
}

// Under fake-ip an app hands mihomo a NAME, not an address. An IP rule with
// no-resolve skips every name, so a work host that resolves to 10.x would fall
// through to MATCH instead of its route-through rule, and a name that resolves
// into the device's own LAN would leave the DIRECT rule behind.
func TestClientProfileIPRulesResolveNames(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{
		MgmtCIDRs: []string{"172.29.0.0/16"},
		Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0"), DNS: []string{"10.80.0.1"},
			RouteThrough: []string{"10.20.0.0/16"}, ClientPool: "10.80.0.0/24"}},
	})
	for _, r := range toStrings(doc["rules"].([]any)) {
		if strings.HasSuffix(r, ",no-resolve") {
			t.Errorf("rule %q skips names: under fake-ip every hostname misses it", r)
		}
	}
}

// Clash Verge Rev on macOS points the system resolver at a public address — the
// only way the OS resolver's queries enter the tun — ONLY when the profile's
// enhanced-mode is fake-ip (src-tauri/src/enhance/tun.rs). Under redir-host a
// router-handed LAN resolver stays in place, its route never enters the tun, and
// every name the OS looks up leaves beside the tunnel. The filter then hands out
// real addresses for every name: dig and nslookup must show what a host really
// is, not a 198.18.x placeholder.
func TestClientProfileDNSIsFakeIPModeWithRealAnswers(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", AWG: profileAWG(t, "2.0"), DNS: []string{"10.80.0.1"}}}})
	dns := doc["dns"].(map[string]any)
	if dns["enhanced-mode"] != "fake-ip" {
		t.Errorf("enhanced-mode = %v, want fake-ip", dns["enhanced-mode"])
	}
	if dns["fake-ip-filter-mode"] != "rule" {
		t.Errorf("fake-ip-filter-mode = %v, want rule", dns["fake-ip-filter-mode"])
	}
	raw, _ := dns["fake-ip-filter"].([]any)
	if got := toStrings(raw); !slices.Equal(got, []string{"MATCH,real-ip"}) {
		t.Errorf("fake-ip-filter = %v, want [MATCH,real-ip]", got)
	}
}

func TestClientProfileVLESSOnlyMasterWithoutResolversHasNoDNSBlock(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", VLESS: profileVLESS(domain.RealityModeXHTTP)}}})
	if _, has := doc["dns"]; has {
		t.Errorf("dns block rendered with no resolver to point at: %v", doc["dns"])
	}
}

// Names are data, not template: the YAML encoder quotes what needs quoting. The
// two characters that ARE syntax inside mihomo strings — ',' in rules, '#' in a
// nameserver — are refused.
func TestClientProfileNamesAreMarshalledNotSpliced(t *testing.T) {
	odd := `мастер "1": x`
	doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{{Name: odd,
		VLESS: profileVLESS(domain.RealityModeXHTTP), DNS: []string{"10.80.0.1"}}}})
	proxyNamed(t, doc, odd+"-vless")
	groupNamed(t, doc, odd)
	for _, bad := range []string{"a,b", "a#b"} {
		if _, err := RenderClientProfile(ClientProfileInput{Masters: []ClientProfileMaster{{Name: bad,
			VLESS: profileVLESS(domain.RealityModeXHTTP)}}}); err == nil {
			t.Errorf("master name %q accepted", bad)
		}
	}
}

// A master literally named "auto" or "wgfleet" would render a second proxy-group
// under a name RenderClientProfile already reserves for its own fallback/select
// groups — one of the two silently wins in the YAML map and the other vanishes.
// "DIRECT"/"REJECT" are mihomo's built-in policies, used verbatim as rule targets
// elsewhere in this same profile (clientRules' private-range rules); a master
// group under either name would shadow the built-in for every rule that names it.
func TestClientProfileRefusesReservedMasterNames(t *testing.T) {
	for _, bad := range []string{ClientProfileAutoGroup, ClientProfileSelectGroup, "DIRECT", "REJECT"} {
		if _, err := RenderClientProfile(ClientProfileInput{Masters: []ClientProfileMaster{{Name: bad,
			VLESS: profileVLESS(domain.RealityModeXHTTP)}}}); err == nil {
			t.Errorf("master name %q accepted", bad)
		}
	}
}

func TestClientProfileRefusesNothingToDial(t *testing.T) {
	if _, err := RenderClientProfile(ClientProfileInput{}); err == nil {
		t.Error("an empty profile rendered")
	}
	bad := profileAWG(t, "2.0")
	bad.Client.PrivateKey = ""
	if _, err := RenderClientProfile(ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", AWG: bad}}}); err == nil {
		t.Error("an AWG proxy without a private key rendered")
	}
}

// ClashMetaForAndroid puts its own app inside its VPN and protects the core's
// sockets only once the tun is up; the profile's first health checks open the
// AWG socket a few milliseconds earlier, so that socket's packets come back
// through the tun. Without a rule ahead of everything they meet MATCH and are
// sent into the very proxy that produced them. Measured 2026-10-14: AWG dead
// after 3 of 4 cold starts, alive after 4 of 4 with these rules. Only the
// proxy's own server, port and network: SSH, ZeroTier or a web page on the same
// address keep riding the tunnel.
func TestClientProfileProxyEndpointsGoDirectFirst(t *testing.T) {
	awg := profileAWG(t, "2.0")
	awg.Endpoint = "198.51.100.7:8443"
	doc := renderProfile(t, ClientProfileInput{
		Sites: []domain.ClientSite{{Name: "home", CIDRs: []string{"192.168.88.0/24"}}},
		Masters: []ClientProfileMaster{
			{Name: "m1", AWG: profileAWG(t, "2.0"), VLESS: profileVLESS("tcp"), DNS: []string{"10.80.0.1"}},
			{Name: "m2", AWG: awg},
		},
	})
	rules := toStrings(doc["rules"].([]any))
	want := []string{
		"AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR,203.0.113.1/32,no-resolve)),DIRECT",
		"AND,((NETWORK,TCP),(DST-PORT,49443),(IP-CIDR,203.0.113.1/32,no-resolve)),DIRECT",
		"AND,((NETWORK,UDP),(DST-PORT,8443),(IP-CIDR,198.51.100.7/32,no-resolve)),DIRECT",
	}
	if len(rules) < len(want) || !slices.Equal(rules[:len(want)], want) {
		t.Fatalf("rules do not open with the proxy endpoints:\n got %v\nwant prefix %v", rules, want)
	}
}

func TestClientProfileProxyEndpointRuleIPv6(t *testing.T) {
	awg := profileAWG(t, "2.0")
	awg.Endpoint = "[2001:db8::7]:443"
	rules := toStrings(renderProfile(t, ClientProfileInput{
		Masters: []ClientProfileMaster{{Name: "m1", AWG: awg}},
	})["rules"].([]any))
	if want := "AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR6,2001:db8::7/128,no-resolve)),DIRECT"; rules[0] != want {
		t.Errorf("rules[0] = %q, want %q", rules[0], want)
	}
}

// A name cannot become an IP-CIDR; the endpoint is left to the rules below it
// rather than guessed at render time.
func TestClientProfileProxyEndpointByNameHasNoRule(t *testing.T) {
	awg := profileAWG(t, "2.0")
	awg.Endpoint = "master.example.net:443"
	for _, r := range toStrings(renderProfile(t, ClientProfileInput{
		Masters: []ClientProfileMaster{{Name: "m1", AWG: awg}},
	})["rules"].([]any)) {
		if strings.HasPrefix(r, "AND,") {
			t.Errorf("rule %q for an endpoint given by name", r)
		}
	}
}

func TestClientProfileVLESSOffersMLKEM(t *testing.T) {
	doc := renderProfile(t, ClientProfileInput{Masters: []ClientProfileMaster{{Name: "m1", VLESS: profileVLESS(domain.RealityModeXHTTP)}}})
	ro := proxyNamed(t, doc, "m1-vless")["reality-opts"].(map[string]any)
	if ro["support-x25519mlkem768"] != true {
		t.Errorf("reality-opts.support-x25519mlkem768 = %v, want true", ro["support-x25519mlkem768"])
	}
}

// The health check must make full-size packets cross the tunnel. A device whose
// AmneziaWG passed small packets and lost large ones (2026-10-26: SSH stuck at the
// server's key exchange reply, HTTP redirects fine) kept a plain-HTTP 204 green
// and never failed over. Over HTTPS the server's certificate chain (~2.5 KB) does.
func TestClientProfileHealthCheckIsHTTPS(t *testing.T) {
	if !strings.HasPrefix(ClientProfileHealthURL, "https://") {
		t.Fatalf("health URL %q is not HTTPS: a 204 over plain HTTP is a few small packets", ClientProfileHealthURL)
	}
}
