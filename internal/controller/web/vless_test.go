package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestBuildVlessLinkXHTTP(t *testing.T) {
	cv := domain.ClientVLESSServerSpec{
		ListenPort: 49443, ServerName: "www.python.org", Dest: "www.python.org:443",
		AllowEmptySNI: true, XHTTPMode: "packet-up",
	}
	c := domain.VLESSClient{Name: "alice", UUID: "11111111-1111-4111-8111-111111111111", ShortID: "0badc0de"}
	link := buildVlessLink("203.0.113.1", 49443, cv, "PBKEY", "master-xa-1", c)

	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not a valid URL: %v (%s)", err, link)
	}
	if u.Scheme != "vless" {
		t.Errorf("scheme = %q", u.Scheme)
	}
	if u.User.Username() != c.UUID {
		t.Errorf("uuid = %q", u.User.Username())
	}
	if u.Host != "203.0.113.1:49443" {
		t.Errorf("host = %q", u.Host)
	}
	q := u.Query()
	if q.Get("security") != "reality" || q.Get("pbk") != "PBKEY" || q.Get("sid") != "0badc0de" {
		t.Errorf("reality params wrong: %v", q)
	}
	if q.Get("type") != "xhttp" || q.Get("mode") != "packet-up" {
		t.Errorf("transport params wrong: %v", q)
	}
	// Empty-SNI ⇒ sni present but empty.
	if _, ok := q["sni"]; !ok || q.Get("sni") != "" {
		t.Errorf("empty-sni should render sni= empty, got %q (present=%v)", q.Get("sni"), q["sni"])
	}
	if u.Fragment != "master-xa-1-alice" {
		t.Errorf("fragment = %q", u.Fragment)
	}
}

func TestBuildVlessLinkVisionAndSNI(t *testing.T) {
	cv := domain.ClientVLESSServerSpec{
		ListenPort: 49443, ServerName: "www.python.org", Mode: domain.RealityModeVision,
		AllowEmptySNI: false,
	}
	c := domain.VLESSClient{Name: "bob", UUID: "u", ShortID: "sid"}
	link := buildVlessLink("h", 49443, cv, "PBKEY", "m", c)
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not a valid URL: %v (%s)", err, link)
	}
	q := u.Query()
	if q.Get("type") != "tcp" || q.Get("flow") != "xtls-rprx-vision" {
		t.Errorf("vision link params wrong: %v", q)
	}
	if q.Get("sni") != "www.python.org" {
		t.Errorf("non-empty-sni should carry the server name, got %q", q.Get("sni"))
	}
}

func TestValidClientName(t *testing.T) {
	good := []string{"alice", "alice-iphone", "a_b.c-1", "A1"}
	for _, n := range good {
		if !validClientName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	bad := []string{"", "has space", "semi;colon", "slash/y", strings.Repeat("x", 65)}
	for _, n := range bad {
		if validClientName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestBuildClashConfig(t *testing.T) {
	cv := domain.ClientVLESSServerSpec{ListenPort: 47252, ServerName: "www.python.org", XHTTPMode: "packet-up"}
	c := domain.VLESSClient{Name: "alice", UUID: "u-1", ShortID: "0badc0de"}
	out := buildClashConfig("203.0.113.1", cv, "PBK", "172.29.3.10", c)
	for _, want := range []string{
		"strict-route: true", "type: vless", `server: "203.0.113.1"`, "port: 47252",
		`uuid: "u-1"`, `public-key: "PBK"`, `short-id: "0badc0de"`, `servername: "www.python.org"`,
		"mode: packet-up", "- MATCH,wgfleet", `"tcp://172.29.3.10:53#wgfleet"`,
		// Clash Verge Rev hijacks the macOS system resolver only under fake-ip.
		"enhanced-mode: fake-ip", "fake-ip-filter-mode: rule", `- "MATCH,real-ip"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("clash config missing %q\n---\n%s", want, out)
		}
	}
	// No blocky ⇒ public DNS, still fake-ip: the OS resolver's leak is the same.
	out2 := buildClashConfig("h", cv, "PBK", "", c)
	if strings.Contains(out2, "#wgfleet") || !strings.Contains(out2, "enhanced-mode: fake-ip") {
		t.Errorf("empty blockyAddr should yield public DNS under fake-ip:\n%s", out2)
	}
}

// TestBuildClashConfigVision guards that the Clash config honours vision mode:
// classic TCP + xtls-rprx-vision, NOT xhttp. Emitting xhttp for a vision inbound
// ships a config that cannot connect (the recommended Clash Verge Rev client).
func TestBuildClashConfigVision(t *testing.T) {
	cv := domain.ClientVLESSServerSpec{
		ListenPort: 47252, ServerName: "www.python.org", Mode: domain.RealityModeVision,
	}
	c := domain.VLESSClient{Name: "bob", UUID: "u-2", ShortID: "0badc0de"}
	out := buildClashConfig("203.0.113.1", cv, "PBK", "", c)
	for _, want := range []string{"network: tcp", "flow: xtls-rprx-vision"} {
		if !strings.Contains(out, want) {
			t.Errorf("vision clash config missing %q\n---\n%s", want, out)
		}
	}
	for _, bad := range []string{"network: xhttp", "xhttp-opts"} {
		if strings.Contains(out, bad) {
			t.Errorf("vision clash config must not contain %q\n---\n%s", bad, out)
		}
	}
}

// TestBuildClashConfigEmptySNI guards the anti-DPI empty-SNI lever: when the
// inbound accepts an empty SNI, the client must send no SNI. uTLS omits the SNI
// extension when servername is a literal IP, so servername must be the server IP,
// not the camouflage domain (which would leak the real SNI on every connection).
func TestBuildClashConfigEmptySNI(t *testing.T) {
	cv := domain.ClientVLESSServerSpec{
		ListenPort: 47252, ServerName: "www.python.org", AllowEmptySNI: true, XHTTPMode: "packet-up",
	}
	c := domain.VLESSClient{Name: "alice", UUID: "u-1", ShortID: "0badc0de"}
	out := buildClashConfig("203.0.113.1", cv, "PBK", "", c)
	if !strings.Contains(out, `servername: "203.0.113.1"`) {
		t.Errorf("empty-sni must set servername to the server IP\n---\n%s", out)
	}
	if strings.Contains(out, "www.python.org") {
		t.Errorf("empty-sni must NOT leak the camouflage SNI\n---\n%s", out)
	}
}

// TestBuildClashConfigFingerprint guards the uTLS fingerprint knob (#12): an unset
// fingerprint resolves to the off-chrome stable default. ("none" no longer reaches
// here: config validation rejects it.)
func TestBuildClashConfigFingerprint(t *testing.T) {
	c := domain.VLESSClient{Name: "a", UUID: "u", ShortID: "0badc0de"}

	def := domain.ClientVLESSServerSpec{ListenPort: 47252, ServerName: "s", XHTTPMode: "packet-up"}
	out := buildClashConfig("h", def, "PBK", "", c)
	if !strings.Contains(out, "client-fingerprint: firefox") {
		t.Errorf("unset fingerprint must default to firefox\n---\n%s", out)
	}
	if strings.Contains(out, "chrome") {
		t.Errorf("client leg must not default to chrome\n---\n%s", out)
	}

	explicit := def
	explicit.Fingerprint = "safari"
	if out := buildClashConfig("h", explicit, "PBK", "", c); !strings.Contains(out, "client-fingerprint: safari") {
		t.Errorf("explicit fingerprint must be honoured\n---\n%s", out)
	}

}

// The portal download is a second mihomo profile; it must offer the post-quantum
// key share exactly as the subscription does (mihomo.realityOpts).
func TestBuildClashConfigOffersMLKEM(t *testing.T) {
	c := domain.VLESSClient{Name: "a", UUID: "u", ShortID: "0badc0de"}
	spec := domain.ClientVLESSServerSpec{ListenPort: 47252, ServerName: "s", XHTTPMode: "packet-up"}
	if out := buildClashConfig("h", spec, "PBK", "", c); !strings.Contains(out, "support-x25519mlkem768: true") {
		t.Errorf("reality-opts must carry support-x25519mlkem768: true\n---\n%s", out)
	}
}

// TestBuildClashConfigMux guards XMUX (hardening #1): mux ON adds xhttp-opts
// reuse-settings; mux OFF omits it; vision mode ignores mux (no XHTTP layer).
func TestBuildClashConfigMux(t *testing.T) {
	c := domain.VLESSClient{Name: "a", UUID: "u", ShortID: "0badc0de"}

	on := domain.ClientVLESSServerSpec{ListenPort: 47252, ServerName: "s", XHTTPMode: "packet-up", Mux: true}
	out := buildClashConfig("h", on, "PBK", "", c)
	for _, want := range []string{"reuse-settings", "max-concurrency", "h-max-request-times", "h-max-reusable-secs"} {
		if !strings.Contains(out, want) {
			t.Errorf("mux-on clash config missing %q\n---\n%s", want, out)
		}
	}

	off := on
	off.Mux = false
	if out := buildClashConfig("h", off, "PBK", "", c); strings.Contains(out, "reuse-settings") {
		t.Errorf("mux-off must omit reuse-settings\n---\n%s", out)
	}

	vision := domain.ClientVLESSServerSpec{ListenPort: 47252, ServerName: "s", Mode: domain.RealityModeVision, Mux: true}
	if out := buildClashConfig("h", vision, "PBK", "", c); strings.Contains(out, "reuse-settings") {
		t.Errorf("vision mode must ignore mux (no XHTTP layer)\n---\n%s", out)
	}
}

// TestBuildVlessLinkFingerprint guards the link-side fingerprint knob: unset ⇒
// firefox. ("none" no longer reaches here: config validation rejects it.)
func TestBuildVlessLinkFingerprint(t *testing.T) {
	base := domain.ClientVLESSServerSpec{ListenPort: 49443, ServerName: "s", XHTTPMode: "packet-up"}
	c := domain.VLESSClient{Name: "a", UUID: "u", ShortID: "sid"}

	link := buildVlessLink("h", 49443, base, "PBK", "m", c)
	u, _ := url.Parse(link)
	if u.Query().Get("fp") != "firefox" {
		t.Errorf("unset fingerprint must default to firefox, got %q", u.Query().Get("fp"))
	}

}
