package web

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestBuildRoutingObject(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "172.19.57.0/24", "172.29.0.0/16"}
	b64 := buildRoutingObject(cidrs)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("routing object is not valid base64: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("decoded routing object is not valid JSON: %v\n%s", err, raw)
	}
	rules, ok := obj["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("want 1 rule, got %v", obj["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["type"] != "field" || rule["outboundTag"] != "proxy" {
		t.Errorf("rule must be field→proxy, got %v", rule)
	}
	ips, _ := rule["ip"].([]any)
	if len(ips) != len(cidrs) {
		t.Fatalf("ip list = %v, want %v", ips, cidrs)
	}
	for i, c := range cidrs {
		if ips[i].(string) != c {
			t.Errorf("ip[%d] = %q, want %q", i, ips[i], c)
		}
	}
}

func TestBuildRoutingObjectEmpty(t *testing.T) {
	// Zero CIDRs still yields a valid object with an empty ip list (caller gates on len).
	if b64 := buildRoutingObject(nil); b64 == "" {
		t.Error("expected a non-empty base64 even for no CIDRs")
	}
}

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
