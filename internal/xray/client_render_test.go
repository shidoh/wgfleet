package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func sampleClientSpec() domain.ClientVLESSServerSpec {
	return domain.ClientVLESSServerSpec{
		ListenPort: 49443,
		Clients: []domain.VLESSClient{
			{Name: "alice", UUID: "11111111-1111-4111-8111-111111111111", ShortID: "0badc0de"},
			{Name: "bob", UUID: "22222222-2222-4222-8222-222222222222", ShortID: "feedface"},
		},
		ServerName:    "www.python.org",
		Dest:          "www.python.org:443",
		AllowEmptySNI: true,
		SocksPort:     domain.ClientVLESSSocksPort,
	}
}

func TestRenderClientConfigStructure(t *testing.T) {
	out, err := RenderClientConfig(ClientRenderInput{Spec: sampleClientSpec(), PrivateKey: "PRIVKEY"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("rendered config is not valid JSON: %v\n%s", err, out)
	}

	inbounds := c["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("want 1 inbound, got %d", len(inbounds))
	}
	in := inbounds[0].(map[string]any)
	if got := in["port"].(float64); got != 49443 {
		t.Errorf("listen port = %v, want 49443", got)
	}
	settings := in["settings"].(map[string]any)
	clients := settings["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}
	if id := clients[0].(map[string]any)["id"].(string); id != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("client[0] id = %q", id)
	}

	ss := in["streamSettings"].(map[string]any)
	if ss["network"] != "xhttp" {
		t.Errorf("network = %v, want xhttp", ss["network"])
	}
	rs := ss["realitySettings"].(map[string]any)
	// shortIds must union "" (match-any) with every client's short-id.
	sids := rs["shortIds"].([]any)
	want := map[string]bool{"": true, "0badc0de": true, "feedface": true}
	if len(sids) != len(want) {
		t.Fatalf("shortIds = %v, want %v", sids, want)
	}
	for _, s := range sids {
		if !want[s.(string)] {
			t.Errorf("unexpected shortId %q", s)
		}
	}
	// AllowEmptySNI ⇒ serverNames prepends "".
	sn := rs["serverNames"].([]any)
	if len(sn) != 2 || sn[0].(string) != "" {
		t.Errorf("serverNames = %v, want leading empty", sn)
	}

	// The outbound must be socks → the mihomo loopback port (not freedom).
	outs := c["outbounds"].([]any)
	ob := outs[0].(map[string]any)
	if ob["protocol"] != "socks" {
		t.Fatalf("outbound protocol = %v, want socks", ob["protocol"])
	}
	srv := ob["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if srv["address"] != "127.0.0.1" || srv["port"].(float64) != float64(domain.ClientVLESSSocksPort) {
		t.Errorf("socks target = %v:%v", srv["address"], srv["port"])
	}

	// IPv4-only data plane ⇒ dns.queryStrategy pins UseIPv4.
	if dns, ok := c["dns"].(map[string]any); !ok || dns["queryStrategy"] != "UseIPv4" {
		t.Errorf("expected dns.queryStrategy UseIPv4, got %v", c["dns"])
	}
}

func TestRenderClientConfigVisionFlow(t *testing.T) {
	spec := sampleClientSpec()
	spec.Mode = domain.RealityModeVision
	out, err := RenderClientConfig(ClientRenderInput{Spec: spec, PrivateKey: "PRIVKEY"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, `"flow": "xtls-rprx-vision"`) {
		t.Errorf("vision mode must set the vision flow\n%s", out)
	}
	if strings.Contains(out, `"xhttpSettings"`) {
		t.Errorf("vision mode must not emit xhttpSettings")
	}
}

func TestRenderClientConfigRequiresKey(t *testing.T) {
	if _, err := RenderClientConfig(ClientRenderInput{Spec: sampleClientSpec()}); err == nil {
		t.Fatal("expected error without a private key")
	}
}

func TestRenderClientConfigEmptyClients(t *testing.T) {
	spec := sampleClientSpec()
	spec.Clients = nil
	out, err := RenderClientConfig(ClientRenderInput{Spec: spec, PrivateKey: "PRIVKEY"})
	if err != nil {
		t.Fatalf("an enabled inbound with no issued clients is valid: %v", err)
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}
