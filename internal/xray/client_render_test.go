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
	// shortIds are exactly the issued clients' short-ids: no "" (match-any), so a
	// public key leaked with one subscription does not open the inbound.
	sids := rs["shortIds"].([]any)
	want := map[string]bool{"0badc0de": true, "feedface": true}
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
	// xray refuses an empty shortIds list, and "" would admit anyone holding the
	// public key: an inbound with no clients carries one id nobody was issued,
	// stable across renders and not guessable without the private key.
	sids := clientShortIDs(t, out)
	if len(sids) != 1 || len(sids[0]) != 16 || sids[0] == "" {
		t.Fatalf("no-client shortIds = %q, want one 16-hex placeholder", sids)
	}
	again, _ := RenderClientConfig(ClientRenderInput{Spec: spec, PrivateKey: "PRIVKEY"})
	if got := clientShortIDs(t, again); got[0] != sids[0] {
		t.Errorf("placeholder not stable across renders: %q vs %q", got[0], sids[0])
	}
	other, _ := RenderClientConfig(ClientRenderInput{Spec: spec, PrivateKey: "OTHERKEY"})
	if got := clientShortIDs(t, other); got[0] == sids[0] {
		t.Errorf("placeholder does not depend on the private key: %q", got[0])
	}
}

func clientShortIDs(t *testing.T, out string) []string {
	t.Helper()
	var c struct {
		Inbounds []struct {
			StreamSettings struct {
				RealitySettings struct {
					ShortIDs []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(out), &c); err != nil || len(c.Inbounds) == 0 {
		t.Fatalf("parse inbound: %v", err)
	}
	return c.Inbounds[0].StreamSettings.RealitySettings.ShortIDs
}

// Per-client traffic needs four things in the config, and missing any one of them
// makes xray count nothing without saying so: stats, the API, the per-level policy
// flags, and an email on every client (no email ⇒ no counter is registered).
func TestRenderClientConfigCountsTrafficPerClient(t *testing.T) {
	spec := sampleClientSpec()
	out, err := RenderClientConfig(ClientRenderInput{Spec: spec, PrivateKey: "PRIVKEY"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var c struct {
		Stats *map[string]any `json:"stats"`
		API   struct {
			Tag      string   `json:"tag"`
			Listen   string   `json:"listen"`
			Services []string `json:"services"`
		} `json:"api"`
		Policy struct {
			Levels map[string]map[string]bool `json:"levels"`
		} `json:"policy"`
		Inbounds []struct {
			Settings struct {
				Clients []struct {
					ID    string `json:"id"`
					Email string `json:"email"`
					Level *int   `json:"level"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatal(err)
	}
	if c.Stats == nil {
		t.Error(`no "stats": {} — xray keeps no counters at all`)
	}
	if c.API.Listen != ClientStatsAPIAddr {
		t.Errorf("api.listen = %q, want %q (loopback only: nothing but the agent reads it)", c.API.Listen, ClientStatsAPIAddr)
	}
	if !strings.HasPrefix(c.API.Listen, "127.0.0.1:") {
		t.Errorf("api.listen %q is not on the loopback", c.API.Listen)
	}
	if len(c.API.Services) != 1 || c.API.Services[0] != "StatsService" {
		t.Errorf("api.services = %v, want only StatsService (no HandlerService: it can add users)", c.API.Services)
	}
	lvl := c.Policy.Levels["0"]
	for _, k := range []string{"statsUserUplink", "statsUserDownlink", "statsUserOnline"} {
		if !lvl[k] {
			t.Errorf("policy.levels.0.%s is not true", k)
		}
	}
	for i, cl := range c.Inbounds[0].Settings.Clients {
		want := domain.VLESSStatsID(spec.Clients[i].UUID)
		if cl.Email != want {
			t.Errorf("client %d email = %q, want the stats id %q", i, cl.Email, want)
		}
		if cl.Level == nil || *cl.Level != 0 {
			t.Errorf("client %d level = %v, want 0 (the level the policy flags are on)", i, cl.Level)
		}
	}
	// The email reaches the open /metrics endpoint. The UUID is the credential.
	for _, cl := range spec.Clients {
		if n := strings.Count(out, cl.UUID); n != 1 {
			t.Errorf("uuid of %s appears %d times in the config, want exactly once (its id)", cl.Name, n)
		}
	}
}

// The exit's server inbound has one service user and nobody reads its stats: it
// must not grow an API listener.
func TestRenderConfigExitHasNoStatsAPI(t *testing.T) {
	out, err := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"api"`, `"stats"`, `"policy"`} {
		if strings.Contains(out, k) {
			t.Errorf("exit config carries %s", k)
		}
	}
}
