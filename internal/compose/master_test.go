package compose

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

func sampleInput() RenderInput {
	return RenderInput{
		MgmtAddr:         "10.20.25.254",
		ClientListenPort: 443,
		ClientPool:       "10.80.0.0/24",
		Compose: domain.ComposeSpec{
			WGEasyImage:      "ghcr.io/wg-easy/wg-easy:15.3.0",
			MihomoImage:      "metacubex/mihomo:v1.18",
			PublicIP:         "203.0.113.20",
			WGEasyWebPort:    44423,
			ClientDNS:        []string{"10.20.4.10", "10.20.4.15"},
			ClientAllowedIPs: "1.0.0.0/8,8.0.0.0/7",
		},
	}
}

func TestRenderMasterComposeStructure(t *testing.T) {
	out, err := RenderMasterCompose(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("rendered compose is not valid YAML: %v\n%s", err, out)
	}
	services, _ := doc["services"].(map[string]any)
	wg, _ := services["wg-easy"].(map[string]any)
	mi, _ := services["mihomo"].(map[string]any)
	if wg == nil || mi == nil {
		t.Fatalf("missing services: %+v", services)
	}

	if wg["image"] != "ghcr.io/wg-easy/wg-easy:15.3.0" || wg["network_mode"] != "host" {
		t.Errorf("wg-easy service wrong: %+v", wg)
	}
	if mi["image"] != "metacubex/mihomo:v1.18" || mi["command"] != "-d /etc/mihomo" {
		t.Errorf("mihomo service wrong: %+v", mi)
	}
	// mihomo depends on wg-easy.
	dep, _ := mi["depends_on"].([]any)
	if len(dep) != 1 || dep[0] != "wg-easy" {
		t.Errorf("mihomo depends_on = %+v", dep)
	}
	// First-run env present and correct.
	env := toStrings(wg["environment"].([]any))
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"HOST=10.20.25.254", "EXPERIMENTAL_AWG=true", "OVERRIDE_AUTO_AWG=awg",
		"INIT_HOST=203.0.113.20", "INIT_PORT=443", "INIT_IPV4_CIDR=10.80.0.0/24",
		"INIT_DNS=10.20.4.10,10.20.4.15", "INIT_ALLOWED_IPS=1.0.0.0/8,8.0.0.0/7",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("wg-easy env missing %q:\n%s", want, joined)
		}
	}
}

func TestRenderMasterComposeDefaults(t *testing.T) {
	in := RenderInput{MgmtAddr: "10.20.25.254", ClientPool: "10.80.0.0/24"}
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DefaultWGEasyImage) || !strings.Contains(out, DefaultMihomoImage) {
		t.Errorf("default images not used:\n%s", out)
	}
	if !strings.Contains(out, "PORT=44423") {
		t.Errorf("default web port not used:\n%s", out)
	}
}

func TestRenderMasterComposeDeterministic(t *testing.T) {
	a, _ := RenderMasterCompose(sampleInput())
	b, _ := RenderMasterCompose(sampleInput())
	if a != b {
		t.Error("compose render must be deterministic")
	}
}

func TestRenderMasterComposeRequiresMgmt(t *testing.T) {
	if _, err := RenderMasterCompose(RenderInput{ClientPool: "10.80.0.0/24"}); err == nil {
		t.Fatal("expected error without mgmt address")
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
