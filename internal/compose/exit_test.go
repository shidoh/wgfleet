package compose

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func TestRenderBlockyComposeHostNetAndBindCap(t *testing.T) {
	out, err := RenderBlockyCompose(BlockyInput{
		ConfigPath: "/etc/wgfleet/blocky/config.yml",
		Timezone:   "Europe/Moscow",
	})
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not valid YAML: %v\n%s", err, out)
	}
	services, _ := doc["services"].(map[string]any)
	blocky, _ := services["blocky"].(map[string]any)
	if blocky["image"] != DefaultBlockyImage {
		t.Errorf("image = %v, want default", blocky["image"])
	}
	// host network is required so the config-pinned binds are the real ones.
	if blocky["network_mode"] != "host" {
		t.Errorf("network_mode = %v, want host", blocky["network_mode"])
	}
	// NET_BIND_SERVICE lets blocky claim :53 without running as root.
	caps, _ := blocky["cap_add"].([]any)
	if len(caps) != 1 || caps[0] != "NET_BIND_SERVICE" {
		t.Errorf("cap_add = %v, want [NET_BIND_SERVICE]", caps)
	}
	if !strings.Contains(out, "/etc/wgfleet/blocky/config.yml:/app/config.yml:ro") {
		t.Errorf("config mount missing:\n%s", out)
	}
	if !strings.Contains(out, "TZ=Europe/Moscow") {
		t.Errorf("timezone env missing:\n%s", out)
	}
}

func TestRenderBlockyComposeCustomImage(t *testing.T) {
	out, err := RenderBlockyCompose(BlockyInput{
		Image:      "spx01/blocky:v0.26",
		ConfigPath: "/x/config.yml",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "image: spx01/blocky:v0.26") {
		t.Errorf("custom image missing:\n%s", out)
	}
}

func TestRenderBlockyComposeRequiresConfigPath(t *testing.T) {
	if _, err := RenderBlockyCompose(BlockyInput{}); err == nil {
		t.Fatal("expected error without config path")
	}
}

// Every container this platform renders has a bounded log.
//
// Docker's json-file driver has no rotation, so an unbounded container is a disk
// leak waiting for a loop to start; even with nothing going wrong an unbounded
// log grows by tens of megabytes in a few weeks.
func TestEveryRenderedContainerBoundsItsLog(t *testing.T) {
	dns, err := RenderBlockyCompose(BlockyInput{ConfigPath: "/etc/wgfleet/blocky/config.yml"})
	if err != nil {
		t.Fatal(err)
	}
	xray, err := RenderXrayCompose(XrayInput{ConfigPath: "/etc/wgfleet/client-vless/config.json", ListenPort: 49443})
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"blocky": dns, "xray": xray} {
		if !strings.Contains(out, "max-size") || !strings.Contains(out, "max-file") {
			t.Errorf("%s renders an unbounded log:\n%s", name, out)
		}
	}
}
