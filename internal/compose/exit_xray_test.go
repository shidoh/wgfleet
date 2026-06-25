package compose

import (
	"strings"
	"testing"
)

func TestRenderXrayCompose(t *testing.T) {
	out, err := RenderXrayCompose(XrayInput{ConfigPath: "/etc/wgfleet/xray/config.json"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		DefaultXrayImage,
		"network_mode: host",
		"/etc/wgfleet/xray/config.json:/etc/xray/config.json:ro",
		"container_name: xray",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
}

func TestRenderXrayComposeRequiresConfigPath(t *testing.T) {
	if _, err := RenderXrayCompose(XrayInput{}); err == nil {
		t.Error("expected error when config path is empty")
	}
}
