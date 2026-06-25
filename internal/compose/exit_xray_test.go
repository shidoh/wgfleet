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
		"0:0",       // run as root: read the 0600 config (holds the REALITY private key)
		"NET_ADMIN", // SO_MARK for the WARP egress path
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
