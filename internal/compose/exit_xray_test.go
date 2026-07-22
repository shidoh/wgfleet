package compose

import (
	"strings"
	"testing"
)

func TestRenderXrayCompose(t *testing.T) {
	// Exit leg: the freedom outbound sets SO_MARK for the WARP egress path, so it
	// needs NET_ADMIN.
	out, err := RenderXrayCompose(XrayInput{ConfigPath: "/etc/wgfleet/xray/config.json", NetAdmin: true})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		DefaultXrayImage,
		"network_mode: host",
		"/etc/wgfleet/xray/config.json:/etc/xray/config.json:ro",
		"container_name: xray",
		"0:0",                    // run as root: read the 0600 config (holds the REALITY private key)
		"NET_ADMIN",              // SO_MARK for the WARP egress path
		"ALL",                    // cap_drop: [ALL] — drop everything, add back only what's needed
		"no-new-privileges:true", // no privilege escalation
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
}

// TestRenderXrayComposeNoNetAdmin guards least-privilege for the client-facing
// master inbound (#9): it forwards decrypted traffic to a loopback SOCKS (mihomo),
// never touches WARP, so it must NOT carry NET_ADMIN — but still drops all caps and
// forbids privilege escalation.
func TestRenderXrayComposeNoNetAdmin(t *testing.T) {
	out, err := RenderXrayCompose(XrayInput{ConfigPath: "/etc/wgfleet/client-vless/config.json"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "NET_ADMIN") {
		t.Errorf("client-vless inbound must not request NET_ADMIN (no WARP egress):\n%s", out)
	}
	for _, want := range []string{"ALL", "no-new-privileges:true"} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing least-privilege directive %q:\n%s", want, out)
		}
	}
}

func TestRenderXrayComposeRequiresConfigPath(t *testing.T) {
	if _, err := RenderXrayCompose(XrayInput{}); err == nil {
		t.Error("expected error when config path is empty")
	}
}
