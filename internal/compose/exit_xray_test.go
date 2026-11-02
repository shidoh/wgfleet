package compose

import (
	"strings"
	"testing"
)

func TestRenderXrayCompose(t *testing.T) {
	// Exit leg: the freedom outbound sets SO_MARK for the WARP egress path, so it
	// needs NET_ADMIN; the REALITY inbound sits on 443 (a privileged port), so with
	// all caps dropped it also needs NET_BIND_SERVICE to bind it (#9 regression:
	// cap_drop [ALL] strips the default CAP_NET_BIND_SERVICE that let root bind 443).
	out, err := RenderXrayCompose(XrayInput{ConfigPath: "/etc/wgfleet/xray/config.json", NetAdmin: true, ListenPort: 443})
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
		"NET_BIND_SERVICE",       // bind the privileged REALITY port (443) after cap_drop ALL
		"ALL",                    // cap_drop: [ALL] — drop everything, add back only what's needed
		"no-new-privileges:true", // no privilege escalation
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
}

// TestRenderXrayComposeHighPortNoBindCap guards that a non-privileged listen port
// does NOT request NET_BIND_SERVICE — a high-port inbound (the recommended
// client-vless port) can bind with all caps dropped, so it stays capability-free.
func TestRenderXrayComposeHighPortNoBindCap(t *testing.T) {
	out, err := RenderXrayCompose(XrayInput{ConfigPath: "/etc/wgfleet/client-vless/config.json", ListenPort: 47252})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "NET_BIND_SERVICE") {
		t.Errorf("high port must not request NET_BIND_SERVICE:\n%s", out)
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

// TestRenderXrayComposeDisablesMPTCP guards that every xray container (exit,
// client-facing VLESS, portal) listens with plain TCP: Go 1.24+ opens MPTCP
// listeners by default, and an MPTCP listener is what the CVE-2026-98432 remote
// root exploit needs. Checked for both the bare and the timezone-carrying render,
// since the environment list is built in two steps.
func TestRenderXrayComposeDisablesMPTCP(t *testing.T) {
	for _, in := range []XrayInput{
		{ConfigPath: "/etc/wgfleet/xray/config.json", NetAdmin: true, ListenPort: 443},
		{ConfigPath: "/etc/wgfleet/client-vless/config.json", Timezone: "Europe/Moscow"},
	} {
		out, err := RenderXrayCompose(in)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		if !strings.Contains(out, "GODEBUG=multipathtcp=0") {
			t.Errorf("compose for %s must disable MPTCP:\n%s", in.ConfigPath, out)
		}
	}
}

func TestRenderXrayComposeRequiresConfigPath(t *testing.T) {
	if _, err := RenderXrayCompose(XrayInput{}); err == nil {
		t.Error("expected error when config path is empty")
	}
}
