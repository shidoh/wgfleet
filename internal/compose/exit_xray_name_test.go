package compose

import (
	"strings"
	"testing"
)

// The exit's and the client-facing xray share this renderer and are deployed to
// every node already; a byte of drift recreates the container on all of them.
// Last deliberate change: GODEBUG=multipathtcp=0 (2026-11-02, CVE-2026-98432).
func TestRenderXrayComposeDefaultIsByteStable(t *testing.T) {
	cases := []struct {
		in   XrayInput
		want string
	}{
		{
			in: XrayInput{ConfigPath: "/etc/wgfleet/xray/config.json", NetAdmin: true, ListenPort: 443, Timezone: "Europe/Moscow"},
			want: `services:
  xray:
    cap_add:
      - NET_ADMIN
      - NET_BIND_SERVICE
    cap_drop:
      - ALL
    command:
      - run
      - -c
      - /etc/xray/config.json
    container_name: xray
    environment:
      - GODEBUG=multipathtcp=0
      - TZ=Europe/Moscow
    image: ghcr.io/xtls/xray-core:26.6.22
    logging:
      driver: json-file
      options:
        max-file: "3"
        max-size: 10m
    network_mode: host
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    user: "0:0"
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /etc/wgfleet/xray/config.json:/etc/xray/config.json:ro
`,
		},
		{
			in: XrayInput{ConfigPath: "/etc/wgfleet/client-vless/config.json", ListenPort: 47252},
			want: `services:
  xray:
    cap_drop:
      - ALL
    command:
      - run
      - -c
      - /etc/xray/config.json
    container_name: xray
    environment:
      - GODEBUG=multipathtcp=0
    image: ghcr.io/xtls/xray-core:26.6.22
    logging:
      driver: json-file
      options:
        max-file: "3"
        max-size: 10m
    network_mode: host
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    user: "0:0"
    volumes:
      - /etc/wgfleet/client-vless/config.json:/etc/xray/config.json:ro
`,
		},
	}
	for i, c := range cases {
		got, err := RenderXrayCompose(c.in)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got != c.want {
			t.Errorf("case %d drifted:\n--- got\n%s--- want\n%s", i, got, c.want)
		}
	}
}

// The master's portal is a second xray next to the client-facing one: same
// service key in its own compose project, a different container name. Its
// restart is driven by the agent so a boot before the SOCKS address exists does
// not crash-loop it.
func TestRenderXrayComposeCustomNameAndRestart(t *testing.T) {
	out, err := RenderXrayCompose(XrayInput{
		ConfigPath:    "/etc/wgfleet/reality-portal/config.json",
		ListenPort:    48123,
		ContainerName: "xray-portal",
		Restart:       "on-failure",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"container_name: xray-portal", "restart: on-failure", "\n  xray:\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "container_name: xray\n") {
		t.Errorf("default container name leaked:\n%s", out)
	}
}
