package mihomo

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

// reverseInput adds exit-c in the exit-initiated REALITY mode: an AWG tunnel and
// a reverse REALITY tunnel the master reaches over its portal's SOCKS inbound.
func reverseInput() RenderInput {
	in := sampleInput()
	in.Spec.ExitTunnels = append(in.Spec.ExitTunnels,
		domain.ExitTunnel{
			Name: "exit-c", Endpoint: "exit-c.example.net:40000",
			ServerPublicKey: "tonqJKi1LFkgd150tF0eNEJDGyeRqT40QlUCtnWUh3A=",
			TunnelIP:        "10.83.0.2", MTU: 1380, AWG: awgFor(6), Drained: true,
		},
		domain.ExitTunnel{
			Name: "exit-c-reality", Transport: domain.TransportRealityXHTTP,
			Reality: &domain.RealityTunnel{Reverse: true},
		},
	)
	in.Spec.RealityPortal = &domain.RealityPortalSpec{ListenPort: 48123, SocksPort: domain.RealityPortalSocksPort}
	in.PortalSocksAddr = "127.0.0.1"
	in.PortalPasswords = map[string]string{"exit-c": "pw-exit-c-0123456789abcdef012345"}
	return in
}

func renderDoc(t *testing.T, in RenderInput) (string, map[string]any) {
	t.Helper()
	out, err := RenderConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	return out, doc
}

func TestReverseRealityProxyIsSocks5(t *testing.T) {
	_, doc := renderDoc(t, reverseInput())
	p := proxyNamed(t, doc, "exit-c-reality")
	want := map[string]any{
		"type": "socks5", "server": "127.0.0.1", "port": domain.RealityPortalSocksPort,
		"username": "exit-c", "password": "pw-exit-c-0123456789abcdef012345", "udp": true,
	}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v (proxy %v)", k, p[k], v, p)
		}
	}
	for _, k := range []string{"uuid", "reality-opts", "tls"} {
		if _, ok := p[k]; ok {
			t.Errorf("reverse proxy carries %s: %v", k, p)
		}
	}
}

// Without the address or the password the proxy would dial nothing or be
// refused; fail the render so the last good config keeps running.
func TestReverseRealityProxyNeedsPortalAddr(t *testing.T) {
	for name, mutate := range map[string]func(*RenderInput){
		"no address":  func(in *RenderInput) { in.PortalSocksAddr = "" },
		"no password": func(in *RenderInput) { in.PortalPasswords = nil },
		"no portal":   func(in *RenderInput) { in.Spec.RealityPortal = nil },
	} {
		t.Run(name, func(t *testing.T) {
			in := reverseInput()
			mutate(&in)
			if _, err := RenderConfig(in); err == nil {
				t.Fatal("rendered anyway")
			}
		})
	}
}

// The name is the transport's, not the mode's: tiers and standby work on it as
// they do for a forward REALITY tunnel.
func TestTierMembersAndStandbyWithReverseTunnel(t *testing.T) {
	in := reverseInput()
	primary, _ := TierMembers(in.Spec)
	if !contains(primary, "exit-c-reality") || contains(primary, "exit-c") {
		t.Errorf("primary = %v, want the reverse tunnel and not the drained AWG one", primary)
	}
	in.Spec.ExitTunnels[2].Drained = false
	in.Spec.ExitTunnels[3].Drained = true
	if sb := StandbyProxies(in.Spec); !contains(sb, "exit-c-reality") {
		t.Errorf("standby = %v, want the drained reverse tunnel", sb)
	}
}

func TestRedactConfigMasksSocksPassword(t *testing.T) {
	out, _ := renderDoc(t, reverseInput())
	if red := RedactConfig(out); strings.Contains(red, "pw-exit-c-0123456789abcdef012345") {
		t.Errorf("SOCKS password in plan output:\n%s", red)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
