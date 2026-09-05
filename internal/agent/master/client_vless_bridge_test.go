package master

import (
	"encoding/json"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/xray"
)

// The SOCKS bridge between xray and mihomo has two ends, rendered by two packages
// into two files. They must name the same socket.
//
// They stopped doing so the moment mihomo moved into its own network namespace:
// the listener followed the move, xray's outbound kept the literal "127.0.0.1",
// and inside a namespace that is a DIFFERENT loopback. xray accepted every REALITY
// client and dropped it on the outbound — a three-hour outage that neither side's
// own tests could see, because each one was right about its own half.
//
// So the assertion is not "the address is X" but "both halves agree", in both
// states the master can be in.
func TestTheClientVLESSBridgeHasTheSameAddressAtBothEnds(t *testing.T) {
	cv := &domain.ClientVLESSServerSpec{
		ListenPort: 49443,
		Clients:    []domain.VLESSClient{{Name: "alice", UUID: "11111111-1111-4111-8111-111111111111", ShortID: "0badc0de"}},
		ServerName: "www.python.org",
		Dest:       "www.python.org:443",
		SocksPort:  domain.ClientVLESSSocksPort,
	}
	master := domain.MasterSpec{
		BindAddress:        "10.80.0.1",
		RedirPort:          7895,
		ExternalController: "172.29.3.10:9090",
		ExitTunnels: []domain.ExitTunnel{{
			Name: "exit-a", Endpoint: "exit-a.example.net:36050",
			ServerPublicKey: "tonqJKi1LFkgd150tF0eNEJDGyeRqT40QlUCtnWUh3A=",
			TunnelIP:        "10.81.0.2", MTU: 1380,
		}},
		ClientVLESS: cv,
	}

	for _, tc := range []struct {
		name  string
		peer  string
		wants string
	}{
		{"on the host, the bridge is the loopback", "", "127.0.0.1"},
		{"in the namespace, the loopback is somebody else's", "100.127.255.2", "100.127.255.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mcfg, err := mihomo.RenderConfig(mihomo.RenderInput{
				Spec: master, PrivateKey: "MASTERPRIVKEYbase64ExampleValueForTestingABC=",
				NetnsPeerAddr: tc.peer,
			})
			if err != nil {
				t.Fatalf("mihomo render: %v", err)
			}
			xcfg, err := xray.RenderClientConfig(xray.ClientRenderInput{
				Spec: *cv, PrivateKey: "PRIVKEY",
				SocksHost: mihomo.ClientVLESSBridgeAddr(tc.peer),
			})
			if err != nil {
				t.Fatalf("xray render: %v", err)
			}

			listens := bridgeListenAddr(t, mcfg)
			dials := bridgeDialAddr(t, xcfg)
			if listens != tc.wants {
				t.Errorf("mihomo listens on %q, want %q", listens, tc.wants)
			}
			if dials != tc.wants {
				t.Errorf("xray dials %q, want %q", dials, tc.wants)
			}
			if listens != dials {
				t.Errorf("the bridge has two different addresses: mihomo listens on %q, xray dials %q",
					listens, dials)
			}
		})
	}
}

// bridgeListenAddr digs the client-vless listener out of mihomo's YAML.
func bridgeListenAddr(t *testing.T, cfg string) string {
	t.Helper()
	var c struct {
		Listeners []struct {
			Name   string `yaml:"name"`
			Listen string `yaml:"listen"`
		} `yaml:"listeners"`
	}
	if err := yaml.Unmarshal([]byte(cfg), &c); err != nil {
		t.Fatalf("mihomo config is not valid YAML: %v", err)
	}
	for _, l := range c.Listeners {
		if l.Name == "client-vless-in" {
			return l.Listen
		}
	}
	t.Fatalf("mihomo rendered no client-vless listener:\n%s", cfg)
	return ""
}

// bridgeDialAddr digs the socks outbound out of xray's JSON.
func bridgeDialAddr(t *testing.T, cfg string) string {
	t.Helper()
	var c struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Servers []struct {
					Address string `json:"address"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(cfg), &c); err != nil {
		t.Fatalf("xray config is not valid JSON: %v", err)
	}
	for _, o := range c.Outbounds {
		if o.Protocol == "socks" && len(o.Settings.Servers) > 0 {
			return o.Settings.Servers[0].Address
		}
	}
	t.Fatalf("xray rendered no socks outbound:\n%s", cfg)
	return ""
}
