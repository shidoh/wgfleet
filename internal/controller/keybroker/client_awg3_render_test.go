package keybroker

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/wg"
)

// clientLegRenders is everything one master's client leg produces in a given
// client_awg.awg3 mode: the master's own interface (wg0), one end user's .conf
// and the same user's mihomo profile. The credential and keys are fixed so two
// modes can be compared byte for byte.
type clientLegRenders struct {
	server, conf, profile string
}

func renderClientLeg(t *testing.T, mode config.ClientAWG3Mode, user domain.WGClient, serverPriv, serverPub string) clientLegRenders {
	t.Helper()
	b, st := newBrokerWithFleet(t, managedFleetAWG3(mode))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", serverPub, domain.RoleMaster)
	setWireVersion(t, st, "master-xa-1", api.WireAWG3TrackB)
	spec, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cw := spec.Master.ClientWG
	if cw == nil || cw.AWG == nil {
		t.Fatal("no client interface rendered")
	}
	ifaceSpec := *cw
	ifaceSpec.Clients = domain.PeersOf([]domain.WGClient{user})
	server, err := wg.RenderClientInterface(wg.ClientInterfaceInput{Spec: ifaceSpec, PrivateKey: serverPriv})
	if err != nil {
		t.Fatalf("server render: %v", err)
	}
	in := wg.ClientConfigInput{Spec: *cw, Client: user, ServerPublicKey: serverPub, Endpoint: "203.0.113.1:443"}
	conf, err := wg.RenderClientConfig(in)
	if err != nil {
		t.Fatalf("client .conf render: %v", err)
	}
	profile, err := mihomo.RenderClientProfile(mihomo.ClientProfileInput{
		Masters: []mihomo.ClientProfileMaster{{Name: "master-xa-1", AWG: &in, DNS: cw.DNS}},
	})
	if err != nil {
		t.Fatalf("mihomo profile render: %v", err)
	}
	return clientLegRenders{server: server, conf: conf, profile: profile}
}

// The 3.x timers are per-end: a peer on the defaults keeps working against a
// server that randomises them. So "timers" must change the master's interface and
// NOTHING a client holds — the .conf and the mihomo profile stay byte-identical to
// "off", which is what lets older apps that refuse a 3.x profile keep their
// config. "full" adds header protection, which must match on both ends, so the
// key reaches the client — and still no timer does.
func TestClientLegAWG3ModesPerRender(t *testing.T) {
	serverKP, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	userKP, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	user := domain.WGClient{ID: "c-1", Name: "laptop", Address: "10.80.0.2/32",
		PublicKey: userKP.PublicKey, PrivateKey: userKP.PrivateKey, Enabled: true}
	off := renderClientLeg(t, config.ClientAWG3Off, user, serverKP.PrivateKey, serverKP.PublicKey)

	timerKeys := []string{"RekeyAfterTime", "KeepaliveTimeout", "RekeyTimeout", "RejectAfterTime", "MaxHandshakeAttempts"}
	timerOpts := []string{"rekey-after-time", "keepalive-timeout", "rekey-timeout", "reject-after-time", "max-handshake-attempts"}

	for _, tc := range []struct {
		mode                config.ClientAWG3Mode
		clientSameAsOff     bool
		serverTimers        bool
		clientHeaderProtect bool
		profileHasVersion3  bool
	}{
		{config.ClientAWG3Off, true, false, false, false},
		{config.ClientAWG3Timers, true, true, false, false},
		{config.ClientAWG3Full, false, true, true, true},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			got := renderClientLeg(t, tc.mode, user, serverKP.PrivateKey, serverKP.PublicKey)

			if tc.clientSameAsOff {
				if got.conf != off.conf {
					t.Errorf(".conf differs from off:\n--- off\n%s\n--- %s\n%s", off.conf, tc.mode, got.conf)
				}
				if got.profile != off.profile {
					t.Errorf("mihomo profile differs from off:\n--- off\n%s\n--- %s\n%s", off.profile, tc.mode, got.profile)
				}
			}
			for _, k := range []string{"RekeyAfterTime", "KeepaliveTimeout"} {
				if has := strings.Contains(got.server, k+" = "); has != tc.serverTimers {
					t.Errorf("server wg0: %s present=%v, want %v\n%s", k, has, tc.serverTimers, got.server)
				}
			}
			for _, k := range []string{"RekeyTimeout", "RejectAfterTime", "MaxHandshakeAttempts"} {
				if strings.Contains(got.server, k+" = ") {
					t.Errorf("server wg0 sets %s; it must stay at the WireGuard default", k)
				}
			}
			for _, k := range timerKeys {
				if strings.Contains(got.conf, k+" = ") {
					t.Errorf(".conf carries %s; timers are server-only", k)
				}
			}
			for _, k := range timerOpts {
				if strings.Contains(got.profile, k+":") {
					t.Errorf("mihomo profile carries %s; timers are server-only", k)
				}
			}
			for what, text := range map[string]string{"server wg0": got.server, ".conf": got.conf} {
				if has := strings.Contains(text, "HeaderProtectionKey = "); has != tc.clientHeaderProtect {
					t.Errorf("%s: HeaderProtectionKey present=%v, want %v", what, has, tc.clientHeaderProtect)
				}
			}
			if has := strings.Contains(got.profile, "version: 3"); has != tc.profileHasVersion3 {
				t.Errorf("mihomo profile: version: 3 present=%v, want %v", has, tc.profileHasVersion3)
			}
		})
	}
}
