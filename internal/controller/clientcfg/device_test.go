package clientcfg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// devSrc: m1 fully ready (AWG + VLESS); m2 has an AWG leg with no published key;
// m3 ready with AWG only.
type devSrc struct {
	nodes   map[string]domain.Node
	specs   map[string]domain.NodeSpec
	wg      map[string][]domain.WGClient
	vless   map[string][]domain.VLESSClient
	devices map[string]domain.ClientDevice // by token
	legacy  map[string]string              // unattached, live credential ID -> master
	listErr map[string]error
}

func (s devSrc) GetNode(_ context.Context, id string) (domain.Node, error) {
	if n, ok := s.nodes[id]; ok {
		return n, nil
	}
	return domain.Node{}, store.ErrNotFound
}
func (s devSrc) RenderNodeSpec(_ context.Context, id string) (domain.NodeSpec, error) {
	if sp, ok := s.specs[id]; ok {
		return sp, nil
	}
	return domain.NodeSpec{}, store.ErrNotFound
}
func (s devSrc) ListWGClients(_ context.Context, m string) ([]domain.WGClient, error) {
	if err := s.listErr[m]; err != nil {
		return nil, err
	}
	return s.wg[m], nil
}
func (s devSrc) ListVLESSClients(_ context.Context, m string) ([]domain.VLESSClient, error) {
	return s.vless[m], nil
}
func (s devSrc) LifelineExits(context.Context) ([]string, error)                  { return nil, nil }
func (s devSrc) ExitEndpointHost(context.Context, string) (string, error)         { return "", nil }
func (s devSrc) NodeChecks(context.Context, string) ([]domain.HealthCheck, error) { return nil, nil }
func (s devSrc) ClientMasterMeta(_ context.Context, m string) (domain.ClientMasterMeta, error) {
	return domain.ClientMasterMeta{RouteThrough: []string{"10.20.0.0/16"},
		Resolvers: s.specs[m].Master.ClientWG.DNS, ClientPool: s.specs[m].Master.ClientWG.AddressPool}, nil
}
func (s devSrc) GetDeviceByToken(_ context.Context, tok string) (domain.ClientDevice, error) {
	if d, ok := s.devices[tok]; ok {
		return d, nil
	}
	return domain.ClientDevice{}, store.ErrNotFound
}
func (s devSrc) FindUnattachedWGClient(_ context.Context, id string) (string, domain.WGClient, error) {
	m, ok := s.legacy[id]
	if !ok {
		return "", domain.WGClient{}, store.ErrNotFound
	}
	for _, c := range s.wg[m] {
		if c.ID == id {
			return m, c, nil
		}
	}
	return "", domain.WGClient{}, store.ErrNotFound
}

func awgCred(m, ref string) domain.DeviceCredential {
	return domain.DeviceCredential{Kind: domain.CredentialAWG, MasterID: m, Ref: ref}
}

func newDevSrc() devSrc {
	cw := func(pool, dns string) *domain.ClientWGSpec {
		return &domain.ClientWGSpec{ListenPort: 443, AddressPool: pool, ServerAddress: dns,
			MTU: 1360, DNS: []string{dns}, AllowedIPs: []string{"0.0.0.0/0"}}
	}
	cred := func(id string, enabled bool) domain.WGClient {
		return domain.WGClient{ID: id, Name: "phone", Address: "10.80.0.2/32", PublicKey: "pub-" + id,
			PrivateKey: "PRIVATE-" + id, Enabled: enabled}
	}
	return devSrc{
		nodes: map[string]domain.Node{
			"m1": {ID: "m1", Name: "m1", PublicIP: "203.0.113.1", ClientWGPublicKey: "srv1", ClientVLESSPublicKey: "pbk1"},
			"m2": {ID: "m2", Name: "m2", PublicIP: "203.0.113.2"},
			"m3": {ID: "m3", Name: "m3", PublicIP: "203.0.113.3", ClientWGPublicKey: "srv3"},
		},
		specs: map[string]domain.NodeSpec{
			"m1": {Master: &domain.MasterSpec{ClientWG: cw("10.80.0.0/24", "10.80.0.1"),
				ClientVLESS: &domain.ClientVLESSServerSpec{ListenPort: 49443, ServerName: "www.python.org", AllowEmptySNI: true}}},
			"m2": {Master: &domain.MasterSpec{ClientWG: cw("10.81.0.0/24", "10.81.0.1")}},
			"m3": {Master: &domain.MasterSpec{ClientWG: cw("10.82.0.0/24", "10.82.0.1")}},
		},
		wg: map[string][]domain.WGClient{
			"m1": {cred("c1", true), cred("paused", false), cred("legacy-cred", true)},
			"m2": {cred("c2", true)},
			"m3": {cred("c3", true)},
		},
		vless:  map[string][]domain.VLESSClient{"m1": {{Name: "phone", UUID: "u1", ShortID: "aa"}}},
		legacy: map[string]string{"legacy-cred": "m1"},
		devices: map[string]domain.ClientDevice{
			"tok-full": {ID: "d1", Token: "tok-full", Name: "phone", Credentials: []domain.DeviceCredential{
				awgCred("m1", "c1"), {Kind: domain.CredentialVLESS, MasterID: "m1", Ref: "phone"}, awgCred("m2", "c2")}},
			"tok-paused":   {ID: "d2", Token: "tok-paused", Name: "old", Credentials: []domain.DeviceCredential{awgCred("m1", "paused")}},
			"tok-empty":    {ID: "d3", Token: "tok-empty", Name: "empty"},
			"tok-notready": {ID: "d4", Token: "tok-notready", Name: "nr", Credentials: []domain.DeviceCredential{awgCred("m2", "c2")}},
			// first master's credential paused, second not ready, third fine
			"tok-mixed": {ID: "d5", Token: "tok-mixed", Name: "mixed", Credentials: []domain.DeviceCredential{
				awgCred("m1", "paused"), awgCred("m2", "c2"), awgCred("m3", "c3")}},
		},
	}
}

var masters = []string{"m1", "m2", "m3"}

func TestBuildDeviceProfileSkipsANotReadyMasterOnly(t *testing.T) {
	src := newDevSrc()
	yml, err := BuildDeviceProfile(context.Background(), src, masters, src.devices["tok-full"])
	if err != nil {
		t.Fatalf("BuildDeviceProfile: %v", err)
	}
	for _, want := range []string{"m1-awg", "m1-vless", "PRIVATE-c1", "tcp://10.80.0.1:53#m1", "10.80.0.0/24,m1"} {
		if !strings.Contains(yml, want) {
			t.Errorf("profile missing %q", want)
		}
	}
	if strings.Contains(yml, "m2-awg") {
		t.Error("m2 has no published key yet and must be skipped, not rendered broken")
	}
}

func TestBuildDeviceProfilePausedAndNotReady(t *testing.T) {
	src := newDevSrc()
	ctx := context.Background()
	for _, tok := range []string{"tok-paused", "tok-empty"} {
		if _, err := BuildDeviceProfile(ctx, src, masters, src.devices[tok]); !errors.Is(err, ErrNoActiveCredential) {
			t.Errorf("%s: err = %v, want ErrNoActiveCredential", tok, err)
		}
	}
	_, err := BuildDeviceProfile(ctx, src, masters, src.devices["tok-notready"])
	if !errors.Is(err, ErrNotReady) || errors.Is(err, store.ErrNotFound) {
		t.Errorf("not-ready device: err = %v, want ErrNotReady and not ErrNotFound", err)
	}
}

func TestBuildDeviceProfileFailsWholeOnStoreError(t *testing.T) {
	src := newDevSrc()
	src.listErr = map[string]error{"m2": errors.New("database is locked")}
	_, err := BuildDeviceProfile(context.Background(), src, masters, src.devices["tok-full"])
	if err == nil || errors.Is(err, ErrNotReady) {
		t.Fatalf("store error produced %v: a thinned profile would be cached by the app for a day", err)
	}
}

func TestSelectWGSkipsPausedAndNotReady(t *testing.T) {
	src := newDevSrc()
	ctx := context.Background()
	sel, err := SelectWG(ctx, src, masters, src.devices["tok-mixed"])
	if err != nil || sel.MasterID != "m3" || sel.Input.Client.ID != "c3" {
		t.Fatalf("SelectWG = %+v, %v; want m3/c3 (m1 paused, m2 not ready)", sel, err)
	}
	if _, err := SelectWG(ctx, src, masters, src.devices["tok-paused"]); !errors.Is(err, ErrNoActiveCredential) {
		t.Errorf("all paused: %v", err)
	}
	if _, err := SelectWG(ctx, src, masters, src.devices["tok-notready"]); !errors.Is(err, ErrNotReady) {
		t.Errorf("only not-ready: %v", err)
	}
	if _, err := SelectWG(ctx, src, masters, src.devices["tok-empty"]); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("no AWG at all: %v", err)
	}
}

func TestResolveDeviceTokenFirstThenLegacy(t *testing.T) {
	src := newDevSrc()
	ctx := context.Background()
	if d, err := ResolveDevice(ctx, src, "tok-full"); err != nil || d.ID != "d1" {
		t.Fatalf("device token: %+v %v", d, err)
	}
	d, err := ResolveDevice(ctx, src, "legacy-cred")
	if err != nil || !d.Legacy() || d.Token != "legacy-cred" || len(d.Credentials) != 1 {
		t.Fatalf("legacy credential: %+v %v", d, err)
	}
	if c := d.Credentials[0]; c.Kind != domain.CredentialAWG || c.MasterID != "m1" || c.Ref != "legacy-cred" {
		t.Errorf("legacy credential view = %+v", c)
	}
	if _, err := ResolveDevice(ctx, src, "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an attached credential's ID resolved through the legacy path: %v", err)
	}
}

func TestViewDeviceUsesTheSameSelection(t *testing.T) {
	src := newDevSrc()
	v, err := ViewDevice(context.Background(), src, masters, src.devices["tok-mixed"])
	if err != nil || !v.Active || v.WG == nil || v.WG.Input.Client.ID != "c3" {
		t.Fatalf("view = %+v, %v", v, err)
	}
	v, err = ViewDevice(context.Background(), src, masters, src.devices["tok-full"])
	if err != nil || len(v.VLESSLinks) != 1 || !strings.HasPrefix(v.VLESSLinks[0], "vless://u1@203.0.113.1:49443") {
		t.Errorf("links = %v, %v", v.VLESSLinks, err)
	}
}
