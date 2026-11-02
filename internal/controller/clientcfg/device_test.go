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
	// lastResort marks a master's VLESS as client_vless.last_resort.
	lastResort map[string]bool
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
func (s devSrc) LifelineMaster(context.Context) (string, error)                   { return "m1", nil }
func (s devSrc) ExitEndpointHost(context.Context, string) (string, error)         { return "", nil }
func (s devSrc) NodeChecks(context.Context, string) ([]domain.HealthCheck, error) { return nil, nil }
func (s devSrc) ClientMasterMeta(_ context.Context, m string) (domain.ClientMasterMeta, error) {
	return domain.ClientMasterMeta{RouteThrough: []string{"10.20.0.0/16"},
		Resolvers: s.specs[m].Master.ClientWG.DNS, ClientPool: s.specs[m].Master.ClientWG.AddressPool,
		VLESSLastResort: s.lastResort[m]}, nil
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
			"m2": {cred("c2", true), cred("c2-paused", false)},
			"m3": {cred("c3", true)},
			// m4 is never registered (absent from nodes/specs): a credential can still
			// be listed against it, the way a store race or a not-yet-applied
			// registration would leave one.
			"m4": {cred("c4", true)},
		},
		vless: map[string][]domain.VLESSClient{
			"m1": {{Name: "phone", UUID: "u1", ShortID: "aa"}},
			"m4": {{Name: "phone", UUID: "u4", ShortID: "bb"}},
		},
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
			// vless-only: no AWG credential at all.
			"tok-vless-only": {ID: "d6", Token: "tok-vless-only", Name: "vless-only",
				Credentials: []domain.DeviceCredential{{Kind: domain.CredentialVLESS, MasterID: "m1", Ref: "phone"}}},
			// this device's only AWG credential sits on a master the store does not know.
			"tok-unregistered-awg": {ID: "d7", Token: "tok-unregistered-awg", Name: "unreg-awg",
				Credentials: []domain.DeviceCredential{awgCred("m4", "c4")}},
			// same, for the VLESS leg.
			"tok-unregistered-vless": {ID: "d8", Token: "tok-unregistered-vless", Name: "unreg-vless",
				Credentials: []domain.DeviceCredential{{Kind: domain.CredentialVLESS, MasterID: "m4", Ref: "phone"}}},
			// paused, AND its master (m2) has no published key: pause must win.
			"tok-paused-notready": {ID: "d9", Token: "tok-paused-notready", Name: "paused-nr",
				Credentials: []domain.DeviceCredential{awgCred("m2", "c2-paused")}},
		},
	}
}

var masters = []string{"m1", "m2", "m3"}

// mastersWithUnregistered adds m4, which the store has never heard of, to the
// walk order — for the tests that hold a credential against it.
var mastersWithUnregistered = []string{"m1", "m2", "m3", "m4"}

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

// A master marked client_vless.last_resort keeps its VLESS in the profile, at
// the very end of the fleet-wide fallback.
func TestBuildDeviceProfileCarriesVLESSLastResort(t *testing.T) {
	src := newDevSrc()
	src.lastResort = map[string]bool{"m1": true}
	p, err := collectDevice(context.Background(), src, masters, src.devices["tok-full"])
	if err != nil {
		t.Fatalf("collectDevice: %v", err)
	}
	var found bool
	for _, m := range p.masters {
		if m.Name == "m1" {
			found = true
			if !m.VLESSLastResort || m.VLESS == nil {
				t.Errorf("m1 = last resort %v, vless %v; want both", m.VLESSLastResort, m.VLESS != nil)
			}
		} else if m.VLESSLastResort {
			t.Errorf("%s marked last resort without being asked", m.Name)
		}
	}
	if !found {
		t.Fatal("m1 missing from the device's masters")
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

// TestBuildDeviceProfilePausedCredentialOnNotReadyMaster covers a credential
// that is BOTH paused AND sitting on a master with no published key yet: pause
// must still win — ErrNoActiveCredential, the same as any other paused-only
// device, not ErrNotReady.
func TestBuildDeviceProfilePausedCredentialOnNotReadyMaster(t *testing.T) {
	src := newDevSrc()
	_, err := BuildDeviceProfile(context.Background(), src, masters, src.devices["tok-paused-notready"])
	if !errors.Is(err, ErrNoActiveCredential) {
		t.Errorf("paused credential on a not-ready master: err = %v, want ErrNoActiveCredential", err)
	}
}

// TestBuildDeviceProfileUnregisteredMasterIsNotReady covers a device whose only
// credential — AWG or VLESS — sits on a master the store has never heard of.
// That must skip the master and surface as ErrNotReady, exactly like any other
// not-ready master, never as the raw store.ErrNotFound GetNode/RenderNodeSpec
// return: a store race or a not-yet-applied registration is not a broken profile.
func TestBuildDeviceProfileUnregisteredMasterIsNotReady(t *testing.T) {
	src := newDevSrc()
	ctx := context.Background()
	for _, tok := range []string{"tok-unregistered-awg", "tok-unregistered-vless"} {
		_, err := BuildDeviceProfile(ctx, src, mastersWithUnregistered, src.devices[tok])
		if !errors.Is(err, ErrNotReady) || errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotReady and not a raw store.ErrNotFound", tok, err)
		}
	}
}

// TestBuildDeviceProfileVLESSOnly covers a device with no AWG credential at
// all: the profile must still render with the VLESS proxy alone, not refuse for
// want of a .conf nobody asked this device to carry.
func TestBuildDeviceProfileVLESSOnly(t *testing.T) {
	src := newDevSrc()
	yml, err := BuildDeviceProfile(context.Background(), src, masters, src.devices["tok-vless-only"])
	if err != nil {
		t.Fatalf("BuildDeviceProfile: %v", err)
	}
	if !strings.Contains(yml, "m1-vless") {
		t.Error("profile missing m1-vless")
	}
	if strings.Contains(yml, "m1-awg") {
		t.Error("a vless-only device must not render an awg proxy")
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
	if _, err := SelectWG(ctx, src, masters, src.devices["tok-empty"]); !errors.Is(err, ErrNoAWG) || errors.Is(err, store.ErrNotFound) {
		t.Errorf("no AWG at all: err = %v, want ErrNoAWG and not store.ErrNotFound", err)
	}
	if _, err := SelectWG(ctx, src, masters, src.devices["tok-vless-only"]); !errors.Is(err, ErrNoAWG) || errors.Is(err, store.ErrNotFound) {
		t.Errorf("vless-only device: err = %v, want ErrNoAWG and not store.ErrNotFound", err)
	}
}

// TestSelectWGUnregisteredMasterIsNotReady covers a device whose only AWG
// credential sits on a master the store has never heard of (GetNode fails
// store.ErrNotFound). That must read as not-ready, not as a missing credential:
// deleting a master cascades its credentials, so the credential surviving while
// the master is gone is always transient, never a dead link to answer 404 to.
func TestSelectWGUnregisteredMasterIsNotReady(t *testing.T) {
	src := newDevSrc()
	_, err := SelectWG(context.Background(), src, mastersWithUnregistered, src.devices["tok-unregistered-awg"])
	if !errors.Is(err, ErrNotReady) {
		t.Errorf("unregistered master: err = %v, want ErrNotReady", err)
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
