package keybroker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestExitSpecBridgesToEveryMaster(t *testing.T) {
	s := newReverseSetup(t)
	spec, err := s.b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	r := spec.Reality
	if r == nil || r.Bridge == nil {
		t.Fatalf("Reality = %+v, want a bridge", r)
	}
	// No inbound: the port is closed and the firewall opens nothing for it.
	if r.ListenPort != 0 || r.UUID != "" || spec.Firewall.RealityPort != 0 {
		t.Errorf("listen port %d, uuid %q, firewall port %d — want no inbound", r.ListenPort, r.UUID, spec.Firewall.RealityPort)
	}
	if r.Image == "" {
		t.Error("bridge has no image")
	}
	ps := r.Bridge.Portals
	if len(ps) != 2 || ps[0].Master != "master-xa-1" || ps[1].Master != "master-xa-2" {
		t.Fatalf("portals = %+v, want both masters by slot", ps)
	}
	for _, p := range ps {
		uuid, sid := portalIDs("exit-de-1", p.Master)
		if p.UUID != uuid || p.ShortID != sid || p.PublicKey != s.pubs[p.Master] || p.ServerName != DefaultRealitySNI {
			t.Errorf("portal %s = %+v", p.Master, p)
		}
	}
	if err := r.Bridge.Validate(); err != nil {
		t.Errorf("rendered bridge invalid: %v", err)
	}
}

func TestExitSpecFingerprintDefaultsToChrome(t *testing.T) {
	s := newReverseSetup(t)
	spec, err := s.b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if fp := spec.Reality.Bridge.Portals[0].ResolvedFingerprint(); fp != "chrome" {
		t.Errorf("fingerprint = %q, want chrome", fp)
	}
	s.b.fleet.Exits[0].Transports.Reality.Fingerprint = "firefox"
	spec, err = s.b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if fp := spec.Reality.Bridge.Portals[0].ResolvedFingerprint(); fp != "firefox" {
		t.Errorf("fingerprint = %q, want the exit's firefox", fp)
	}
}

// Until the mode is live for the exit (its agent on wire 13), the flag must
// change nothing at all in its spec.
func TestExitSpecUnarmedIsByteIdenticalToFlagOff(t *testing.T) {
	render := func(s reverseSetup) []byte {
		t.Helper()
		spec, err := s.b.RenderNodeSpec(context.Background(), "exit-de-1")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(spec)
		return b
	}
	off := newReverseSetup(t)
	off.b.fleet.Exits[0].Transports.Reality.ExitInitiated = false
	want := render(off)

	old := newReverseSetup(t)
	setWireVersion(t, old.st, "exit-de-1", 13)
	if got := render(old); string(got) != string(want) {
		t.Errorf("exit on wire 13: spec differs from flag off\n got %s\nwant %s", got, want)
	}
}

// In the mode with no master ready the exit dials nothing — it does not fall
// back to listening, which is what the filter kills.
func TestExitSpecWithNoReadyMasterKeepsTheModeWithNoPortals(t *testing.T) {
	s := newReverseSetup(t)
	setWireVersion(t, s.st, "master-xa-1", 13)
	setWireVersion(t, s.st, "master-xa-2", 13)
	spec, err := s.b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Reality == nil || spec.Reality.Bridge == nil || len(spec.Reality.Bridge.Portals) != 0 || spec.Reality.ListenPort != 0 {
		t.Fatalf("Reality = %+v, want the mode with an empty portal list", spec.Reality)
	}
	if !spec.HasTransport(domain.TransportRealityXHTTP) {
		t.Error("REALITY dropped from the enabled transports")
	}
}
