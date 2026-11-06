package keybroker

import (
	"context"
	"regexp"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

func forwardRealityBroker(t *testing.T) *Broker {
	t.Helper()
	ctx := context.Background()
	fleet := testFleet()
	fleet.Exits[0].Transports = config.TransportsConfig{AWG: config.AWGTransportConfig{Enabled: true}, Reality: config.RealityTransportConfig{Enabled: true}}
	fleet.Exits[0].ActiveTransport = "reality-xhttp"
	b, st := newBrokerWithFleet(t, fleet)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	_, realityPub, _ := xray.GenerateKeypair()
	if err := st.SetNodeRealityKey(ctx, "exit-de-1", realityPub); err != nil {
		t.Fatal(err)
	}
	return b
}

// forwardIDs renders both ends and returns the identity each one holds.
func forwardIDs(t *testing.T, b *Broker) (master, exit domain.RealityServerSpec) {
	t.Helper()
	ctx := context.Background()
	mSpec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render master: %v", err)
	}
	for _, tn := range mSpec.Master.ExitTunnels {
		if tn.Transport.OrDefault() == domain.TransportRealityXHTTP {
			master = domain.RealityServerSpec{UUID: tn.Reality.UUID, ShortID: tn.Reality.ShortID, XHTTPPath: tn.Reality.XHTTPPath}
		}
	}
	eSpec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	if eSpec.Reality == nil {
		t.Fatal("exit spec has no REALITY inbound")
	}
	return master, *eSpec.Reality
}

var hexShortID = regexp.MustCompile(`^[0-9a-f]{16}$`)

// The tunnel's VLESS id and short-id are random and stored, not computed from the
// node names: anyone who knows the names and reads the source could compute the
// old ones. Both ends must still hold the same pair, render after render.
func TestForwardRealityIDsAreRandomStableAndShared(t *testing.T) {
	b := forwardRealityBroker(t)
	m, e := forwardIDs(t, b)
	if m.UUID == "" || m.UUID != e.UUID || m.ShortID != e.ShortID || m.XHTTPPath != e.XHTTPPath {
		t.Fatalf("ends disagree: master %+v, exit uuid=%q sid=%q path=%q", m, e.UUID, e.ShortID, e.XHTTPPath)
	}
	if !hexShortID.MatchString(e.ShortID) {
		t.Errorf("short-id %q, want 16 hex characters", e.ShortID)
	}
	if m2, _ := forwardIDs(t, b); m2.UUID != m.UUID || m2.ShortID != m.ShortID {
		t.Error("the identity changed between renders")
	}
	if other, _ := forwardIDs(t, forwardRealityBroker(t)); other.UUID == m.UUID {
		t.Error("a second controller computed the same id: it is derivable")
	}
}

// An unreadable store fails the render rather than inventing an identity the
// other end will never see.
func TestForwardRealityIDsFailTheRenderOnAnUnreadableStore(t *testing.T) {
	b := forwardRealityBroker(t)
	b.store = failingTunnelIDs{Store: b.store}
	if _, err := b.RenderNodeSpec(context.Background(), "exit-de-1"); err == nil {
		t.Error("exit render succeeded without its tunnel identity")
	}
}

type failingTunnelIDs struct{ store.Store }

func (failingTunnelIDs) EnsureRealityTunnelIDs(context.Context, string, string, string, string) (string, string, error) {
	return "", "", errStoreDown
}
