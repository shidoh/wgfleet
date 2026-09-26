package keybroker

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func deviceFleet() config.FleetSection {
	return config.FleetSection{
		MgmtSubnet: "172.29.0.0/16",
		Masters: []config.MasterConfig{{
			Name:      "m1",
			DNSFilter: true,
			ClientAWG: config.ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24",
				RouteThroughCIDRs: []string{"10.20.0.0/16"}},
			ClientVLESS: config.ClientVLESSConfig{Enabled: true,
				RouteThroughCIDRs: []string{"10.20.0.0/16", "10.30.0.0/16"}},
		}},
	}
}

func seedMaster(t *testing.T, st store.Store) {
	t.Helper()
	if err := st.UpsertNode(context.Background(), domain.Node{ID: "m1", Name: "m1", Role: domain.RoleMaster, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateDeviceMintsTokenBeforeTheWrite(t *testing.T) {
	b, _ := newBrokerWithFleet(t, deviceFleet())
	d, err := b.CreateDevice(context.Background(), "alice-phone")
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := hex.DecodeString(d.Token); err != nil || len(raw) != 16 {
		t.Errorf("token %q is not 16 random bytes in hex", d.Token)
	}
	if d.ID == "" || d.ID == d.Token || d.CreatedAt.IsZero() {
		t.Errorf("device = %+v", d)
	}
	if _, err := b.CreateDevice(context.Background(), "bad name"); err == nil {
		t.Error("invalid name accepted")
	}
}

func TestRotateDeviceTokenChangesOnlyTheToken(t *testing.T) {
	b, _ := newBrokerWithFleet(t, deviceFleet())
	ctx := context.Background()
	d, _ := b.CreateDevice(ctx, "a")
	r, err := b.RotateDeviceToken(ctx, d.ID)
	if err != nil || r.Token == d.Token || r.ID != d.ID {
		t.Fatalf("rotate = %+v, %v", r, err)
	}
	if _, err := b.GetDeviceByToken(ctx, d.Token); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("old token still resolves: %v", err)
	}
}

func TestIssueForDeviceNamesAfterTheDeviceAndAttaches(t *testing.T) {
	b, st := newBrokerWithFleet(t, deviceFleet())
	seedMaster(t, st)
	ctx := context.Background()
	d, _ := b.CreateDevice(ctx, "alice-phone")
	wc, err := b.IssueWGClientForDevice(ctx, "m1", d.ID)
	if err != nil || wc.Name != "alice-phone" {
		t.Fatalf("wg = %+v, %v", wc, err)
	}
	if _, err := b.IssueVLESSClientForDevice(ctx, "m1", d.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.GetDevice(ctx, d.ID); len(got.Credentials) != 2 {
		t.Errorf("credentials = %+v", got.Credentials)
	}
	if _, err := b.IssueWGClientForDevice(ctx, "m1", d.ID); !errors.Is(err, store.ErrDeviceSlotTaken) {
		t.Errorf("second AWG on the same master: %v", err)
	}
	if _, _, err := b.FindUnattachedWGClient(ctx, wc.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a credential issued onto a device has a live personal link: %v", err)
	}
}

func TestDetachKeepsAnOrdinaryToken(t *testing.T) {
	b, st := newBrokerWithFleet(t, deviceFleet())
	seedMaster(t, st)
	ctx := context.Background()
	d, _ := b.CreateDevice(ctx, "a")
	wc, _ := b.IssueWGClientForDevice(ctx, "m1", d.ID)
	if err := b.DetachCredential(ctx, domain.CredentialAWG, "m1", wc.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := b.GetDevice(ctx, d.ID); err != nil || got.Token != d.Token {
		t.Errorf("an ordinary device's token changed on detach: %+v %v", got, err)
	}
}

func TestClientMasterMeta(t *testing.T) {
	b, _ := newBrokerWithFleet(t, deviceFleet())
	m, err := b.ClientMasterMeta(context.Background(), "m1")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.RouteThrough) != 2 || m.RouteThrough[0] != "10.20.0.0/16" || m.RouteThrough[1] != "10.30.0.0/16" {
		t.Errorf("route-through = %v, want the union without duplicates", m.RouteThrough)
	}
	if len(m.Resolvers) != 1 || m.Resolvers[0] != "10.80.0.1" {
		t.Errorf("resolvers = %v (dns_filter master ⇒ the client pool gateway, as the .conf)", m.Resolvers)
	}
	if m.ClientPool != "10.80.0.0/24" || len(m.MgmtCIDRs) != 1 || m.MgmtCIDRs[0] != "172.29.0.0/16" {
		t.Errorf("meta = %+v", m)
	}
	if _, err := b.ClientMasterMeta(context.Background(), "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown master: %v", err)
	}
}

func TestMastersFollowTheManifest(t *testing.T) {
	f := deviceFleet()
	f.Masters = append(f.Masters, config.MasterConfig{Name: "m0",
		ClientAWG: config.ClientAWGConfig{ListenPort: 443, AddressPool: "10.81.0.0/24"}})
	b, _ := newBrokerWithFleet(t, f)
	if got := b.Masters(); len(got) != 2 || got[0] != "m1" || got[1] != "m0" {
		t.Errorf("Masters() = %v", got)
	}
}
