package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestStoreCollectorClientInfoNamesEveryPeer(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)
	for _, n := range []domain.Node{
		{ID: "m1", Name: "master-1", Role: domain.RoleMaster, State: domain.StateReady},
		{ID: "e1", Name: "exit-1", Role: domain.RoleExit, State: domain.StateReady},
	} {
		if err := st.UpsertNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateDevice(ctx, domain.ClientDevice{ID: "d1", Token: "tok", Name: "pixel", CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	onDevice := domain.WGClient{ID: "c1", Name: "alice", Address: "10.73.0.2/32", PublicKey: "PUBalice=", PrivateKey: "x", Enabled: true, CreatedAt: at}
	if err := st.AddWGClientToDevice(ctx, "m1", onDevice, "d1"); err != nil {
		t.Fatal(err)
	}
	// A muted credential still owns its traffic history: it keeps its name.
	lone := domain.WGClient{ID: "c2", Name: "bob", Address: "10.73.0.3/32", PublicKey: "PUBbob=", PrivateKey: "y", Enabled: false, CreatedAt: at}
	if err := st.AddWGClient(ctx, "m1", lone); err != nil {
		t.Fatal(err)
	}

	want := `
# HELP wgfleet_client_info Client-facing WireGuard credential behind a peer public key; value is always 1. Join on peer to name wgfleet_wg_peer_* series, on the master's wg0 and on an exit's lifeline interface alike.
# TYPE wgfleet_client_info gauge
wgfleet_client_info{client="alice",device="pixel",node="master-1",peer="PUBalice="} 1
wgfleet_client_info{client="bob",device="",node="master-1",peer="PUBbob="} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_client_info"); err != nil {
		t.Error(err)
	}
}

// The private key sits in the same struct the collector reads. It must never
// reach a label — the metrics endpoint is unauthenticated.
func TestStoreCollectorClientInfoNeverCarriesThePrivateKey(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "m1", Name: "master-1", Role: domain.RoleMaster, State: domain.StateReady})
	c := domain.WGClient{ID: "c1", Name: "alice", Address: "10.73.0.2/32", PublicKey: "PUB=", PrivateKey: "SECRET-PRIVATE-KEY", Enabled: true, CreatedAt: time.Unix(1, 0)}
	if err := st.AddWGClient(ctx, "m1", c); err != nil {
		t.Fatal(err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), "SECRET") {
					t.Fatalf("%s label %s carries the client's private key", mf.GetName(), l.GetName())
				}
			}
		}
	}
}
