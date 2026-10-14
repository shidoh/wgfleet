package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/domain"
)

const (
	alicePub  = "ALICEkey0000000000000000000000000000000000="
	bobPub    = "BOBkey00000000000000000000000000000000000000="
	aliceUUID = "11111111-1111-4111-8111-111111111111"
	carolUUID = "33333333-3333-4333-8333-333333333333"
)

// The label must be the agent's form of the key: the dashboard joins
// wgfleet_wg_peer_*{peer} to this on(peer). The first version used the whole key
// while the agent labels a short prefix, and the join matched nothing in prod.
func TestClientInfoPeerMatchesTheAgentsPeerLabel(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "m1", Name: "master-1", Role: domain.RoleMaster, State: domain.StateReady})
	if err := st.AddWGClient(ctx, "m1", domain.WGClient{ID: "c1", Name: "alice", Address: "10.73.0.2/32", PublicKey: alicePub, PrivateKey: "x", Enabled: true, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	// What the agent emits for this peer, through its own parser.
	agentPeer := ""
	for _, p := range parseWGDump("priv\tpub\t51820\toff\n" + alicePub + "\t(none)\t1.2.3.4:5\t10.73.0.2/32\t1700000000\t10\t20\toff\n") {
		agentPeer = shortPeerID(p.publicKey)
	}
	if agentPeer == "" {
		t.Fatal("parseWGDump found no peer in the sample dump")
	}
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() != "wgfleet_client_info" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "peer" && l.GetValue() != agentPeer {
					t.Errorf("client_info peer=%q, the agent labels the same peer %q — the join cannot match", l.GetValue(), agentPeer)
				}
			}
		}
	}
}

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
	onDevice := domain.WGClient{ID: "c1", Name: "alice", Address: "10.73.0.2/32", PublicKey: alicePub, PrivateKey: "x", Enabled: true, CreatedAt: at}
	if err := st.AddWGClientToDevice(ctx, "m1", onDevice, "d1"); err != nil {
		t.Fatal(err)
	}
	// A muted credential still owns its traffic history: it keeps its name.
	lone := domain.WGClient{ID: "c2", Name: "bob", Address: "10.73.0.3/32", PublicKey: bobPub, PrivateKey: "y", Enabled: false, CreatedAt: at}
	if err := st.AddWGClient(ctx, "m1", lone); err != nil {
		t.Fatal(err)
	}
	if err := st.AddVLESSClientToDevice(ctx, "m1", domain.VLESSClient{Name: "alice-v", UUID: aliceUUID, ShortID: "0badc0de"}, "d1", at); err != nil {
		t.Fatal(err)
	}
	if err := st.AddVLESSClient(ctx, "m1", domain.VLESSClient{Name: "carol-v", UUID: carolUUID, ShortID: "feedface"}); err != nil {
		t.Fatal(err)
	}

	want := `
# HELP wgfleet_client_info Client credential behind a per-client series key; value is always 1. kind=awg: peer is the WireGuard key in the agents' short form — join wgfleet_wg_peer_*{peer} on the master's wg0 and an exit's lifeline interface. kind=vless: peer is the VLESS stats id — join wgfleet_vless_user_*{user}.
# TYPE wgfleet_client_info gauge
wgfleet_client_info{client="alice",device="pixel",kind="awg",node="master-1",peer="` + shortPeerID(alicePub) + `"} 1
wgfleet_client_info{client="alice-v",device="pixel",kind="vless",node="master-1",peer="` + domain.VLESSStatsID(aliceUUID) + `"} 1
wgfleet_client_info{client="bob",device="",kind="awg",node="master-1",peer="` + shortPeerID(bobPub) + `"} 1
wgfleet_client_info{client="carol-v",device="",kind="vless",node="master-1",peer="` + domain.VLESSStatsID(carolUUID) + `"} 1
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
	// The VLESS UUID is a credential too (UUID + address = access).
	if err := st.AddVLESSClient(ctx, "m1", domain.VLESSClient{Name: "v", UUID: "SECRET-0000-4000-8000-000000000000", ShortID: "ab"}); err != nil {
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
					t.Fatalf("%s label %s carries a client secret (WG private key or VLESS UUID)", mf.GetName(), l.GetName())
				}
			}
		}
	}
}
