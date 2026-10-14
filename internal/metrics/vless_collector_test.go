package metrics

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	statscmd "github.com/shidoh/wgfleet/internal/api/pb/third_party/xray/stats"
)

func vlessReg(t *testing.T, on bool, users []VLESSUserStats, err error) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	NewVLESSCollector(reg, "master-1", "master", func() bool { return on },
		func(context.Context) ([]VLESSUserStats, error) { return users, err })
	return reg
}

func TestVLESSCollectorPerUserTraffic(t *testing.T) {
	reg := vlessReg(t, true, []VLESSUserStats{
		{User: "a1b2c3d4e5f6", Uplink: 100, Downlink: 5000, OnlineIPs: 2, OnlineKnown: true},
		{User: "0f0f0f0f0f0f", Uplink: 0, Downlink: 0, OnlineIPs: 0, OnlineKnown: true},
	}, nil)
	want := `
# HELP wgfleet_vless_collector_up 1 when the master's client-facing xray answered its stats API on this scrape, 0 when it did not. Absent on a master without the VLESS inbound.
# TYPE wgfleet_vless_collector_up gauge
wgfleet_vless_collector_up{node="master-1",role="master"} 1
# HELP wgfleet_vless_user_online_ips Source IPs this VLESS client has open connections from right now; > 0 means online. An IP can be several people behind one NAT.
# TYPE wgfleet_vless_user_online_ips gauge
wgfleet_vless_user_online_ips{node="master-1",role="master",user="0f0f0f0f0f0f"} 0
wgfleet_vless_user_online_ips{node="master-1",role="master",user="a1b2c3d4e5f6"} 2
# HELP wgfleet_vless_user_rx_bytes Bytes received from a VLESS client (its upload), decrypted payload without REALITY/XHTTP overhead. Cumulative; resets when xray restarts, so read it with rate()/increase().
# TYPE wgfleet_vless_user_rx_bytes counter
wgfleet_vless_user_rx_bytes{node="master-1",role="master",user="0f0f0f0f0f0f"} 0
wgfleet_vless_user_rx_bytes{node="master-1",role="master",user="a1b2c3d4e5f6"} 100
# HELP wgfleet_vless_user_tx_bytes Bytes sent to a VLESS client (its download), decrypted payload without REALITY/XHTTP overhead. Cumulative; resets when xray restarts, so read it with rate()/increase().
# TYPE wgfleet_vless_user_tx_bytes counter
wgfleet_vless_user_tx_bytes{node="master-1",role="master",user="0f0f0f0f0f0f"} 0
wgfleet_vless_user_tx_bytes{node="master-1",role="master",user="a1b2c3d4e5f6"} 5000
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

// "Could not read" and "nobody connected" must not look alike.
func TestVLESSCollectorReadErrorIsUpZero(t *testing.T) {
	reg := vlessReg(t, true, nil, errors.New("connection refused"))
	want := `
# HELP wgfleet_vless_collector_up 1 when the master's client-facing xray answered its stats API on this scrape, 0 when it did not. Absent on a master without the VLESS inbound.
# TYPE wgfleet_vless_collector_up gauge
wgfleet_vless_collector_up{node="master-1",role="master"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

// A master that runs no VLESS inbound has nothing to report — not a broken
// collector.
func TestVLESSCollectorSilentWhenInboundIsOff(t *testing.T) {
	reg := vlessReg(t, false, nil, errors.New("connection refused"))
	if n, err := testutil.GatherAndCount(reg); err != nil || n != 0 {
		t.Errorf("inbound off: %d series (err %v), want none", n, err)
	}
}

// An xray older than GetUsersStats gives traffic but no online figure: the online
// series is left out rather than reported as 0, which would read as "offline".
func TestVLESSCollectorOmitsOnlineWhenUnknown(t *testing.T) {
	reg := vlessReg(t, true, []VLESSUserStats{{User: "a1b2c3d4e5f6", Uplink: 1, Downlink: 2}}, nil)
	n, err := testutil.GatherAndCount(reg, "wgfleet_vless_user_online_ips")
	if err != nil || n != 0 {
		t.Errorf("online unknown: %d online series (err %v), want none", n, err)
	}
}

func TestParseXrayUserStatName(t *testing.T) {
	for in, want := range map[string][2]string{
		"user>>>a1b2c3d4e5f6>>>traffic>>>uplink":   {"a1b2c3d4e5f6", "uplink"},
		"user>>>a1b2c3d4e5f6>>>traffic>>>downlink": {"a1b2c3d4e5f6", "downlink"},
		"inbound>>>api>>>traffic>>>uplink":         {"", ""},
		"user>>>x>>>online":                        {"", ""},
	} {
		u, dir := parseUserTrafficStat(in)
		if u != want[0] || dir != want[1] {
			t.Errorf("parseUserTrafficStat(%q) = %q,%q, want %q,%q", in, u, dir, want[0], want[1])
		}
	}
}

// fakeStats is xray's StatsService as far as the collector talks to it.
type fakeStats struct {
	statscmd.UnimplementedStatsServiceServer
	old bool // an xray build without GetUsersStats
}

// GetUsersStats as xray 26.6.22 really answers it: ONLY users online right now
// (seen on the stand — a user who disconnected vanished from it, traffic and all).
func (f fakeStats) GetUsersStats(context.Context, *statscmd.GetUsersStatsRequest) (*statscmd.GetUsersStatsResponse, error) {
	if f.old {
		return nil, status.Error(codes.Unimplemented, "unknown method GetUsersStats")
	}
	return &statscmd.GetUsersStatsResponse{Users: []*statscmd.UserStat{{
		Email: "a1b2c3d4e5f6",
		Ips:   []*statscmd.OnlineIPEntry{{Ip: "198.51.100.7", LastSeen: 1}},
	}}}, nil
}

func (f fakeStats) QueryStats(_ context.Context, r *statscmd.QueryStatsRequest) (*statscmd.QueryStatsResponse, error) {
	if r.GetReset_() {
		return nil, status.Error(codes.InvalidArgument, "the collector must never reset counters")
	}
	return &statscmd.QueryStatsResponse{Stat: []*statscmd.Stat{
		{Name: "user>>>a1b2c3d4e5f6>>>traffic>>>uplink", Value: 10},
		{Name: "user>>>a1b2c3d4e5f6>>>traffic>>>downlink", Value: 20},
		// gone offline: absent from GetUsersStats, still owns its traffic
		{Name: "user>>>0f0f0f0f0f0f>>>traffic>>>uplink", Value: 3},
		{Name: "user>>>0f0f0f0f0f0f>>>traffic>>>downlink", Value: 4},
		{Name: "inbound>>>api>>>traffic>>>uplink", Value: 999},
	}}, nil
}

func serveFakeStats(t *testing.T, f fakeStats) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	statscmd.RegisterStatsServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func TestXrayUserStatsOverGRPC(t *testing.T) {
	for name, tc := range map[string]struct {
		old        bool
		wantOnline bool
	}{
		"GetUsersStats":          {old: false, wantOnline: true},
		"QueryStats on old xray": {old: true, wantOnline: false},
	} {
		t.Run(name, func(t *testing.T) {
			addr := serveFakeStats(t, fakeStats{old: tc.old})
			got, err := xrayUserStats(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			by := map[string]VLESSUserStats{}
			for _, u := range got {
				by[u.User] = u
			}
			if len(got) != 2 {
				t.Fatalf("users = %+v, want both users — the offline one keeps its traffic — and no inbound counters", got)
			}
			on, off := by["a1b2c3d4e5f6"], by["0f0f0f0f0f0f"]
			if on.Uplink != 10 || on.Downlink != 20 || off.Uplink != 3 || off.Downlink != 4 {
				t.Errorf("traffic: online %+v, offline %+v", on, off)
			}
			if on.OnlineKnown != tc.wantOnline || off.OnlineKnown != tc.wantOnline {
				t.Errorf("online known = %v/%v, want %v", on.OnlineKnown, off.OnlineKnown, tc.wantOnline)
			}
			if tc.wantOnline && (on.OnlineIPs != 1 || off.OnlineIPs != 0) {
				t.Errorf("online ips = %d/%d, want 1/0", on.OnlineIPs, off.OnlineIPs)
			}
		})
	}
}

func TestXrayUserStatsUnreachableIsAnError(t *testing.T) {
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := lis.Addr().String()
	_ = lis.Close()
	if _, err := xrayUserStats(context.Background(), addr); err == nil {
		t.Error("no xray listening: want an error (collector_up 0), got none")
	}
}
