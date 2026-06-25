package metrics

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// realistic `nft -j list table inet wgfleet` fixtures.
const (
	// v4 blacklist with 3 interval elements, v6 with 1, plus a named drop counter.
	nftFull = `{"nftables":[
		{"metainfo":{"version":"1.0.2","release_name":"Lester Gooch","json_schema_version":1}},
		{"table":{"family":"inet","name":"wgfleet","handle":1}},
		{"set":{"family":"inet","name":"as_blacklist","table":"wgfleet","type":"ipv4_addr","handle":2,"flags":["interval"],"elem":[
			{"prefix":{"addr":"45.155.205.0","len":24}},
			{"prefix":{"addr":"193.32.162.0","len":24}},
			"8.8.8.8"
		]}},
		{"set":{"family":"inet","name":"as_blacklist_v6","table":"wgfleet","type":"ipv6_addr","handle":3,"flags":["interval"],"elem":[
			{"prefix":{"addr":"2001:db8::","len":32}}
		]}},
		{"counter":{"family":"inet","name":"scan_drops","table":"wgfleet","handle":4,"packets":42,"bytes":2520}},
		{"chain":{"family":"inet","table":"wgfleet","name":"input","handle":5}}
	]}`

	// table present but the AS-blacklist feature is off: no sets, no counters.
	nftEmpty = `{"nftables":[
		{"table":{"family":"inet","name":"wgfleet","handle":1}},
		{"chain":{"family":"inet","table":"wgfleet","name":"input","handle":2}}
	]}`

	// v4 set present but with no elements (fail-open empty set).
	nftEmptySet = `{"nftables":[
		{"set":{"family":"inet","name":"as_blacklist","table":"wgfleet","type":"ipv4_addr","handle":2,"flags":["interval"]}}
	]}`
)

func TestParseNFTTable(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		wantV4      int
		wantV4Found bool
		wantV6      int
		wantV6Found bool
		wantCounter map[string]float64
	}{
		{
			name:   "full table",
			input:  nftFull,
			wantV4: 3, wantV4Found: true,
			wantV6: 1, wantV6Found: true,
			wantCounter: map[string]float64{"scan_drops": 42},
		},
		{
			name:        "empty table no sets",
			input:       nftEmpty,
			wantV4Found: false,
			wantV6Found: false,
			wantCounter: map[string]float64{},
		},
		{
			name:   "set present but empty",
			input:  nftEmptySet,
			wantV4: 0, wantV4Found: true,
			wantV6Found: false,
			wantCounter: map[string]float64{},
		},
		{
			name:    "malformed json",
			input:   `{not json`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats, err := parseNFTTable([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			v4, okV4 := stats.blacklistSize["v4"]
			if okV4 != tt.wantV4Found {
				t.Errorf("v4 found = %v, want %v", okV4, tt.wantV4Found)
			}
			if tt.wantV4Found && v4 != tt.wantV4 {
				t.Errorf("v4 size = %d, want %d", v4, tt.wantV4)
			}
			v6, okV6 := stats.blacklistSize["v6"]
			if okV6 != tt.wantV6Found {
				t.Errorf("v6 found = %v, want %v", okV6, tt.wantV6Found)
			}
			if tt.wantV6Found && v6 != tt.wantV6 {
				t.Errorf("v6 size = %d, want %d", v6, tt.wantV6)
			}
			for name, want := range tt.wantCounter {
				if got := stats.counters[name]; got != want {
					t.Errorf("counter %q = %v, want %v", name, got, want)
				}
			}
			if len(stats.counters) != len(tt.wantCounter) {
				t.Errorf("counters = %v, want %v", stats.counters, tt.wantCounter)
			}
		})
	}
}

func TestFWCollectorSeries(t *testing.T) {
	list := func(context.Context) ([]byte, error) { return []byte(nftFull), nil }
	reg := prometheus.NewRegistry()
	NewFWCollector(reg, "exit-de-1", "exit", list)

	wantBL := `
# HELP wgfleet_fw_as_blacklist_size Number of elements in the nftables AS-blacklist set, by address family.
# TYPE wgfleet_fw_as_blacklist_size gauge
wgfleet_fw_as_blacklist_size{family="v4",node="exit-de-1",role="exit"} 3
wgfleet_fw_as_blacklist_size{family="v6",node="exit-de-1",role="exit"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantBL), "wgfleet_fw_as_blacklist_size"); err != nil {
		t.Error(err)
	}

	wantDrops := `
# HELP wgfleet_fw_drops_total Packets dropped by a named nftables drop counter in table inet wgfleet.
# TYPE wgfleet_fw_drops_total counter
wgfleet_fw_drops_total{counter="scan_drops",node="exit-de-1",role="exit"} 42
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantDrops), "wgfleet_fw_drops_total"); err != nil {
		t.Error(err)
	}
}

func TestFWCollectorFailsSoft(t *testing.T) {
	list := func(context.Context) ([]byte, error) { return nil, errNoIface } // nft missing / table absent
	reg := prometheus.NewRegistry()
	NewFWCollector(reg, "master-xa-1", "master", list)

	// No table → no firewall series at all (not a scrape failure).
	if n := testutil.CollectAndCount(reg, "wgfleet_fw_as_blacklist_size", "wgfleet_fw_drops_total"); n != 0 {
		t.Errorf("want 0 firewall series on unreadable table, got %d", n)
	}
}
