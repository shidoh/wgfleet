package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/asnfeed"
)

func TestFeedCollectorReportsEachSource(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "as-blacklist.lst")
	data := asnfeed.EncodeCacheWithSources([]string{"10.0.0.0/24"}, []string{"2001:db8::/32"}, []asnfeed.SourceCount{
		{URL: "https://c24be/v4", V4: 917, V4Addresses: 230467},
		{URL: "https://sngvy/list", V4: 1799, V6: 268, V4Addresses: 32795},
	}, time.Unix(0, 0))
	if err := os.WriteFile(cache, data, 0o644); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	NewFeedCollector(reg, "master-xa-1", "master", cache)

	want := `
# HELP wgfleet_fw_as_blacklist_source_ipv4_addresses IPv4 addresses one scanner-feed source covers in the last good list, overlaps counted once.
# TYPE wgfleet_fw_as_blacklist_source_ipv4_addresses gauge
wgfleet_fw_as_blacklist_source_ipv4_addresses{node="master-xa-1",role="master",source="https://c24be/v4"} 230467
wgfleet_fw_as_blacklist_source_ipv4_addresses{node="master-xa-1",role="master",source="https://sngvy/list"} 32795
# HELP wgfleet_fw_as_blacklist_source_prefixes Prefixes one scanner-feed source contributed to the last good list, by address family.
# TYPE wgfleet_fw_as_blacklist_source_prefixes gauge
wgfleet_fw_as_blacklist_source_prefixes{family="v4",node="master-xa-1",role="master",source="https://c24be/v4"} 917
wgfleet_fw_as_blacklist_source_prefixes{family="v4",node="master-xa-1",role="master",source="https://sngvy/list"} 1799
wgfleet_fw_as_blacklist_source_prefixes{family="v6",node="master-xa-1",role="master",source="https://c24be/v4"} 0
wgfleet_fw_as_blacklist_source_prefixes{family="v6",node="master-xa-1",role="master",source="https://sngvy/list"} 268
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"wgfleet_fw_as_blacklist_source_prefixes", "wgfleet_fw_as_blacklist_source_ipv4_addresses"); err != nil {
		t.Fatal(err)
	}
}

func TestFeedCollectorIsSilentWithoutACache(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewFeedCollector(reg, "exit-1", "exit", filepath.Join(t.TempDir(), "absent"))
	if n, err := testutil.GatherAndCount(reg); err != nil || n != 0 {
		t.Fatalf("got %d series (err %v), want none", n, err)
	}
}
