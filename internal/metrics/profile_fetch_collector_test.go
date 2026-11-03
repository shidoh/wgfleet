package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func TestProfileFetchCollectorReportsAgeAndSoftware(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, d := range []domain.ClientDevice{
		{ID: "d1", Token: "0123456789abcdef0123456789abcdef", Name: "alice-laptop", CreatedAt: t0},
		{ID: "d2", Token: "fedcba9876543210fedcba9876543210", Name: "bob-phone", CreatedAt: t0},
	} {
		if err := st.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordProfileFetch(ctx, domain.ProfileFetch{DeviceID: "d1", Kind: domain.FetchProvider,
		At: t0, UserAgent: "clash.meta/v1.19.33"}); err != nil {
		t.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	c := NewProfileFetchCollector(reg, st)
	c.now = func() time.Time { return t0.Add(90 * time.Second) }

	want := `
# HELP wgfleet_client_profile_fetch_age_seconds Seconds since the device last downloaded this kind from the portal (absent if never).
# TYPE wgfleet_client_profile_fetch_age_seconds gauge
wgfleet_client_profile_fetch_age_seconds{device="alice-laptop",kind="provider"} 90
# HELP wgfleet_client_profile_fetch_info Software behind the device's latest download, read from its User-Agent; value is always 1.
# TYPE wgfleet_client_profile_fetch_info gauge
wgfleet_client_profile_fetch_info{app="",app_version="",core_version="1.19.33",device="alice-laptop",kind="provider"} 1
`
	// bob-phone never fetched: absent, not zero — zero would read as "just now".
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}
