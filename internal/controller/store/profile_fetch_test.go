package store

import (
	"context"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestRecordProfileFetchKeepsLatestPerDeviceAndKind(t *testing.T) {
	ctx := context.Background()
	s := devStore(t)
	mustDevice(t, s, "d1", "0123456789abcdef0123456789abcdef", "alice-phone")
	t1 := devT0.Add(time.Hour)

	for _, f := range []domain.ProfileFetch{
		{DeviceID: "d1", Kind: domain.FetchProfile, At: devT0, UserAgent: "clash-verge/v2.5.8"},
		{DeviceID: "d1", Kind: domain.FetchProfile, At: t1, UserAgent: "clash-verge/v2.5.9"},
		{DeviceID: "d1", Kind: domain.FetchProvider, At: devT0, UserAgent: "mihomo/1.19.33"},
	} {
		if err := s.RecordProfileFetch(ctx, f); err != nil {
			t.Fatalf("RecordProfileFetch(%+v): %v", f, err)
		}
	}

	got, err := s.ListProfileFetches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	byKind := map[domain.ProfileFetchKind]domain.ProfileFetch{}
	for _, f := range got {
		byKind[f.Kind] = f
	}
	if p := byKind[domain.FetchProfile]; !p.At.Equal(t1) || p.UserAgent != "clash-verge/v2.5.9" || p.DeviceID != "d1" {
		t.Errorf("profile row = %+v, want the later fetch", p)
	}
	if p := byKind[domain.FetchProvider]; !p.At.Equal(devT0) || p.UserAgent != "mihomo/1.19.33" {
		t.Errorf("provider row = %+v", p)
	}
}

func TestRecordProfileFetchIgnoresAnOlderWrite(t *testing.T) {
	ctx := context.Background()
	s := devStore(t)
	mustDevice(t, s, "d1", "0123456789abcdef0123456789abcdef", "alice-phone")
	newer := domain.ProfileFetch{DeviceID: "d1", Kind: domain.FetchProfile, At: devT0.Add(time.Hour), UserAgent: "new"}
	older := domain.ProfileFetch{DeviceID: "d1", Kind: domain.FetchProfile, At: devT0, UserAgent: "old"}
	for _, f := range []domain.ProfileFetch{newer, older} {
		if err := s.RecordProfileFetch(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListProfileFetches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].UserAgent != "new" {
		t.Errorf("rows = %+v, want only the newer fetch", got)
	}
}

func TestProfileFetchGoesWithItsDevice(t *testing.T) {
	ctx := context.Background()
	s := devStore(t)
	mustDevice(t, s, "d1", "0123456789abcdef0123456789abcdef", "alice-phone")
	if err := s.RecordProfileFetch(ctx, domain.ProfileFetch{DeviceID: "d1", Kind: domain.FetchProfile, At: devT0}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListProfileFetches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("rows after deleting the device = %+v, want none", got)
	}
}

func TestRecordProfileFetchRejectsIncompleteInput(t *testing.T) {
	ctx := context.Background()
	s := devStore(t)
	mustDevice(t, s, "d1", "0123456789abcdef0123456789abcdef", "alice-phone")
	for name, f := range map[string]domain.ProfileFetch{
		"no device": {Kind: domain.FetchProfile, At: devT0},
		"no time":   {DeviceID: "d1", Kind: domain.FetchProfile},
		"bad kind":  {DeviceID: "d1", Kind: "zip", At: devT0},
		"unknown":   {DeviceID: "nope", Kind: domain.FetchProfile, At: devT0},
	} {
		if err := s.RecordProfileFetch(ctx, f); err == nil {
			t.Errorf("%s: RecordProfileFetch accepted %+v", name, f)
		}
	}
}
