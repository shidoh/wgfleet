package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

type recorder struct {
	mu   sync.Mutex
	got  []domain.ProfileFetch
	fail error
}

func (r *recorder) RecordProfileFetch(_ context.Context, f domain.ProfileFetch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.got = append(r.got, f)
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// fetchPortal is testPortal with a recorder and a clock the test moves.
func fetchPortal(t *testing.T) (*Handler, *recorder, *time.Time) {
	t.Helper()
	h := testPortal(t)
	rec := &recorder{}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	h.opts.Fetches = rec
	h.opts.Now = func() time.Time { return now }
	return h, rec, &now
}

func fetchAs(t *testing.T, h http.Handler, path, ua string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "10.80.0.2:51820"
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestPortalRecordsTheProfileDownload(t *testing.T) {
	h, rec, now := fetchPortal(t)
	if code := fetchAs(t, h, "/c/"+devTok+"/mihomo", "clash-verge/v2.5.9\x00"); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	want := domain.ProfileFetch{DeviceID: "d0", Kind: domain.FetchProfile, At: *now, UserAgent: "clash-verge/v2.5.9"}
	if rec.count() != 1 || rec.got[0] != want {
		t.Errorf("recorded %+v, want [%+v]", rec.got, want)
	}
}

func TestPortalThrottlesRepeatDownloadsButNotANewClient(t *testing.T) {
	h, rec, now := fetchPortal(t)
	path := "/c/" + devTok + "/mihomo"
	fetchAs(t, h, path, "clash-verge/v2.5.9")
	*now = now.Add(time.Minute)
	fetchAs(t, h, path, "clash-verge/v2.5.9")
	if rec.count() != 1 {
		t.Fatalf("a repeat within %v was written: %+v", fetchRecordEvery, rec.got)
	}
	fetchAs(t, h, path, "clash-verge/v2.6.0")
	if rec.count() != 2 {
		t.Fatalf("a changed User-Agent was not written: %+v", rec.got)
	}
	*now = now.Add(fetchRecordEvery)
	fetchAs(t, h, path, "clash-verge/v2.6.0")
	if rec.count() != 3 {
		t.Fatalf("a download after %v was not written: %+v", fetchRecordEvery, rec.got)
	}
}

func TestPortalServesTheProfileWhenTheRecordFails(t *testing.T) {
	h, rec, _ := fetchPortal(t)
	rec.fail = errors.New("database is locked")
	path := "/c/" + devTok + "/mihomo"
	if code := fetchAs(t, h, path, "x/1"); code != http.StatusOK {
		t.Fatalf("status = %d, want the profile despite the failed record", code)
	}
	// The failed write is not remembered as done: the next download retries it.
	rec.fail = nil
	fetchAs(t, h, path, "x/1")
	if rec.count() != 1 {
		t.Errorf("after a failed write the next download was not recorded: %+v", rec.got)
	}
}

func TestPortalRecordsNothingForAFailedOrLegacyDownload(t *testing.T) {
	h, rec, _ := fetchPortal(t)
	fetchAs(t, h, "/c/deadbeefdeadbeefdeadbeefdeadbeef/mihomo", "x/1") // unknown token
	fetchAs(t, h, "/c/1111222233334444/mihomo", "x/1")                 // legacy link, paused
	fetchAs(t, h, "/c/"+devTok, "x/1")                                 // the page, not the profile
	if rec.count() != 0 {
		t.Errorf("recorded %+v, want nothing", rec.got)
	}
}
