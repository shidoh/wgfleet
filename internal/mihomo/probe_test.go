package mihomo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// clashStub serves the Clash API's per-proxy delay endpoint. reach decides, per
// target URL, whether mihomo "reached" it.
func clashStub(t *testing.T, reach func(target string) bool) (addr string, calls *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/proxies/") || !strings.HasSuffix(r.URL.Path, "/delay") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if reach(r.URL.Query().Get("url")) {
			fmt.Fprint(w, `{"delay":123}`)
			return
		}
		// mihomo answers a failed dial with a non-2xx, not a transport error.
		http.Error(w, `{"message":"timeout"}`, http.StatusRequestTimeout)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), &n
}

func TestProbeMemberCountsReachableDestinations(t *testing.T) {
	addr, _ := clashStub(t, func(string) bool { return true })
	ok, total, err := ProbeMember(context.Background(), addr, "", "vn1", []string{"http://a", "http://b"})
	if err != nil {
		t.Fatal(err)
	}
	if ok != 2 || total != 2 {
		t.Fatalf("ok=%d total=%d, want 2/2", ok, total)
	}
}

// The destination-scoped block signature: exactly one destination answers, the rest time out.
func TestProbeMemberReportsPartialReachability(t *testing.T) {
	addr, _ := clashStub(t, func(target string) bool { return target == "http://good" })
	ok, total, err := ProbeMember(context.Background(), addr, "", "pn8",
		[]string{"http://good", "http://blocked1", "http://blocked2", "http://blocked3"})
	if err != nil {
		t.Fatal(err)
	}
	if ok != 1 {
		t.Fatalf("reachable = %d, want 1 — a censored exit must not look healthy", ok)
	}
	if total != 4 {
		t.Fatalf("probed = %d, want 4", total)
	}
}

// Once the usable threshold is met the verdict cannot change, so the remaining
// probes must not be waited on — that bound is what keeps a reconcile pass inside
// its interval when destinations are timing out.
// Every delay test that was STARTED must be waited on.
//
// mihomo writes the proxy's alive flag from the result of every URLTest
// (adapter.Proxy.URLTest stores `alive = err == nil` in a defer, unconditionally),
// and a request the client cancels cancels the dial on mihomo's side too — so an
// abandoned probe stamps alive=false on the very proxy this call is about to
// report healthy. In a load-balance group that takes the exit out of rotation
// until the group's own 30s check puts it back, and consistent-hashing then moves
// live destinations to a different exit with a different egress IP.
//
// The early exit it replaces bought almost nothing: the probes run CONCURRENTLY,
// so waiting for all of them is still bounded by one timeout, and on a healthy
// tier they all answer in about the same 100ms.
func TestProbeMemberWaitsForEveryTestItStarted(t *testing.T) {
	addr, calls := clashStub(t, func(string) bool { return true })
	urls := []string{"http://a", "http://b", "http://c", "http://d"}

	ok, total, err := ProbeMember(context.Background(), addr, "", "vn1", urls)
	if err != nil {
		t.Fatal(err)
	}
	if total != len(urls) {
		t.Errorf("total = %d, want every one of the %d tests counted", total, len(urls))
	}
	if ok != len(urls) {
		t.Errorf("ok = %d, want %d — a result was abandoned rather than read", ok, len(urls))
	}
	if got := calls.Load(); got != int32(len(urls)) {
		t.Fatalf("issued %d calls for %d urls", got, len(urls))
	}
}

// The verdict itself is unchanged: enough reachable destinations still means
// usable, it is just decided after every answer is in.
func TestProbeMemberStillReportsUsableOnAPartialSet(t *testing.T) {
	addr, _ := clashStub(t, func(u string) bool { return u == "http://a" || u == "http://b" })
	ok, total, err := ProbeMember(context.Background(), addr, "", "vn1",
		[]string{"http://a", "http://b", "http://c", "http://d"})
	if err != nil {
		t.Fatal(err)
	}
	if ok < enough {
		t.Fatalf("ok = %d, want at least %d", ok, enough)
	}
	if total != 4 {
		t.Errorf("total = %d, want all four attempted", total)
	}
}

// A dead API is not the same as a dead exit: the caller must be able to tell them
// apart, so it can hold its current tier instead of failing over on no evidence.
func TestProbeMemberReportsUnreachableAPI(t *testing.T) {
	_, _, err := ProbeMember(context.Background(), "127.0.0.1:1", "", "vn1", []string{"http://a"})
	if err == nil {
		t.Fatal("expected an error when the Clash API is unreachable")
	}
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error must be classifiable as unreachable, got %v", err)
	}
}

func TestProbeMemberRequiresControllerAddr(t *testing.T) {
	if _, _, err := ProbeMember(context.Background(), "", "", "vn1", nil); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("empty controller address must report unreachable, got %v", err)
	}
}
