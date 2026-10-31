package asnfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	feed := strings.Join([]string{
		"# comment line",
		"",
		"1.2.3.0/24",
		"1.2.3.0/24",        // duplicate
		"5.6.7.8",           // bare IPv4 -> /32
		"1.2.3.4/24",        // unmasked, canonicalizes to 1.2.3.0/24 (dup)
		"2001:db8::/32",     // IPv6 CIDR
		"2001:db8::1",       // bare IPv6 -> /128
		"10.0.0.0/8 # tail", // inline comment stripped
		"not-an-ip",         // skipped
		"999.999.0.0/16",    // skipped
		"1.2.3.4; nft junk", // injection attempt -> skipped
	}, "\n")

	v4, v6, skipped, err := Parse(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantV4 := []string{"1.2.3.0/24", "10.0.0.0/8", "5.6.7.8/32"}
	if got := strings.Join(v4, ","); got != strings.Join(wantV4, ",") {
		t.Errorf("v4 = %v, want %v", v4, wantV4)
	}
	wantV6 := []string{"2001:db8::/32", "2001:db8::1/128"}
	if got := strings.Join(v6, ","); got != strings.Join(wantV6, ",") {
		t.Errorf("v6 = %v, want %v", v6, wantV6)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}
}

func TestParseEmpty(t *testing.T) {
	v4, v6, skipped, err := Parse(strings.NewReader("# only comments\n\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(v4) != 0 || len(v6) != 0 || skipped != 0 {
		t.Errorf("expected all empty, got v4=%v v6=%v skipped=%d", v4, v6, skipped)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	v4 := []string{"1.2.3.0/24", "10.0.0.0/8"}
	v6 := []string{"2001:db8::/32"}
	when := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	cache := EncodeCache(v4, v6, when)
	if !strings.Contains(string(cache), "# updated: 2026-06-22T12:00:00Z") {
		t.Errorf("cache missing updated header:\n%s", cache)
	}
	gotV4, gotV6, err := DecodeCache(strings.NewReader(string(cache)))
	if err != nil {
		t.Fatalf("DecodeCache: %v", err)
	}
	if strings.Join(gotV4, ",") != strings.Join(v4, ",") {
		t.Errorf("v4 round-trip = %v, want %v", gotV4, v4)
	}
	if strings.Join(gotV6, ",") != strings.Join(v6, ",") {
		t.Errorf("v6 round-trip = %v, want %v", gotV6, v6)
	}
}

// feedServer serves fixed bodies by path; any other path is a 404.
func feedServer(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func decode(t *testing.T, cache []byte) (v4, v6 []string) {
	t.Helper()
	v4, v6, err := DecodeCache(strings.NewReader(string(cache)))
	if err != nil {
		t.Fatalf("DecodeCache: %v", err)
	}
	return v4, v6
}

func TestRefreshTakesOneFamilyFromEachPairURL(t *testing.T) {
	// A stray v6 line in the v4 feed and v4 in the v6 feed are left out, as before.
	srv := feedServer(t, map[string]string{
		"/v4": "1.2.3.0/24\n5.6.7.0/24\n2001:db8:ffff::/48\n",
		"/v6": "2001:db8::/32\n9.9.9.9\n",
	})
	cache, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", srv.URL+"/v6", nil, time.Now())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	v4, v6 := decode(t, cache)
	if strings.Join(v4, ",") != "1.2.3.0/24,5.6.7.0/24" || strings.Join(v6, ",") != "2001:db8::/32" {
		t.Errorf("decoded v4=%v v6=%v", v4, v6)
	}
}

func TestRefreshMergesAnExtraSourceOfBothFamilies(t *testing.T) {
	srv := feedServer(t, map[string]string{
		"/v4":    "1.2.3.0/24\n",
		"/v6":    "2001:db8::/32\n",
		"/extra": "# ГРЧЦ\n1.2.3.0/24\n198.51.100.7\n2001:db8:1::/48\n",
	})
	cache, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", srv.URL+"/v6", []string{srv.URL + "/extra"}, time.Now())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	v4, v6 := decode(t, cache)
	if strings.Join(v4, ",") != "1.2.3.0/24,198.51.100.7/32" {
		t.Errorf("v4 = %v, want the pair's prefix and the extra's address, the shared one once", v4)
	}
	if strings.Join(v6, ",") != "2001:db8:1::/48,2001:db8::/32" {
		t.Errorf("v6 = %v", v6)
	}
}

func TestRefreshRecordsWhatEachSourceGave(t *testing.T) {
	srv := feedServer(t, map[string]string{
		"/v4":    "10.0.0.0/24\n10.0.0.0/25\n",
		"/v6":    "2001:db8::/32\n",
		"/extra": "198.51.100.7\n2001:db8:1::/48\n",
	})
	cache, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", srv.URL+"/v6", []string{srv.URL + "/extra"}, time.Now())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got, err := DecodeSources(strings.NewReader(string(cache)))
	if err != nil {
		t.Fatal(err)
	}
	want := []SourceCount{
		{URL: srv.URL + "/v4", V4: 2, V4Addresses: 256}, // the /25 inside the /24 counted once
		{URL: srv.URL + "/v6", V6: 1},
		{URL: srv.URL + "/extra", V4: 1, V6: 1, V4Addresses: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("sources = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("source %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// All-or-nothing: one failing source keeps the whole last good list, so a gist
// that is down never shrinks the list to C24Be alone.
func TestRefreshFailsWhenAnySourceFails(t *testing.T) {
	srv := feedServer(t, map[string]string{"/v4": "1.2.3.0/24\n", "/v6": "2001:db8::/32\n"})
	for name, extra := range map[string][]string{
		"missing extra":  {srv.URL + "/gone"},
		"missing v6 url": nil,
	} {
		t.Run(name, func(t *testing.T) {
			v6 := srv.URL + "/v6"
			if extra == nil {
				v6 = srv.URL + "/gone"
			}
			cache, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", v6, extra, time.Now())
			if err == nil || cache != nil {
				t.Fatalf("want an error and no cache, got err=%v cache=%d bytes", err, len(cache))
			}
		})
	}
}

func TestRefreshRejectsASourceThatParsesToNothing(t *testing.T) {
	srv := feedServer(t, map[string]string{"/v4": "1.2.3.0/24\n", "/extra": "<html>rate limited</html>\n"})
	if _, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", "", []string{srv.URL + "/extra"}, time.Now()); err == nil {
		t.Fatal("an error page from a source must fail the refresh")
	}
}

func TestRefreshSkipsEmptyURLs(t *testing.T) {
	srv := feedServer(t, map[string]string{"/v4": "1.2.3.0/24\n"})
	cache, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", "", []string{"", "  "}, time.Now())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if v4, _ := decode(t, cache); len(v4) != 1 {
		t.Errorf("v4 = %v", v4)
	}
}

func TestV4AddressCountMergesOverlaps(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want uint64
	}{
		{nil, 0},
		{[]string{"10.0.0.0/24"}, 256},
		{[]string{"10.0.0.0/24", "10.0.0.128/25"}, 256},
		{[]string{"10.0.0.0/25", "10.0.0.128/25"}, 256},
		{[]string{"10.0.0.0/24", "10.0.2.0/24"}, 512},
		{[]string{"0.0.0.0/0"}, 1 << 32},
		{[]string{"2001:db8::/32", "bogus", "1.1.1.1/32"}, 1},
	} {
		if got := V4AddressCount(tc.in); got != tc.want {
			t.Errorf("V4AddressCount(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
