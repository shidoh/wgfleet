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

func TestRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte("1.2.3.0/24\n5.6.7.0/24\n"))
		case "/v6":
			_, _ = w.Write([]byte("2001:db8::/32\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	cache, n4, n6, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", srv.URL+"/v6", now)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n4 != 2 || n6 != 1 {
		t.Errorf("counts = v4:%d v6:%d, want v4:2 v6:1", n4, n6)
	}
	v4, v6, err := DecodeCache(strings.NewReader(string(cache)))
	if err != nil {
		t.Fatalf("DecodeCache: %v", err)
	}
	if len(v4) != 2 || len(v6) != 1 {
		t.Errorf("decoded v4=%v v6=%v", v4, v6)
	}
}

func TestRefreshFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v4" {
			_, _ = w.Write([]byte("1.2.3.0/24\n"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // v6 fails
	}))
	defer srv.Close()

	// v6 returns 500 -> the whole refresh fails (all-or-nothing), no cache returned.
	cache, _, _, err := Refresh(context.Background(), srv.Client(), srv.URL+"/v4", srv.URL+"/v6", time.Now())
	if err == nil {
		t.Fatal("expected error when a configured feed fails")
	}
	if cache != nil {
		t.Errorf("expected nil cache on failure, got %d bytes", len(cache))
	}
}

func TestRefreshSkipsEmptyURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.2.3.0/24\n"))
	}))
	defer srv.Close()

	// Empty v6 URL -> v6 family skipped, v4-only refresh still succeeds.
	cache, n4, n6, err := Refresh(context.Background(), srv.Client(), srv.URL, "", time.Now())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n4 != 1 || n6 != 0 {
		t.Errorf("counts = v4:%d v6:%d, want v4:1 v6:0", n4, n6)
	}
	if len(cache) == 0 {
		t.Error("expected non-empty cache")
	}
}
