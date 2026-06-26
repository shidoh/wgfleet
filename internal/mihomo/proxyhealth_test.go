package mihomo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseProxyHealth(t *testing.T) {
	js := []byte(`{"proxies":{
	  "exit-de-1":{"alive":true,"history":[{"time":"2026-06-26T10:00:00Z","delay":42}]},
	  "exit-nl-1":{"alive":false,"history":[{"time":"2026-06-26T10:00:01Z","delay":0}]},
	  "wg-best":{"now":"exit-de-1","all":["exit-de-1","exit-nl-1"]}
	}}`)

	got, err := ParseProxyHealth(js, "wg-best", []string{"exit-de-1", "exit-nl-1", "exit-gone"})
	if err != nil {
		t.Fatalf("ParseProxyHealth: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	de := got[0]
	if de.Name != "exit-de-1" || !de.Alive || de.Delay != 42*time.Millisecond || !de.Selected {
		t.Fatalf("exit-de-1 mismatch: %+v", de)
	}
	if de.LastTest.IsZero() {
		t.Fatalf("exit-de-1 LastTest should be set")
	}
	if nl := got[1]; nl.Alive || nl.Selected {
		t.Fatalf("exit-nl-1 should be down and not selected: %+v", nl)
	}
	if gone := got[2]; gone.Alive || !gone.LastTest.IsZero() {
		t.Fatalf("absent proxy must be down with no test time: %+v", gone)
	}
}

func TestParseProxyHealthGarbage(t *testing.T) {
	if _, err := ParseProxyHealth([]byte("not json"), "wg-best", []string{"x"}); err == nil {
		t.Fatal("expected error on unparseable JSON")
	}
}

func TestFetchProxies(t *testing.T) {
	const body = `{"proxies":{"wg-best":{"now":"exit-de-1"}}}`
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/proxies" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	got, err := FetchProxies(context.Background(), addr, "s3cret")
	if err != nil {
		t.Fatalf("FetchProxies: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch: %s", got)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("auth header = %q", gotAuth)
	}
}

func TestFetchProxiesNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := FetchProxies(context.Background(), strings.TrimPrefix(srv.URL, "http://"), ""); err == nil {
		t.Fatal("expected error on non-2xx")
	}
}
