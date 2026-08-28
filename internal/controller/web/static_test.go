package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An embed.FS reports a zero modification time, so the plain FileServer emitted no
// Last-Modified and no ETag: the browser had no way to revalidate and re-fetched
// every asset in full on every navigation — about 122 KB of 200s per page, a third
// of it CSS comments.
func TestStaticAssetsRevalidateAndCompress(t *testing.T) {
	h := newStaticAssets(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag: the browser has nothing to revalidate against")
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("Cache-Control = %q, want a max-age with revalidation", cc)
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no nosniff on the one class of file where sniffing matters most")
	}

	// A second visit costs a 304 and no body.
	req2 := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Result().StatusCode != http.StatusNotModified {
		t.Errorf("revalidation status = %d, want 304", rec2.Result().StatusCode)
	}
	if body, _ := io.ReadAll(rec2.Result().Body); len(body) != 0 {
		t.Errorf("304 carried %d bytes of body", len(body))
	}

	// And a first visit is compressed when the browser says it can take it.
	req3 := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	req3.Header.Set("Accept-Encoding", "gzip")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	res3 := rec3.Result()
	if res3.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", res3.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(res3.Body)
	if err != nil {
		t.Fatalf("the body is not gzip: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(raw) {
		t.Error("the decompressed body does not match the file")
	}
	compressed := rec3.Body.Len()
	if compressed >= len(raw)/2 {
		t.Errorf("compressed to %d of %d bytes; gzip should do far better on CSS", compressed, len(raw))
	}
	t.Logf("app.css: %d bytes plain, %d gzipped", len(raw), compressed)
}
