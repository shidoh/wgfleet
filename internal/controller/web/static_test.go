package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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

// One ETag for two different bodies is a cache-poisoning bug, not an inefficiency.
// The first version hashed the FILE, so the identity and gzip responses shared a
// validator: a client holding the compressed bytes revalidates without offering
// gzip, is told 304, and renders gzip as text/css — an unstyled console with
// nothing in the log to explain it.
func TestStaticAssetsGiveEachEncodingItsOwnValidator(t *testing.T) {
	h := newStaticAssets(staticFS)

	get := func(ae, inm string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		if inm != "" {
			req.Header.Set("If-None-Match", inm)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result()
	}

	plain, gz := get("", ""), get("gzip", "")
	plainTag, gzTag := plain.Header.Get("ETag"), gz.Header.Get("ETag")
	if plainTag == gzTag {
		t.Fatalf("both encodings answer with ETag %s; a cache cannot tell the bodies apart", plainTag)
	}
	// Vary belongs on every response, the 304 included — it is what tells a shared
	// cache that the encoding took part in choosing this body.
	for name, res := range map[string]*http.Response{"identity": plain, "gzip": gz} {
		if res.Header.Get("Vary") != "Accept-Encoding" {
			t.Errorf("%s response has Vary = %q", name, res.Header.Get("Vary"))
		}
	}

	// The gzip tag must NOT satisfy a revalidation that cannot accept gzip.
	if res := get("", gzTag); res.StatusCode == http.StatusNotModified {
		t.Error("a gzip validator revalidated an identity request: the client would render gzip as CSS")
	}
	if res := get("gzip", gzTag); res.StatusCode != http.StatusNotModified {
		t.Errorf("the gzip validator did not revalidate its own encoding: %d", res.StatusCode)
	}
	if res := get("gzip", gzTag); res.Header.Get("Vary") != "Accept-Encoding" {
		t.Error("the 304 dropped Vary, which is the response that most needs it")
	}
}

// woff2 is Brotli-compressed already: gzipping it made every font 25 bytes LARGER
// and cost a full compression pass per request, while dropping the Content-Length
// and Accept-Ranges the plain body carries.
func TestStaticAssetsDoNotRecompressFonts(t *testing.T) {
	h := newStaticAssets(staticFS)
	req := httptest.NewRequest(http.MethodGet, "/static/fonts/jetbrains-mono-400.woff2", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if enc := res.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q on an already-compressed font", enc)
	}
	if res.Header.Get("Content-Length") == "" {
		t.Error("no Content-Length: the font is streamed for no reason")
	}
	if ct := res.Header.Get("Content-Type"); ct != "font/woff2" {
		t.Errorf("Content-Type = %q", ct)
	}
}

// A directory is not an asset. The gzip branch used to open one successfully and
// copy nothing out of it, answering /static/fonts with a 200, an
// application/octet-stream type and a 20-byte empty gzip stream — where the plain
// FileServer would at least have redirected to the trailing slash. And /static/
// itself published an index of everything embedded.
func TestStaticAssetsServeNoDirectories(t *testing.T) {
	h := newStaticAssets(staticFS)
	for _, path := range []string{"/static", "/static/", "/static/fonts", "/static/fonts/", "/static/nope.css"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		h.ServeHTTP(rec, req)
		if rec.Result().StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Result().StatusCode)
		}
	}
}

// A client that explicitly refuses gzip must get the plain body.
func TestStaticAssetsHonourAnExplicitGzipRefusal(t *testing.T) {
	if acceptsGzip("gzip;q=0") {
		t.Error("gzip;q=0 was read as an offer")
	}
	if acceptsGzip("gzip; q=0, deflate") {
		t.Error("gzip; q=0 was read as an offer")
	}
	if !acceptsGzip("deflate, gzip;q=1.0, *;q=0.5") {
		t.Error("a normal browser Accept-Encoding was read as a refusal")
	}
	if acceptsGzip("") || acceptsGzip("identity") || acceptsGzip("br") {
		t.Error("gzip was inferred from a header that never mentions it")
	}
}

// A page must name its stylesheet by content, not by path alone: the files are
// cached for an hour, and an upgrade that changes the markup would otherwise be
// drawn with the previous release's CSS until that hour runs out.
func TestPagesReferenceAssetsByContentHash(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	_, body := get(t, h, "/")
	m := regexp.MustCompile(`href="(/static/app\.css\?v=[A-Za-z0-9_-]{12})"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("fleet page links app.css without a content hash:\n%s", body)
	}
	if res, _ := get(t, h, m[1]); res.StatusCode != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", m[1], res.StatusCode)
	}
}
