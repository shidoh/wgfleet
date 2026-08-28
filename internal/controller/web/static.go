package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"
)

// staticAssets serves the embedded CSS/JS/fonts with a validator and compression.
//
// The obvious `http.FileServer(http.FS(embedded))` cannot do either. An embed.FS
// reports a ZERO modification time, so net/http emits no Last-Modified and,
// having no ETag either, no way for a browser to revalidate — every navigation
// re-fetched app.css, htmx.min.js and app.js in full: about 122 KB of 200s, of
// which 28.8 KB was CSS comments. Over a management overlay, on a link that is
// sometimes a phone tethered in a hurry, that is the whole page budget spent on
// bytes the browser already had.
//
// Every representation is built once at startup — the corpus is a handful of files
// that change only when the binary does — and each gets its OWN content hash. That
// is not a detail. The first version hashed the file and served that one tag for
// both the identity and the gzip body, which is a cache-poisoning bug with a very
// plain failure: a client holding the compressed bytes revalidates without offering
// gzip, is told 304, and renders gzip as text/css. `Vary: Accept-Encoding` now goes
// on EVERY response, including the 304 — it was previously set on the gzip branch
// only, i.e. never on the response that needed it.
//
// Fonts are not compressed. woff2 is Brotli-compressed already; gzipping it made
// each file 25 bytes LARGER while dropping Content-Length and Accept-Ranges.
//
// Serving is http.ServeContent over a byte slice, so HEAD, Range and If-None-Match
// are the standard library's rather than hand-rolled. Anything not in the map is a
// 404: there is no directory listing (the old FileServer published one for /static/
// and answered /static/fonts with an empty gzip stream instead of a redirect).
type staticAssets struct {
	fs   fs.FS
	once sync.Once
	reps map[string]representation
}

// representation is one file in both the encodings this handler will serve.
type representation struct {
	contentType string
	identity    []byte
	identityTag string
	gzipped     []byte // nil when compressing this type is not worth it
	gzipTag     string
}

func newStaticAssets(f fs.FS) *staticAssets { return &staticAssets{fs: f} }

func (s *staticAssets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.once.Do(s.build)
	name := strings.TrimPrefix(r.URL.Path, "/")
	rep, ok := s.reps[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Vary first, and unconditionally: it describes how the response was selected,
	// so it has to be on the 304 as well as the 200.
	w.Header().Set("Vary", "Accept-Encoding")
	// Content sniffing matters most on exactly these files, and nothing else sets it.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Long max-age is safe BECAUSE the tag is a content hash: a changed file gets
	// a new tag, and until then a revalidation is a 304 with no body.
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	w.Header().Set("Content-Type", rep.contentType)

	body, tag := rep.identity, rep.identityTag
	if rep.gzipped != nil && acceptsGzip(r.Header.Get("Accept-Encoding")) {
		body, tag = rep.gzipped, rep.gzipTag
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("ETag", tag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

// acceptsGzip reports whether the client offered gzip. Deliberately literal: the
// header is a q-value list, and the only case worth honouring beyond "the token is
// present" is an explicit refusal, which is what `gzip;q=0` means.
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if strings.TrimSpace(fields[0]) != "gzip" {
			continue
		}
		for _, p := range fields[1:] {
			if strings.ReplaceAll(strings.TrimSpace(p), " ", "") == "q=0" {
				return false
			}
		}
		return true
	}
	return false
}

func (s *staticAssets) build() {
	s.reps = map[string]representation{}
	_ = fs.WalkDir(s.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		raw, rerr := fs.ReadFile(s.fs, path)
		if rerr != nil {
			return nil
		}
		rep := representation{
			contentType: contentTypeFor(path),
			identity:    raw,
			identityTag: etagOf(raw, "identity"),
		}
		if compressible(path) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			if _, werr := gz.Write(raw); werr == nil && gz.Close() == nil {
				rep.gzipped = buf.Bytes()
				rep.gzipTag = etagOf(rep.gzipped, "gzip")
			}
		}
		s.reps[path] = rep
		return nil
	})
}

// etagOf hashes the bytes that will actually be sent, with the encoding folded in
// so the two representations of one file can never share a validator.
func etagOf(body []byte, encoding string) string {
	h := sha256.New()
	h.Write([]byte(encoding))
	h.Write([]byte{0})
	h.Write(body)
	return `"` + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16]) + `"`
}

// compressible is a small allow-list rather than "everything but fonts": a new file
// type should have to be looked at before it is compressed, not after.
func compressible(name string) bool {
	return strings.HasSuffix(name, ".css") ||
		strings.HasSuffix(name, ".js") ||
		strings.HasSuffix(name, ".svg")
}

// contentTypeFor covers the types this directory holds.
func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}
