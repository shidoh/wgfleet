package web

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
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
// The ETag is the content hash, computed once at startup: these files change only
// when the binary does, so a strong validator is both correct and free. Compression
// is done per-response rather than precomputed because the corpus is three files.
type staticAssets struct {
	fs    fs.FS
	once  sync.Once
	etags map[string]string
}

func newStaticAssets(f fs.FS) *staticAssets { return &staticAssets{fs: f} }

func (s *staticAssets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	s.once.Do(s.hashAll)

	if tag, ok := s.etags[name]; ok {
		w.Header().Set("ETag", tag)
		// Long max-age is safe BECAUSE the tag is a content hash: a changed file gets
		// a new tag, and until then a revalidation is a 304 with no body.
		w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
		if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	// Content sniffing matters most on exactly these files, and nothing else sets it.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		http.FileServer(http.FS(s.fs)).ServeHTTP(w, r)
		return
	}
	f, err := s.fs.Open(name)
	if err != nil {
		http.FileServer(http.FS(s.fs)).ServeHTTP(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", contentTypeFor(name))
	w.Header().Set("Content-Encoding", "gzip")
	// Content-Length would be wrong for the compressed body, and Go will not set one
	// for a streamed response.
	w.Header().Add("Vary", "Accept-Encoding")
	gz := gzip.NewWriter(w)
	defer func() { _ = gz.Close() }()
	_, _ = io.Copy(gz, f)
}

func (s *staticAssets) hashAll() {
	s.etags = map[string]string{}
	_ = fs.WalkDir(s.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := fs.ReadFile(s.fs, path)
		if rerr != nil {
			return nil
		}
		sum := sha256.Sum256(b)
		s.etags[path] = `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
		return nil
	})
}

// contentTypeFor covers the handful of types this directory holds; anything else
// falls through to the plain FileServer above, which sniffs.
func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}
