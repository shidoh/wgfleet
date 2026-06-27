package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
)

func newBackupHandler(t *testing.T, exporter func(ctx context.Context, recipient string) ([]byte, error)) *Handler {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// Seed an admin so session cookies work for backup handler tests.
	hash, _ := auth.HashPassword("test-password-123")
	secret := []byte("test-secret-test-secret-test-sec")
	if err := st.SetAuthCredential(context.Background(), "admin", hash, secret); err != nil {
		t.Fatal(err)
	}
	h, err := New(st, nil, nil, nil, exporter, testSessionTTL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// postForm signs a form POST through the CSRF/Sec-Fetch/session guard.
func postForm(t *testing.T, h *Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-CSRF-Token", h.csrf)
	req.AddCookie(sessionCookieFor(t, h))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandleBackupExportStreamsArchive(t *testing.T) {
	exporter := func(_ context.Context, recipient string) ([]byte, error) {
		return []byte("AGE-ARCHIVE for " + recipient), nil
	}
	h := newBackupHandler(t, exporter)

	rec := postForm(t, h, "/backup", url.Values{"recipient": {"age1xyz"}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "wgfleet-backup.tar.age") {
		t.Fatalf("missing attachment header: %q", cd)
	}
	if !strings.Contains(rec.Body.String(), "age1xyz") {
		t.Fatalf("archive not streamed: %q", rec.Body.String())
	}
}

func TestHandleBackupExportRequiresRecipient(t *testing.T) {
	exporter := func(_ context.Context, _ string) ([]byte, error) { return []byte("x"), nil }
	h := newBackupHandler(t, exporter)

	rec := postForm(t, h, "/backup", url.Values{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without recipient, got %d", rec.Code)
	}
}

func TestHandleBackupExportGuarded(t *testing.T) {
	exporter := func(_ context.Context, _ string) ([]byte, error) { return []byte("x"), nil }
	h := newBackupHandler(t, exporter)

	// Authenticated but no CSRF token / Sec-Fetch headers ⇒ the guard must reject
	// (the export is a sensitive surface: it carries the CA key and every client key).
	req := httptest.NewRequest(http.MethodPost, "/backup", strings.NewReader("recipient=age1xyz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookieFor(t, h))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("unguarded export must not succeed, got %d", rec.Code)
	}
}
