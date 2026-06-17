package mihomo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReloadSuccess(t *testing.T) {
	var gotAuth, gotBody, gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := Reload(context.Background(), addr, "s3cr3t", []byte("log-level: debug\n")); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/configs" {
		t.Errorf("request = %s %s, want PUT /configs", gotMethod, gotPath)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Errorf("auth header = %q, want Bearer s3cr3t", gotAuth)
	}
	if !strings.Contains(gotBody, "log-level: debug") || !strings.Contains(gotBody, `"payload"`) {
		t.Errorf("body did not carry the yaml payload: %q", gotBody)
	}
}

func TestReloadRejectedConfigIsNotUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid config", http.StatusBadRequest)
	}))
	defer srv.Close()

	err := Reload(context.Background(), strings.TrimPrefix(srv.URL, "http://"), "", []byte("x"))
	if err == nil {
		t.Fatal("expected an error for a rejected config")
	}
	if errors.Is(err, ErrUnreachable) {
		t.Errorf("a rejected config must NOT be ErrUnreachable (would trigger a restart into a bad config): %v", err)
	}
}

func TestReloadUnreachable(t *testing.T) {
	// No server listening on this address ⇒ transport error ⇒ ErrUnreachable.
	err := Reload(context.Background(), "127.0.0.1:1", "", []byte("x"))
	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("a transport failure must be ErrUnreachable, got %v", err)
	}
}

func TestReloadNoControllerIsUnreachable(t *testing.T) {
	if err := Reload(context.Background(), "", "", []byte("x")); !errors.Is(err, ErrUnreachable) {
		t.Errorf("empty controller addr must be ErrUnreachable, got %v", err)
	}
}
