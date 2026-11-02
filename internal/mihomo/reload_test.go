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

// A restart drops every client's connection, so the plan must say which proxy
// forced it. Without the names, two bounces in a minute leave no reason that can
// be reconstructed from anything left on the box.
func TestChangedProxiesNamesWhatMoved(t *testing.T) {
	oldCfg := []byte("proxies:\n  - name: vn0\n    mtu: 1360\n  - name: vn1\n    mtu: 1360\n")
	newCfg := []byte("proxies:\n  - name: vn0\n    mtu: 1280\n  - name: vn1\n    mtu: 1360\n")

	got := ChangedProxies(oldCfg, newCfg)
	if len(got) != 1 || got[0] != "vn0" {
		t.Errorf("changed = %v, want [vn0] — an operator cannot tell why the data plane bounced", got)
	}
	if n := len(ChangedProxies(oldCfg, oldCfg)); n != 0 {
		t.Errorf("identical configs reported %d changes", n)
	}
	if !ProxiesChanged(oldCfg, newCfg) || ProxiesChanged(oldCfg, oldCfg) {
		t.Error("the bool predicate disagrees with the list it is built on")
	}
}

// Added and removed proxies count too: an exit joining or leaving changes the
// wireguard outbounds, which a hot reload cannot re-initialise.
func TestChangedProxiesNoticesAdditionsAndRemovals(t *testing.T) {
	one := []byte("proxies:\n  - name: vn0\n")
	two := []byte("proxies:\n  - name: vn0\n  - name: vn1\n")

	if got := ChangedProxies(one, two); len(got) != 1 || got[0] != "vn1" {
		t.Errorf("adding a proxy: changed = %v, want [vn1]", got)
	}
	if got := ChangedProxies(two, one); len(got) != 1 || got[0] != "vn1" {
		t.Errorf("removing a proxy: changed = %v, want [vn1]", got)
	}
}

// Reordering the list is not a change: the rendered order is deterministic, and
// treating a permutation as a change would restart mihomo for nothing.
func TestChangedProxiesIgnoresOrder(t *testing.T) {
	a := []byte("proxies:\n  - name: vn0\n    mtu: 1360\n  - name: vn1\n    mtu: 1360\n")
	b := []byte("proxies:\n  - name: vn1\n    mtu: 1360\n  - name: vn0\n    mtu: 1360\n")
	if got := ChangedProxies(a, b); len(got) != 0 {
		t.Errorf("a permutation reported %v as changed", got)
	}
}

// The asymmetry that matters: an unparseable NEW config must force a restart, but
// two consecutively unparseable ones must not — that is a restart every pass, an
// outage on repeat rather than a safety measure.
func TestChangedProxiesHandlesUnparseableConfigs(t *testing.T) {
	good := []byte("proxies:\n  - name: vn0\n")
	bad := []byte("{{ not yaml")

	if got := ChangedProxies(good, bad); len(got) != 1 || got[0] != "<unparseable>" {
		t.Errorf("an unparseable new config reported %v, want a forced restart", got)
	}
	if got := ChangedProxies(bad, good); len(got) != 1 || got[0] != "<unparseable>" {
		t.Errorf("recovering from an unparseable config reported %v, want a forced restart", got)
	}
	if got := ChangedProxies(bad, bad); len(got) != 0 {
		t.Errorf("two unparseable configs reported %v — this restarts mihomo every 30 seconds", got)
	}
}
