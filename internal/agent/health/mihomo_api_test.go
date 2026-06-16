package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClashSecret(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"present", map[string]any{"secret": "s3cr3t"}, "s3cr3t"},
		{"missing", map[string]any{"log-level": "info"}, ""},
		{"nil map", nil, ""},
		{"non-string", map[string]any{"secret": 123}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clashSecret(tc.in); got != tc.want {
				t.Errorf("clashSecret = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMihomoAPIProbeAuth verifies the probe authenticates with the operator's
// Clash API secret — a server that demands the bearer answers 401 without it.
func TestMihomoAPIProbeAuth(t *testing.T) {
	const secret = "ZknWGp"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"version":"test"}`))
	}))
	defer srv.Close()
	controller := strings.TrimPrefix(srv.URL, "http://")

	// With the right secret ⇒ OK.
	if r := mihomoAPIProbe(controller, secret)(context.Background()); !r.OK {
		t.Errorf("authenticated probe should pass, got fail: %s", r.Detail)
	}
	// Without the secret ⇒ 401 ⇒ fail (the bug that flapped the master to Degraded).
	if r := mihomoAPIProbe(controller, "")(context.Background()); r.OK {
		t.Errorf("unauthenticated probe should fail against a secured API")
	} else if !strings.Contains(r.Detail, "401") {
		t.Errorf("expected a 401 detail, got %q", r.Detail)
	}
}
