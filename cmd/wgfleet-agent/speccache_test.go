package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The distinction the whole fallback rests on. Falling back on a REFUSAL would
// resurrect a node the operator deliberately removed — PullSpec answers NotFound
// for a deleted node, and re-applying a cached spec on that answer rebuilds the
// data plane the controller just said to stop having.
func TestOnlyTransportFailuresReachTheCache(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"dial failure (nothing answered)", errors.New("connection refused"), true},
		{"unavailable", status.Error(codes.Unavailable, "no route"), true},
		{"deadline", status.Error(codes.DeadlineExceeded, "timeout"), true},
		{"canceled", status.Error(codes.Canceled, "shutting down"), true},

		{"node deleted", status.Error(codes.NotFound, "node not found"), false},
		{"cert revoked", status.Error(codes.PermissionDenied, "no"), false},
		{"wire skew", status.Error(codes.FailedPrecondition, "agent too new"), false},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad cert"), false},
		{"an unknown refusal is still a refusal", status.Error(codes.Internal, "boom"), false},

		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := controllerUnreachable(tc.err); got != tc.want {
				t.Errorf("controllerUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// The agent wraps its errors; the classification must survive that.
func TestUnreachableSurvivesWrapping(t *testing.T) {
	wrapped := fmt.Errorf("pull spec: %w", status.Error(codes.Unavailable, "down"))
	if !controllerUnreachable(wrapped) {
		t.Error("a wrapped Unavailable was not recognised as unreachable")
	}
	refused := fmt.Errorf("pull spec: %w", status.Error(codes.NotFound, "gone"))
	if controllerUnreachable(refused) {
		t.Error("a wrapped NotFound was treated as unreachable — a deleted node would resurrect itself")
	}
}

func TestSpecCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "last-spec.json")
	want := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressWARP}
	want.WGServer.ListenPort = 51820
	want.WGServer.AddressPool = "10.81.0.0/24"

	if err := saveSpec(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, age, err := loadSpec(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Role != want.Role || got.WGServer.ListenPort != want.WGServer.ListenPort {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if age < 0 || age > time.Minute {
		t.Errorf("age = %v, want something just written", age)
	}
}

// A NodeSpec carries peer preshared keys, and on a master every issued client's
// key material. It must never land group- or world-readable.
func TestSpecCacheIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last-spec.json")
	if err := saveSpec(path, domain.NodeSpec{Role: domain.RoleExit}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("spec cache mode = %o, want 600", perm)
	}
}

// After a decommission teardown nothing may be left to fall back on: the cached
// spec is the last LIVE one, and "controller unreachable" would rebuild from it.
func TestForgetSpecLeavesNothingToFallBackOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last-spec.json")
	if err := saveSpec(path, domain.NodeSpec{Role: domain.RoleExit}); err != nil {
		t.Fatal(err)
	}
	if err := forgetSpec(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSpec(path); err == nil {
		t.Fatal("the cached spec is still loadable after forgetSpec")
	}
	if err := forgetSpec(path); err != nil {
		t.Fatalf("forgetting an absent cache is an error: %v", err)
	}
}
