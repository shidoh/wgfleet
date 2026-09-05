package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shidoh/wgfleet/internal/atomicfile"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/shidoh/wgfleet/internal/domain"
)

// specCacheFile is where the agent keeps the last spec it applied successfully.
// It lives beside the node's other durable state rather than in /run: the whole
// point is to survive a reboot.
const specCacheFile = "/var/lib/wgfleet/last-spec.json"

// cachedSpec is the on-disk form. The timestamp is not used to expire anything —
// a node with no controller is better converged to an old spec than left dark —
// but it is what makes the log line honest about how old the fallback is.
type cachedSpec struct {
	SavedAt time.Time       `json:"saved_at"`
	Spec    domain.NodeSpec `json:"spec"`
}

// saveSpec records a spec the agent has just applied successfully.
//
// LAST-GOOD, not last-received: a spec that failed to apply is not something to
// replay unattended at boot. It is written 0600 because a NodeSpec carries peer
// preshared keys and, on a master, every issued client's key material.
func saveSpec(path string, spec domain.NodeSpec) error {
	blob, err := json.Marshal(cachedSpec{SavedAt: time.Now().UTC(), Spec: spec})
	if err != nil {
		return fmt.Errorf("marshal spec cache: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create spec cache dir: %w", err)
	}
	// Through the shared atomic writer: the same tmp+rename as before, plus the fsync
	// it was missing. Without that a power cut can land the rename ahead of the bytes
	// and leave a zero-length cache — breaking it in exactly the case it exists for,
	// a node coming up without its controller.
	if err := atomicfile.Write(path, blob, 0o600); err != nil {
		return fmt.Errorf("write spec cache: %w", err)
	}
	return nil
}

// loadSpec returns the cached spec and its age.
func loadSpec(path string) (domain.NodeSpec, time.Duration, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return domain.NodeSpec{}, 0, err
	}
	var c cachedSpec
	if err := json.Unmarshal(blob, &c); err != nil {
		return domain.NodeSpec{}, 0, fmt.Errorf("parse spec cache %q: %w", path, err)
	}
	return c.Spec, time.Since(c.SavedAt), nil
}

// controllerUnreachable reports whether err means "I could not talk to the
// controller" as opposed to "the controller answered, and the answer was no".
//
// This distinction is the whole safety of the fallback. Falling back on a REFUSAL
// would resurrect a node the operator deliberately removed: PullSpec answers
// NotFound for a deleted node, and a node that re-applied its cached spec on that
// answer would rebuild the data plane the controller just told it to stop having.
// Only transport-class failures — nothing answered — may reach the cache.
//
// Unknown codes are treated as ANSWERS, not as silence: an unrecognised refusal
// must not become a reason to ignore the controller.
func controllerUnreachable(err error) bool {
	if err == nil {
		return false
	}
	// Walk the chain rather than inspecting err directly: the agent wraps its errors
	// ("pull spec: %w"), and status.FromError does not unwrap. Note also that
	// status.FromError(nil) reports ok=true with code OK, so testing the unwrapped
	// error first silently classified every unwrapped status as "not an error".
	var gs interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &gs) {
		// Not a gRPC status anywhere in the chain — a dial failure, a TLS handshake
		// error, a DNS failure, a cancelled context. Nothing answered.
		return true
	}
	switch gs.GRPCStatus().Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return true
	default:
		// NotFound, PermissionDenied, FailedPrecondition, Unauthenticated,
		// FailedPrecondition-for-wire-skew — all of these are the controller
		// answering. Its answer wins over anything on disk.
		return false
	}
}
