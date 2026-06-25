package provmgr

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// observation records one OnProvision call for assertions.
type observation struct {
	role    string
	seconds float64
	err     error
}

// recordingObserver returns a thread-safe ProvisionObserver and an accessor for
// the recorded calls (the async path records from a goroutine).
func recordingObserver() (ProvisionObserver, func() []observation) {
	var (
		mu   sync.Mutex
		obs  []observation
		read = func() []observation {
			mu.Lock()
			defer mu.Unlock()
			out := make([]observation, len(obs))
			copy(out, obs)
			return out
		}
	)
	return func(role string, seconds float64, err error) {
		mu.Lock()
		defer mu.Unlock()
		obs = append(obs, observation{role: role, seconds: seconds, err: err})
	}, read
}

// newTimedManager builds a Manager with a fake monotonic clock (each call to now
// advances by step) plus an injected OnProvision observer, so the recorded
// duration is deterministic.
func newTimedManager(t *testing.T, dial DialFunc, onProv ProvisionObserver, step time.Duration) (*Manager, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(st, ca, testFleet(), Options{
		ControllerEndpoint: "ctl:8443", Dial: dial, OnProvision: onProv,
	}, log)

	cur := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time {
		now := cur
		cur = cur.Add(step)
		return now
	}
	return m, st
}

func TestProvisionRecordsDurationOnSuccess(t *testing.T) {
	obs, read := recordingObserver()
	mock := readyMock()
	// 10s clock step: start - end is exactly one step.
	m, _ := newTimedManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil }, obs, 10*time.Second)

	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision: %v", err)
	}
	got := read()
	if len(got) != 1 {
		t.Fatalf("want 1 observation, got %d", len(got))
	}
	if got[0].role != string(domain.RoleExit) {
		t.Errorf("role = %q, want %q", got[0].role, domain.RoleExit)
	}
	if got[0].err != nil {
		t.Errorf("err = %v, want nil", got[0].err)
	}
	if got[0].seconds != 10 {
		t.Errorf("duration = %v, want 10", got[0].seconds)
	}
}

func TestProvisionRecordsDurationOnError(t *testing.T) {
	obs, read := recordingObserver()
	dialErr := errors.New("ssh refused")
	m, _ := newTimedManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		return nil, dialErr
	}, obs, 3*time.Second)

	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply); err == nil {
		t.Fatal("expected provision error")
	}
	got := read()
	if len(got) != 1 {
		t.Fatalf("want 1 observation, got %d", len(got))
	}
	if got[0].err == nil {
		t.Error("want error recorded, got nil")
	}
	if got[0].role != string(domain.RoleExit) {
		t.Errorf("role = %q, want %q", got[0].role, domain.RoleExit)
	}
	if got[0].seconds != 3 {
		t.Errorf("duration = %v, want 3", got[0].seconds)
	}
}

func TestProvisionPlanModeNotTimed(t *testing.T) {
	obs, read := recordingObserver()
	mock := readyMock()
	m, _ := newTimedManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil }, obs, time.Second)

	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModePlan); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if got := read(); len(got) != 0 {
		t.Errorf("plan mode must not be timed, got %d observations", len(got))
	}
}

func TestProvisionNilObserverNoPanic(t *testing.T) {
	mock := readyMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	// Options.OnProvision is nil here — Provision must not panic.
	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision: %v", err)
	}
}
