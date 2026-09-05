package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// fakePlanner is stubPlanner's sibling for the cases where planning itself has to
// fail, or where the order planners ran in is the thing under test.
type fakePlanner struct {
	component string
	plan      func() ([]Action, error)
}

func (f fakePlanner) Component() string { return f.component }
func (f fakePlanner) Plan(context.Context, domain.NodeSpec) ([]Action, error) {
	return f.plan()
}

// quietLogger keeps a deliberately noisy failure path out of the test output: the
// engine logs every component that does not converge, which is the point of the
// change these tests cover.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A component that fails must not take the rest of the node with it.
//
// The master runs twenty planners in a fixed order, and the pass used to stop at
// the first error. A failure in the namespace interception — sixth of the list —
// therefore left the node with no host NAT, no DOCKER-USER accept, no DNS filter
// and no client VLESS inbound, every thirty seconds, for as long as the cause
// lasted. The blast radius of a fault had nothing to do with what the fault was
// about. That is the shape of the three-hour outage of 2026-09-05, generalised.
func TestOneFailedComponentDoesNotStopTheOthers(t *testing.T) {
	var ran []string
	note := func(name string) Planner {
		return fakePlanner{component: name, plan: func() ([]Action, error) {
			ran = append(ran, name)
			return []Action{NoChangeAction(name, "fine")}, nil
		}}
	}
	broken := fakePlanner{component: "broken", plan: func() ([]Action, error) {
		ran = append(ran, "broken")
		return nil, errors.New("the namespace is not there")
	}}

	eng := NewEngine(quietLogger(), note("first"), broken, note("after"))
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply)

	if err == nil {
		t.Fatal("a failed component reported a clean pass")
	}
	if !strings.Contains(err.Error(), "the namespace is not there") {
		t.Errorf("the pass error does not name the cause: %v", err)
	}
	if got := strings.Join(ran, ","); got != "first,broken,after" {
		t.Errorf("planners after the failure were skipped: ran %s", got)
	}
	var withErr []string
	for _, p := range report.Plans {
		if p.Err != nil {
			withErr = append(withErr, p.Component)
		}
	}
	if got := strings.Join(withErr, ","); got != "broken" {
		t.Errorf("the failure is attributed to %q, want just the component that failed", got)
	}
}

// Within one component the remaining actions ARE skipped: they are the steps of a
// single build and each one assumes the one before it happened.
func TestAFailedActionStopsItsOwnComponentOnly(t *testing.T) {
	var ran []string
	act := func(name string, fail bool) Action {
		return CustomAction(ActionExec, name, name, name, func(context.Context) error {
			ran = append(ran, name)
			if fail {
				return errors.New("boom")
			}
			return nil
		})
	}
	broken := fakePlanner{component: "broken", plan: func() ([]Action, error) {
		return []Action{act("step1", false), act("step2", true), act("step3", false)}, nil
	}}
	after := fakePlanner{component: "after", plan: func() ([]Action, error) {
		return []Action{act("other", false)}, nil
	}}

	eng := NewEngine(quietLogger(), broken, after)
	if _, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply); err == nil {
		t.Fatal("a failed action reported a clean pass")
	}
	if got := strings.Join(ran, ","); got != "step1,step2,other" {
		t.Errorf("ran %s: step3 must be skipped (it assumes step2 happened) and other must not", got)
	}
}
