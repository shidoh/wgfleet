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

// Some components really are one build, and continuing past a failure in the first
// one is worse than stopping.
//
// The master's NAT renders the "moved" ruleset — host interception removed,
// client traffic routed at mihomo's namespace — because the namespace planner one
// step earlier was supposed to have armed that namespace. While the pass aborted
// on the first error, a namespace that failed to arm took the NAT down with it and
// the host kept intercepting. Continuing blindly would instead tear down the host
// path with nothing on the other side.
func TestAComponentThatBuildsOnAFailedOneIsSkipped(t *testing.T) {
	var ran []string
	eng := NewEngine(quietLogger(),
		fakePlanner{component: "namespace", plan: func() ([]Action, error) {
			ran = append(ran, "namespace")
			return nil, errors.New("the holder is not up")
		}},
		dependentPlanner{fakePlanner{component: "master NAT", plan: func() ([]Action, error) {
			ran = append(ran, "master NAT")
			return []Action{NoChangeAction("nat", "fine")}, nil
		}}, "namespace"},
		fakePlanner{component: "unrelated", plan: func() ([]Action, error) {
			ran = append(ran, "unrelated")
			return []Action{NoChangeAction("dns", "fine")}, nil
		}},
	)
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply)
	if err == nil {
		t.Fatal("a failed component reported a clean pass")
	}
	if got := strings.Join(ran, ","); got != "namespace,unrelated" {
		t.Errorf("ran %s: the dependent must not be planned at all, the unrelated one must", got)
	}
	var skipped string
	for _, p := range report.Plans {
		if p.Component == "master NAT" && len(p.Actions) == 1 {
			skipped = p.Actions[0].Summary
		}
	}
	if !strings.Contains(skipped, "namespace") {
		t.Errorf("the skip does not say what it is waiting for: %q", skipped)
	}
}

// And a dependency that is satisfied changes nothing.
func TestADependentComponentRunsWhenWhatItBuildsOnConverged(t *testing.T) {
	var ran []string
	eng := NewEngine(quietLogger(),
		fakePlanner{component: "namespace", plan: func() ([]Action, error) {
			ran = append(ran, "namespace")
			return []Action{NoChangeAction("ns", "fine")}, nil
		}},
		dependentPlanner{fakePlanner{component: "master NAT", plan: func() ([]Action, error) {
			ran = append(ran, "master NAT")
			return []Action{NoChangeAction("nat", "fine")}, nil
		}}, "namespace"},
	)
	if _, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply); err != nil {
		t.Fatalf("a clean pass reported an error: %v", err)
	}
	if got := strings.Join(ran, ","); got != "namespace,master NAT" {
		t.Errorf("ran %s, want both", got)
	}
}

type dependentPlanner struct {
	fakePlanner
	on string
}

func (d dependentPlanner) DependsOn() string { return d.on }

// A failed component must be visible in the report, not only in the journal.
//
// It used to render as "(nothing to do)" — indistinguishable from a component that
// had nothing to do — because Plan.Err was written by the engine and read by
// nobody.
func TestTheReportNamesTheComponentThatFailed(t *testing.T) {
	eng := NewEngine(quietLogger(),
		fakePlanner{component: "namespace", plan: func() ([]Action, error) {
			return nil, errors.New("the holder is not up")
		}},
	)
	report, _ := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply)
	out := report.String()
	if strings.Contains(out, "(nothing to do)") {
		t.Errorf("a failed component reads as an idle one:\n%s", out)
	}
	if !strings.Contains(out, "the holder is not up") {
		t.Errorf("the report does not say why the component failed:\n%s", out)
	}
}

// A skip propagates. C stands on B, B stands on A, and A failed: B is skipped, so
// B did not converge either, so C must not act on what B was supposed to build.
// Stopping the chain at one link would let the third component act on a second one
// that never ran.
func TestASkipPropagatesDownTheChain(t *testing.T) {
	var ran []string
	note := func(name string) func() ([]Action, error) {
		return func() ([]Action, error) {
			ran = append(ran, name)
			return []Action{NoChangeAction(name, "fine")}, nil
		}
	}
	eng := NewEngine(quietLogger(),
		fakePlanner{component: "A", plan: func() ([]Action, error) {
			ran = append(ran, "A")
			return nil, errors.New("A is broken")
		}},
		dependentPlanner{fakePlanner{component: "B", plan: note("B")}, "A"},
		dependentPlanner{fakePlanner{component: "C", plan: note("C")}, "B"},
		fakePlanner{component: "D", plan: note("D")},
	)
	if _, err := eng.Reconcile(context.Background(), domain.NodeSpec{}, ModeApply); err == nil {
		t.Fatal("a failed component reported a clean pass")
	}
	if got := strings.Join(ran, ","); got != "A,D" {
		t.Errorf("ran %s: B and C both stand on A, D stands on nobody", got)
	}
}
