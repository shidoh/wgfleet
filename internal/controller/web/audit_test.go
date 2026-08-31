package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// captureLog swaps the handler's logger for one writing into a buffer.
func captureLog(h *Handler) *bytes.Buffer {
	var buf bytes.Buffer
	h.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return &buf
}

// The console's destructive actions used to leave nothing in the journal — only
// failures were logged, via redirectErr. A month later, "who removed this exit, and
// when" had no answer anywhere on the box. Every action that changes fleet or
// credential state has to say so.
func TestDestructiveActionsAreAudited(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		action string
		setup  func(t *testing.T, h *Handler, st storeSeeder)
	}{
		{
			name:   "delete",
			path:   "/nodes/exit-de-1/delete",
			action: "delete node",
			setup: func(t *testing.T, h *Handler, st storeSeeder) {
				st.seed(domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})
			},
		},
		{
			name:   "drain",
			path:   "/nodes/exit-de-1/drain",
			action: "take node out of routing",
			setup: func(t *testing.T, h *Handler, st storeSeeder) {
				st.seed(domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})
			},
		},
		{
			name:   "undrain",
			path:   "/nodes/exit-de-1/undrain",
			action: "return node to routing",
			setup: func(t *testing.T, h *Handler, st storeSeeder) {
				st.seed(domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Drain: true})
			},
		},
		{
			name:   "decommission",
			path:   "/nodes/exit-de-1/decommission",
			action: "decommission node",
			setup: func(t *testing.T, h *Handler, st storeSeeder) {
				st.seed(domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Drain: true})
			},
		},
		{
			name:   "recommission",
			path:   "/nodes/exit-de-1/recommission",
			action: "cancel node decommission",
			setup: func(t *testing.T, h *Handler, st storeSeeder) {
				st.seed(domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, st := newTestHandler(t, nil)
			tc.setup(t, h, storeSeeder{t: t, st: st})
			buf := captureLog(h)

			res := postWith(t, h, tc.path, url.Values{"confirm": {"1"}})
			if res.StatusCode != 303 {
				t.Fatalf("status = %d, want 303 (action did not go through)", res.StatusCode)
			}

			got := buf.String()
			if !strings.Contains(got, tc.action) {
				t.Errorf("no audit line naming %q:\n%s", tc.action, got)
			}
			// The line must answer "who" and "what", not just "something happened".
			for _, want := range []string{"exit-de-1", "admin"} {
				if !strings.Contains(got, want) {
					t.Errorf("audit line does not record %q:\n%s", want, got)
				}
			}
		})
	}
}

// A confirmation page renders and changes NOTHING. Logging it as a completed action
// would put a delete in the journal that never happened — worse than no log at all.
func TestTheConfirmationPageIsNotAudited(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})
	buf := captureLog(h)

	res := post(t, h, "/nodes/exit-de-1/delete") // unconfirmed
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want the confirmation page", res.StatusCode)
	}

	if got := buf.String(); strings.Contains(got, "delete node") {
		t.Errorf("the confirmation page was logged as a completed delete:\n%s", got)
	}
}

// A refused action must not be audited as a completed one either.
func TestARefusedActionIsNotAuditedAsDone(t *testing.T) {
	h, st := newTestHandler(t, nil)
	// Not decommissioned: the delete is refused server-side.
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})
	buf := captureLog(h)

	postWith(t, h, "/nodes/exit-de-1/delete", url.Values{"confirm": {"1"}})

	if got := buf.String(); strings.Contains(got, "msg=\"console action\"") {
		t.Errorf("a refused delete was audited as a completed action:\n%s", got)
	}
}

type storeSeeder struct {
	t  *testing.T
	st interface {
		UpsertNode(context.Context, domain.Node) error
	}
}

func (s storeSeeder) seed(n domain.Node) {
	s.t.Helper()
	if err := s.st.UpsertNode(context.Background(), n); err != nil {
		s.t.Fatal(err)
	}
}

// Show the real line once, so the shape an operator greps for is pinned by a test.
func TestAuditLineShape(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})
	buf := captureLog(h)

	postWith(t, h, "/nodes/exit-de-1/delete", url.Values{"confirm": {"1"}})

	line := strings.TrimSpace(buf.String())
	t.Logf("audit line: %s", line)
	for _, want := range []string{`level=INFO`, `msg="console action"`, `action="delete node"`, `user=admin`, `node=exit-de-1`} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %s in:\n%s", want, line)
		}
	}
}
