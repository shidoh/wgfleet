package domain

import (
	"strings"
	"testing"
	"time"
)

// Uploading a binary and restarting a service is the first half of an upgrade.
// Three of the four paths that upgrade an agent stopped there and reported success,
// so an agent that started and could not converge was indistinguishable from one
// that worked. These are the conditions the rolling upgrade always checked, now
// where every path can reach them.
func TestAgentBackReasonHoldsAllFourConditions(t *testing.T) {
	restarted := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	now := restarted.Add(10 * time.Second)
	fresh := 2 * time.Minute
	ok := Node{State: StateReady, AgentVersion: "v2", LastSeen: restarted.Add(5 * time.Second)}

	if r := ok.AgentBackReason("v2", restarted, now, fresh); r != "" {
		t.Fatalf("a healthy node was rejected: %s", r)
	}
	for _, tc := range []struct {
		name string
		node Node
		want string
	}{
		// Ready alone can be state the PREVIOUS binary left behind.
		{"not ready", Node{State: StateDegraded, AgentVersion: "v2", LastSeen: now}, "state is"},
		// The version alone says nothing about whether the reconcile is healthy.
		{"old version", Node{State: StateReady, AgentVersion: "v1", LastSeen: now}, "want \"v2\""},
		// A report from before the restart belongs to the process we just killed.
		{"stale report", Node{State: StateReady, AgentVersion: "v2", LastSeen: restarted.Add(-time.Minute)}, "has not reported since"},
		// And a node that reported once and then wedged is not back either.
		{"gone quiet", Node{State: StateReady, AgentVersion: "v2", LastSeen: restarted.Add(time.Second)},
			"last report is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := now
			if tc.name == "gone quiet" {
				at = restarted.Add(10 * time.Minute)
			}
			r := tc.node.AgentBackReason("v2", restarted, at, fresh)
			if r == "" {
				t.Fatalf("%s counted as back", tc.name)
			}
			if !strings.Contains(r, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", r, tc.want)
			}
		})
	}
}

// A node that was Degraded going into an upgrade has come back when it is Degraded
// again: the gate is for binaries that break nodes, and a node that arrives broken
// and leaves as broken was not broken by the binary. Ready before ⇒ Ready required;
// Error never passes.
func TestAgentBackReasonFromHonoursThePriorState(t *testing.T) {
	restarted := time.Date(2026, 9, 7, 8, 50, 0, 0, time.UTC)
	now := restarted.Add(20 * time.Second)
	fresh := time.Minute
	back := func(st NodeState) Node {
		return Node{State: st, AgentVersion: "v2", LastSeen: restarted.Add(10 * time.Second)}
	}
	for _, tc := range []struct {
		before, after NodeState
		wantOK        bool
	}{
		{StateDegraded, StateDegraded, true},
		{StateDegraded, StateReady, true},
		{StateReady, StateDegraded, false},
		{StateReady, StateReady, true},
		{StateDegraded, StateError, false},
		{StateError, StateError, false},
	} {
		r := back(tc.after).AgentBackReasonFrom(tc.before, "v2", restarted, now, fresh)
		if (r == "") != tc.wantOK {
			t.Errorf("before=%s after=%s: reason %q, want ok=%v", tc.before, tc.after, r, tc.wantOK)
		}
	}
}
