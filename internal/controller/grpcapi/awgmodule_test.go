package grpcapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The module build an agent registers with is what the controller's build gates
// read. It must land on the node, follow every change — including an agent that
// stops reporting, which must read as unknown rather than keep the last good
// answer — and an unchanged report must not rewrite the row.
func TestRegisterRecordsAWGModuleBuild(t *testing.T) {
	h := newHarness(t, integrationFleet())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agent := h.agentFor(t, "exit-de-1")

	newBuild := domain.AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: "A1B2C3D4E5F60718293A4B5"}
	pending := domain.AWGModuleBuild{
		PackageVersion: "1.0.0-0~202609061402+4569c4c", SrcVersion: "0123456789ABCDEF0123456", ReloadPending: true,
	}
	steps := []struct {
		name      string
		report    domain.AWGModuleBuild
		wantLabel string
	}{
		{name: "first report", report: newBuild, wantLabel: "202609061402"},
		{name: "reload pending", report: pending, wantLabel: "unknown"},
		{name: "reloaded", report: newBuild, wantLabel: "202609061402"},
		{name: "agent stops reporting", report: domain.AWGModuleBuild{}, wantLabel: "unknown"},
	}
	for _, st := range steps {
		if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5", st.report); err != nil {
			t.Fatalf("%s: register: %v", st.name, err)
		}
		got, err := h.store.GetNode(ctx, "exit-de-1")
		if err != nil {
			t.Fatalf("%s: get node: %v", st.name, err)
		}
		if got.AWGModule != st.report {
			t.Errorf("%s: stored build = %+v, want %+v", st.name, got.AWGModule, st.report)
		}
		if l := got.AWGModule.Label(); l != st.wantLabel {
			t.Errorf("%s: label = %q, want %q", st.name, l, st.wantLabel)
		}
	}

	// Steady state: the same build again is no write.
	if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5", newBuild); err != nil {
		t.Fatal(err)
	}
	first, _ := h.store.GetNode(ctx, "exit-de-1")
	time.Sleep(5 * time.Millisecond)
	if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5", newBuild); err != nil {
		t.Fatal(err)
	}
	second, _ := h.store.GetNode(ctx, "exit-de-1")
	if !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Errorf("unchanged build rewrote the node: updated_at %s -> %s", first.UpdatedAt, second.UpdatedAt)
	}
}
