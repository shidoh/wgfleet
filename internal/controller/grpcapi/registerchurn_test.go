package grpcapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Agents call Register on EVERY reconcile pass (~30s each). In steady state the
// request carries nothing new, so the controller must not rewrite the row: the
// write is pure WAL churn and, under ADR-0027 phase B, would become a replicated
// raft command per node per pass. updated_at is the observable: the store stamps
// it on every write, so an unchanged re-register must leave it untouched.
func TestRegisterDoesNotRewriteUnchangedNode(t *testing.T) {
	h := newHarness(t, integrationFleet())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.store.UpsertNode(ctx, domain.Node{
		ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady,
	}); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	agent := h.agentFor(t, "exit-de-1")
	if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5"); err != nil {
		t.Fatalf("first register: %v", err)
	}
	first, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}

	// Sleep past the clock's resolution so a second write would be visibly later.
	time.Sleep(5 * time.Millisecond)

	if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5"); err != nil {
		t.Fatalf("second register: %v", err)
	}
	second, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Errorf("unchanged re-register rewrote the node: updated_at %s -> %s",
			first.UpdatedAt, second.UpdatedAt)
	}

	// A real change must still be persisted — the dedup must not freeze the row.
	if _, err := agent.Register(ctx, domain.RoleExit, "203.0.113.9", "", "10.20.0.5"); err != nil {
		t.Fatalf("changed register: %v", err)
	}
	third, err := h.store.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if third.PublicIP != "203.0.113.9" {
		t.Errorf("public_ip = %q, want the newly reported 203.0.113.9", third.PublicIP)
	}
	if !third.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("changed register did not stamp updated_at (%s, first was %s)",
			third.UpdatedAt, first.UpdatedAt)
	}
}

// A node the operator deleted must not come back by registering. Its certificate
// still validates — deletion does not revoke it — so the refusal is the gate.
func TestRegisterRefusesADeletedNodeUntilProvisioned(t *testing.T) {
	h := newHarness(t, integrationFleet())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.store.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.DeleteNode(ctx, "exit-de-1"); err != nil {
		t.Fatal(err)
	}
	agent := h.agentFor(t, "exit-de-1")
	if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5"); err == nil {
		t.Fatal("a deleted node registered itself back into the fleet")
	}
	if _, err := h.store.GetNode(ctx, "exit-de-1"); err == nil {
		t.Fatal("the refused registration still created the row")
	}
	if err := h.store.Readmit(ctx, "exit-de-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Register(ctx, domain.RoleExit, "198.51.100.7", "", "10.20.0.5"); err != nil {
		t.Fatalf("readmitted node refused: %v", err)
	}
}
