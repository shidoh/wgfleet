package web

import (
	"net/http"

	"github.com/shidoh/wgfleet/internal/controller/rollout"
)

// Roller drives the fleet-wide rolling agent upgrade. The controller wires an
// adapter over *rollout.Coordinator + the fleet manifest; nil ⇒ the action is
// omitted from the page entirely (not rendered disabled), matching how the
// dashboard treats a missing provisioner.
type Roller interface {
	// Plan is the dry-run: which exits would be rolled, in which order, and what
	// each is running now. Cheap and side-effect free — the page renders it on
	// every poll so the operator sees the answer before committing to anything.
	Plan() rollout.Plan
	// Start begins a rollout, erroring if one is already running.
	Start() error
	// Abort stops a running rollout (the node in flight is rolled back).
	Abort()
	// Snapshot is the live state of the current/last rollout.
	Snapshot() rollout.State
}

// rolloutData backs both the fleet-page section and its polled partial.
type rolloutData struct {
	Plan  rollout.Plan
	State rollout.State
	CSRF  string
}

// rolloutView assembles the panel's data. Safe to call with a nil Roller.
func (h *Handler) rolloutView() *rolloutData {
	if h.roller == nil {
		return nil
	}
	return &rolloutData{Plan: h.roller.Plan(), State: h.roller.Snapshot(), CSRF: h.csrf}
}

// handleRolloutPartial serves the polled progress panel. Read-only, so it is not
// guarded — it is the same exposure as the existing /partials/nodes.
func (h *Handler) handleRolloutPartial(w http.ResponseWriter, r *http.Request) {
	if h.roller == nil {
		http.Error(w, "rolling upgrade is not configured", http.StatusServiceUnavailable)
		return
	}
	h.render(w, h.listTmpl, "rollout-panel", h.rolloutView())
}

// handleRolloutStart kicks off a rollout and returns to the fleet page, where
// the polled panel takes over reporting. A refusal (one already running, nothing
// outdated) comes back as the standard flash on that page rather than a bare
// error document.
func (h *Handler) handleRolloutStart(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.roller == nil {
		http.Error(w, "rolling upgrade is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := h.roller.Start(); err != nil {
		h.redirectErr(w, r, "/", "start rolling upgrade", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleRolloutAbort(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.roller == nil {
		http.Error(w, "rolling upgrade is not configured", http.StatusServiceUnavailable)
		return
	}
	h.roller.Abort()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
