package web

import (
	"fmt"
	"net/http"
)

// handleBackupExport streams an age-encrypted controller backup. It is a
// mutating, sensitive surface (the archive carries the CA key and every client
// key), so it goes through the same guard() as the other POST actions. A
// recipient is required: the browser path cannot drive age's interactive
// passphrase prompt, so the operator supplies an age recipient (public key) to
// encrypt to.
func (h *Handler) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.exportBackup == nil {
		http.Error(w, "backup export not configured", http.StatusNotImplemented)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	recipient := r.FormValue("recipient")
	if recipient == "" {
		http.Error(w, "an age recipient is required for UI export", http.StatusBadRequest)
		return
	}
	archive, err := h.exportBackup(r.Context(), recipient)
	if err != nil {
		http.Error(w, fmt.Sprintf("backup failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="wgfleet-backup.tar.age"`)
	_, _ = w.Write(archive)
}
