package grpcapi

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// When a re-registration DOES change something, the log must name the field.
//
// The guard that suppresses an unchanged re-registration works — there is an
// integration test for it, and on the live fleet no exit ever appears in this log.
// It does not hold for the master: measured 2026-09-04, `node registered` fired
// 721 times in three hours for master-xa-1 alone, 97% of the controller's entire
// journal, and each line is also a write to the store. Twenty fields and no way to
// tell which one churns is what made that unfixable for weeks; it also buried the
// events an operator needs, so the reason mihomo bounced twice in 36 seconds that
// morning could not be reconstructed from this log at all.
func TestChangedNodeFieldsNamesWhatMoved(t *testing.T) {
	before := domain.Node{ID: "n1", Name: "master-xa-1", Role: domain.RoleMaster, PublicIP: "1.2.3.4"}

	if got := changedNodeFields(before, before, true); got != "nothing" {
		t.Errorf("an identical re-registration reported %q, want %q", got, "nothing")
	}
	if got := changedNodeFields(domain.Node{}, before, false); got != "new" {
		t.Errorf("a first registration reported %q, want %q", got, "new")
	}

	after := before
	after.PublicIP = "5.6.7.8"
	after.AgentVersion = "v9"
	got := changedNodeFields(before, after, true)
	for _, want := range []string{"PublicIP", "AgentVersion"} {
		if !strings.Contains(got, want) {
			t.Errorf("changed = %q, missing %q — the field that churns stays anonymous", got, want)
		}
	}
	if strings.Contains(got, "Name") {
		t.Errorf("changed = %q names a field that did not move", got)
	}
}

// A field added to domain.Node later must be covered without anyone remembering
// to update this function — reflection is the point, not an implementation detail.
func TestChangedNodeFieldsCoversEveryExportedField(t *testing.T) {
	before := domain.Node{}
	after := domain.Node{Drain: true}
	if got := changedNodeFields(before, after, true); !strings.Contains(got, "Drain") {
		t.Errorf("changed = %q, want it to notice Drain", got)
	}
}
