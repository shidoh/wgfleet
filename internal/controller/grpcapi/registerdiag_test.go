package grpcapi

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// When a re-registration DOES change something, the log must name the field.
//
// The guard that suppresses an unchanged re-registration works — there is an
// integration test for it, and exits do not appear in this log. It can fail to
// hold for a master: then `node registered` fires on every pass, dominates the
// controller's journal, and each line is also a write to the store. Twenty fields
// and no way to tell which one churns makes that hard to fix; it also buries the
// events an operator needs, such as why mihomo bounced, which then cannot be
// reconstructed from this log at all.
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
