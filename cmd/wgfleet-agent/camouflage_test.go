package main

import (
	"errors"
	"testing"

	"github.com/shidoh/wgfleet/internal/camouflage"
	"github.com/shidoh/wgfleet/internal/domain"
)

// A new claim of the domain waits for a clean pass: a failed one may have left
// the inbound on its old target. Keeping or withdrawing a claim never waits.
func TestCamouflageReportClaimsTheDomainOnlyAfterACleanPass(t *testing.T) {
	a := &agent{camoGate: camouflage.NewGate("")}
	s := &domain.CamouflageSpec{Domain: "e1.example.net", PublicIP: "198.51.100.20"}
	failed := errors.New("apply reality inbound: boom")

	a.camoGate.Observe(s, camouflage.Result{TLSOK: true, DNSOK: true})
	if got := a.camouflageReport(failed); got != "" {
		t.Errorf("claimed after a failed pass: %q", got)
	}
	if got := a.camouflageReport(nil); got != s.Domain {
		t.Errorf("clean pass: %q, want the domain", got)
	}
	if got := a.camouflageReport(failed); got != s.Domain {
		t.Errorf("an unrelated failure withdrew a standing claim: %q", got)
	}
	a.camoGate.Observe(nil, camouflage.Result{})
	if got := a.camouflageReport(failed); got != "" {
		t.Errorf("withdrawal waited for a clean pass: %q", got)
	}
}
