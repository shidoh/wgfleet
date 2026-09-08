package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func passing(detail string) Probe {
	return func(context.Context) Result { return ok(detail, 5*time.Millisecond) }
}

func failing(detail string) Probe {
	return func(context.Context) Result { return fail(detail) }
}

func TestEvaluateReady(t *testing.T) {
	state, checks := Evaluate(context.Background(), nil, []Check{
		{Name: "a", Probe: passing("ok-a")},
		{Name: "b", Probe: passing("ok-b")},
	})
	if state != domain.StateReady {
		t.Fatalf("state = %q, want Ready", state)
	}
	if len(checks) != 2 || !checks[0].OK || checks[0].Detail != "ok-a" {
		t.Errorf("checks = %+v", checks)
	}
}

func TestEvaluateDegraded(t *testing.T) {
	state, checks := Evaluate(context.Background(), nil, []Check{
		{Name: "a", Probe: passing("ok")},
		{Name: "b", Probe: failing("boom")},
	})
	if state != domain.StateDegraded {
		t.Fatalf("state = %q, want Degraded", state)
	}
	// All check results are reported, not just the failing one.
	if len(checks) != 2 {
		t.Fatalf("want 2 checks, got %d", len(checks))
	}
	if checks[1].OK || checks[1].Detail != "boom" {
		t.Errorf("failing check = %+v", checks[1])
	}
}

func TestEvaluateReconcileError(t *testing.T) {
	// A reconcile error short-circuits to Error and does not run the probes.
	ran := false
	probe := func(context.Context) Result { ran = true; return ok("", 0) }
	state, checks := Evaluate(context.Background(), errors.New("nft failed"), []Check{{Name: "x", Probe: probe}})
	if state != domain.StateError {
		t.Fatalf("state = %q, want Error", state)
	}
	if ran {
		t.Error("probes must not run when reconcile failed")
	}
	if len(checks) != 1 || checks[0].Name != "reconcile" || checks[0].OK {
		t.Errorf("expected synthetic failing reconcile check, got %+v", checks)
	}
}

func TestEvaluateNoChecks(t *testing.T) {
	state, checks := Evaluate(context.Background(), nil, nil)
	if state != domain.StateReconciling {
		t.Errorf("state = %q, want Reconciling when nothing to check", state)
	}
	if checks != nil {
		t.Errorf("expected nil checks, got %+v", checks)
	}
}

func TestExitChecksRespectSpec(t *testing.T) {
	probes := ExitProbes{
		HandshakeFresh: passing("hs"),
		WARPEgress:     passing("warp"),
		DNSResolves:    passing("dns"),
	}
	// WARP egress + DNS enabled (with a mgmt addr) ⇒ all three checks.
	warpSpec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressWARP, DNS: domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.0.5"}}
	if names := checkNames(ExitChecks(warpSpec, probes)); len(names) != 3 {
		t.Errorf("warp+dns exit: want 3 checks, got %v", names)
	}

	// DNS enabled but mgmt addr not yet known ⇒ the dns-filter check is deferred,
	// so the node isn't falsely marked Degraded during the startup window.
	dnsPendingSpec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressWARP, DNS: domain.DNSFilterSpec{Enabled: true}}
	if names := checkNames(ExitChecks(dnsPendingSpec, probes)); len(names) != 2 {
		t.Errorf("dns pending (no mgmt addr): want 2 checks (no dns-filter), got %v", names)
	}

	// Direct egress, DNS off ⇒ only handshake.
	directSpec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressDirect}
	names := checkNames(ExitChecks(directSpec, probes))
	if len(names) != 1 || names[0] != "wg-handshake" {
		t.Errorf("direct exit: want [wg-handshake], got %v", names)
	}
}

// An exit that carries a lifeline must report on it: the reserve leg is what the
// fleet's "survive the block" promise rests on, and an awgl0 that never came up
// is invisible from every other check on the node — the master↔exit handshake,
// WARP egress and the resolver are all still green while it is down.
func TestExitChecksIncludeTheLifelineOnlyWhenTheSpecCarriesOne(t *testing.T) {
	probes := ExitProbes{HandshakeFresh: passing("hs"), LifelineUp: passing("lifeline")}
	base := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressDirect}

	if names := checkNames(ExitChecks(base, probes)); contains(names, "lifeline") {
		t.Errorf("an exit without a lifeline must not be checked for one, got %v", names)
	}

	withLifeline := base
	withLifeline.Lifeline = &domain.LifelineSpec{
		ClientWGSpec: domain.ClientWGSpec{
			ListenPort: 41827, AddressPool: "10.98.77.0/24", ServerAddress: "10.98.77.1",
		},
		Egress: domain.EgressWARP,
	}
	if names := checkNames(ExitChecks(withLifeline, probes)); !contains(names, "lifeline") {
		t.Errorf("an exit carrying a lifeline must be checked for it, got %v", names)
	}
}

func TestMasterChecks(t *testing.T) {
	probes := MasterProbes{MihomoAPI: passing("api"), WGServerUp: passing("wg")}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{ExternalController: "10.20.25.254:9090"}}
	names := checkNames(MasterChecks(spec, probes))
	if len(names) != 2 {
		t.Fatalf("want 2 master checks, got %v", names)
	}

	// No external controller ⇒ mihomo-api check omitted.
	specNoAPI := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	if names := checkNames(MasterChecks(specNoAPI, probes)); len(names) != 1 || names[0] != "client-wg" {
		t.Errorf("no-api master: want [client-wg], got %v", names)
	}

	// Master-tier blocky (ADR-0024): when DNS is enabled with a bind, a dns-filter
	// check is added so a down/non-resolving resolver shows Degraded.
	dnsProbes := MasterProbes{MihomoAPI: passing("api"), WGServerUp: passing("wg"), DNSResolves: passing("resolves")}
	specDNS := domain.NodeSpec{
		Role:   domain.RoleMaster,
		Master: &domain.MasterSpec{ExternalController: "10.20.25.254:9090"},
		DNS:    domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.3.10"},
	}
	if names := checkNames(MasterChecks(specDNS, dnsProbes)); len(names) != 3 || names[2] != "dns-filter" {
		t.Errorf("dns-enabled master: want [client-wg mihomo-api dns-filter], got %v", names)
	}

	// DNS enabled but mgmt addr not yet known ⇒ the dns-filter check is deferred
	// (no false Degraded in the startup window).
	specDNSPending := domain.NodeSpec{
		Role:   domain.RoleMaster,
		Master: &domain.MasterSpec{ExternalController: "10.20.25.254:9090"},
		DNS:    domain.DNSFilterSpec{Enabled: true},
	}
	if names := checkNames(MasterChecks(specDNSPending, dnsProbes)); len(names) != 2 {
		t.Errorf("dns pending (no mgmt addr): want 2 checks (no dns-filter), got %v", names)
	}

	// Client-facing VLESS inbound (ADR-0031): when the master runs it, a
	// client-vless check is added so a down inbound shows Degraded. Omitted when the
	// master does not run it, or when the probe is unwired.
	cvProbes := MasterProbes{WGServerUp: passing("wg"), ClientVLESSUp: passing("listening")}
	specCV := domain.NodeSpec{
		Role:   domain.RoleMaster,
		Master: &domain.MasterSpec{ClientVLESS: &domain.ClientVLESSServerSpec{ListenPort: 47252}},
	}
	if names := checkNames(MasterChecks(specCV, cvProbes)); !contains(names, "client-vless") {
		t.Errorf("client-vless master: want a client-vless check, got %v", names)
	}
	// No ClientVLESS spec ⇒ no client-vless check even if the probe is wired.
	specNoCV := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	if names := checkNames(MasterChecks(specNoCV, cvProbes)); contains(names, "client-vless") {
		t.Errorf("master without client-vless spec must omit the check, got %v", names)
	}
}

func TestEndToEndExitReady(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressWARP, DNS: domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.0.5"}}
	checks := ExitChecks(spec, ExitProbes{
		HandshakeFresh: passing("12s"),
		WARPEgress:     passing("104.16.0.1"),
		DNSResolves:    passing("ok"),
	})
	state, results := Evaluate(context.Background(), nil, checks)
	if state != domain.StateReady || len(results) != 3 {
		t.Fatalf("state=%q results=%d", state, len(results))
	}
}

func checkNames(checks []Check) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.Name
	}
	return out
}

func TestNewestHandshake(t *testing.T) {
	out := "PUBKEY1\t1700000000\nPUBKEY2\t1700000123\nPUBKEY3\t0\n"
	if got := newestHandshake(out); got != 1700000123 {
		t.Errorf("newestHandshake = %d, want 1700000123", got)
	}
	if got := newestHandshake(""); got != 0 {
		t.Errorf("empty newestHandshake = %d, want 0", got)
	}
	if got := newestHandshake("garbage line\n"); got != 0 {
		t.Errorf("garbage newestHandshake = %d, want 0", got)
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("10.20.0.5:53"); got != "10.20.0.5" {
		t.Errorf("hostOf = %q", got)
	}
	if got := hostOf(""); got != "" {
		t.Errorf("hostOf empty = %q", got)
	}
}

func TestExitChecksTransportSelectsLink(t *testing.T) {
	probes := ExitProbes{
		HandshakeFresh: passing("hs"),
		RealityInbound: passing("reality"),
		WARPEgress:     passing("warp"),
	}
	base := domain.NodeSpec{
		Role: domain.RoleExit, Egress: domain.EgressWARP,
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
	}

	// AWG active ⇒ wg-handshake gates (no reality-inbound).
	awg := base
	awg.ActiveTransport = domain.TransportAWG
	if names := checkNames(ExitChecks(awg, probes)); !contains(names, "wg-handshake") || contains(names, "reality-inbound") {
		t.Errorf("awg-active: want wg-handshake (not reality-inbound), got %v", names)
	}

	// REALITY active ⇒ reality-inbound gates, wg-handshake is omitted (the AWG
	// standby has no handshake and would always fail).
	rxt := base
	rxt.ActiveTransport = domain.TransportRealityXHTTP
	if names := checkNames(ExitChecks(rxt, probes)); !contains(names, "reality-inbound") || contains(names, "wg-handshake") {
		t.Errorf("reality-active: want reality-inbound (not wg-handshake), got %v", names)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
