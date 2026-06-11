package wg

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestDeriveAWGParamsValid(t *testing.T) {
	for _, seed := range []string{"a|b|", "exit-de-1|master-xa-1|salt", "x", ""} {
		p := DeriveAWGParams(seed)
		if err := p.Validate(); err != nil {
			t.Errorf("seed %q produced invalid AWG params: %v", seed, err)
		}
	}
}

func TestDeriveAWGDeterministic(t *testing.T) {
	seed := "exit-de-1|master-xa-1|salt"
	a := DeriveAWGShared(seed)
	b := DeriveAWGShared(seed)
	if a != b {
		t.Fatalf("same seed must yield identical shared params:\n%+v\n%+v", a, b)
	}
}

func TestDeriveAWGDiffersBySeed(t *testing.T) {
	if DeriveAWGShared("tunnel-1") == DeriveAWGShared("tunnel-2") {
		t.Fatal("different seeds should yield different params")
	}
}

func TestTunnelSeedOrderIndependent(t *testing.T) {
	if TunnelSeed("master-xa-1", "exit-de-1", "s") != TunnelSeed("exit-de-1", "master-xa-1", "s") {
		t.Fatal("TunnelSeed must be order-independent")
	}
	if DeriveAWGShared(TunnelSeed("a", "b", "salt")) != DeriveAWGShared(TunnelSeed("b", "a", "salt")) {
		t.Fatal("both tunnel ends must derive identical shared AWG params")
	}
}

func TestDeriveAWGHeaderRangesNonOverlapping(t *testing.T) {
	// Exercise many seeds; the generated header ranges must always be valid and
	// non-overlapping (the band partition guarantees it).
	for i := 0; i < 1000; i++ {
		p := DeriveAWGParams(string(rune(i)) + "-seed")
		if err := p.Validate(); err != nil {
			t.Fatalf("seed %d invalid: %v", i, err)
		}
	}
}

// TestDeriveSignaturesAlwaysGenerated verifies every end gets all five I-packets
// and they are valid CPS templates, across many seeds and both tag profiles.
func TestDeriveSignaturesAlwaysGenerated(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := string(rune(i)) + "-tunnel"
		for _, kernel := range []bool{true, false} {
			loc := DeriveAWGLocal(seed, kernel)
			sigs := []string{loc.I1, loc.I2, loc.I3, loc.I4, loc.I5}
			for k, s := range sigs {
				if s == "" {
					t.Fatalf("seed %q kernel=%v: I%d is empty", seed, kernel, k+1)
				}
				if !strings.HasPrefix(s, "<b 0x") {
					t.Fatalf("seed %q I%d missing literal prefix: %q", seed, k+1, s)
				}
			}
		}
	}
}

// TestKernelVsUserspaceTags confirms userspace signatures never use <c>/<t> while
// kernel signatures may, and both validate under the matching domain check.
func TestKernelVsUserspaceTags(t *testing.T) {
	const seed = "exit-de-1|master-xa-1|salt"

	// Userspace: must pass ValidateUserspace and contain no <c>/<t>.
	us := domain.AWGParams{Shared: DeriveAWGShared(seed), Local: DeriveAWGLocal(seed+"|end|master", false)}
	if err := us.ValidateUserspace(); err != nil {
		t.Fatalf("userspace params must validate: %v", err)
	}

	// Kernel: must pass the kernel Validate. Search enough seeds to observe at
	// least one <c>/<t> tag — proving the kernel profile actually emits them.
	sawKernelTag := false
	for i := 0; i < 200 && !sawKernelTag; i++ {
		s := DeriveAWGShared(seed)
		loc := DeriveAWGLocal(seed+"|k"+string(rune(i)), true)
		kp := domain.AWGParams{Shared: s, Local: loc}
		if err := kp.Validate(); err != nil {
			t.Fatalf("kernel params must validate: %v", err)
		}
		joined := loc.I1 + loc.I2 + loc.I3 + loc.I4 + loc.I5
		if strings.Contains(joined, "<c>") || strings.Contains(joined, "<t>") {
			sawKernelTag = true
			// That same template, treated as userspace, must be rejected.
			if err := kp.ValidateUserspace(); err == nil {
				t.Fatal("kernel <c>/<t> signature must fail ValidateUserspace")
			}
		}
	}
	if !sawKernelTag {
		t.Fatal("kernel profile never produced a <c>/<t> tag across 200 seeds")
	}
}

// TestDeriveEndsDifferButShareShared checks the two ends of one tunnel agree on
// shared params yet carry their own signatures, and that generation is stable.
func TestDeriveEndsDifferButShareShared(t *testing.T) {
	seed := TunnelSeed("exit-de-1", "master-xa-1", awgTestSalt)
	exit := DeriveAWGParamsForEnd(seed, "exit", true)
	master := DeriveAWGParamsForEnd(seed, "master", false)

	if exit.Shared != master.Shared {
		t.Fatal("both ends must share identical S/H params")
	}
	if exit.Local.I1 == master.Local.I1 {
		t.Fatal("the two ends should derive distinct I1 signatures")
	}
	// Idempotent: same inputs ⇒ same output (no reconcile churn).
	if again := DeriveAWGParamsForEnd(seed, "exit", true); again.Local != exit.Local {
		t.Fatal("DeriveAWGParamsForEnd must be deterministic")
	}
}

const awgTestSalt = "wgfleet-awg-v1"
