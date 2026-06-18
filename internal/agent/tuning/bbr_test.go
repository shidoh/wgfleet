package tuning

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func planWith(t *testing.T, vals map[string]string) string {
	t.Helper()
	p := bbrPlanner{read: func(path string) string { return vals[path] }}
	acts, err := p.Plan(context.Background(), domain.NodeSpec{})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, a := range acts {
		b.WriteString(string(a.Kind))
		b.WriteString(" ")
		b.WriteString(a.Summary)
		b.WriteString("\n")
	}
	return b.String()
}

func TestBBRAppliesWhenCubic(t *testing.T) {
	// A node on cubic with bbr not even loaded: modprobe + set cc + set qdisc.
	out := planWith(t, map[string]string{
		ccPath:    "cubic",
		availPath: "reno cubic",
		qdiscPath: "fq_codel",
	})
	for _, want := range []string{"load tcp_bbr module", "congestion control to bbr", "qdisc to fq"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestBBRSkipsWhenNoProcfs(t *testing.T) {
	// Non-Linux / unreadable /proc ⇒ a single NoChange, no exec (must never abort).
	out := planWith(t, map[string]string{}) // all reads return ""
	if strings.Contains(out, "exec") {
		t.Errorf("must not emit exec actions without /proc/sys:\n%s", out)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("expected NoChange 'unavailable' when /proc absent:\n%s", out)
	}
}

func TestBBRNoChangeWhenAlready(t *testing.T) {
	// Already bbr + fq + module loaded ⇒ no exec actions at all.
	out := planWith(t, map[string]string{
		ccPath:    "bbr",
		availPath: "reno cubic bbr",
		qdiscPath: "fq",
	})
	if strings.Contains(out, "exec") {
		t.Errorf("expected no exec actions when already tuned:\n%s", out)
	}
	for _, want := range []string{"already bbr", "already fq"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// modprobe must NOT run when bbr is already available.
	if strings.Contains(out, "modprobe") {
		t.Errorf("modprobe should be skipped when bbr is available:\n%s", out)
	}
}

func TestBBRLoadsModuleButCCAlreadyBBR(t *testing.T) {
	// cc already bbr (built-in) yet not listed as separate module: still fine, no modprobe.
	out := planWith(t, map[string]string{
		ccPath:    "bbr",
		availPath: "reno cubic bbr",
		qdiscPath: "fq_codel",
	})
	if !strings.Contains(out, "qdisc to fq") {
		t.Errorf("should still fix qdisc when only that differs:\n%s", out)
	}
}
