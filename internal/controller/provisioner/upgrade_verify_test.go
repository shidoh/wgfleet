package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/version"
)

func upgradeInput(bin []byte) BootstrapInput {
	return BootstrapInput{Node: domain.Node{Name: "anz3", Role: domain.RoleExit}, AgentBinary: bin}
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// stepSummaries renders a plan's step summaries for order assertions.
func stepSummaries(p Plan) []string {
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, s.Summary)
	}
	return out
}

func indexOfStep(p Plan, substr string) int {
	for i, s := range stepSummaries(p) {
		if strings.Contains(s, substr) {
			return i
		}
	}
	return -1
}

// The whole point of the digest check is that it runs while the OLD binary is
// still the one systemd would start. Verifying after the restart would mean the
// truncated binary had already been launched.
func TestUpgradePlanVerifiesBeforeRestarting(t *testing.T) {
	p := BuildUpgradePlan(upgradeInput([]byte("agent-binary")))

	snapshot := indexOfStep(p, "snapshot current agent binary")
	upload := indexOfStep(p, "upload wgfleet-agent binary")
	verify := indexOfStep(p, "verify uploaded binary sha256")
	restart := indexOfStep(p, "restart agent")

	for name, idx := range map[string]int{
		"snapshot": snapshot, "upload": upload, "verify": verify, "restart": restart,
	} {
		if idx < 0 {
			t.Fatalf("upgrade plan has no %s step: %v", name, stepSummaries(p))
		}
	}
	if !(snapshot < upload && upload < verify && verify < restart) {
		t.Fatalf("steps out of order (snapshot=%d upload=%d verify=%d restart=%d): %v",
			snapshot, upload, verify, restart, stepSummaries(p))
	}
}

func TestUpgradeAcceptsAnIntactUpload(t *testing.T) {
	bin := []byte("a good agent binary")
	r := NewMockRunner()
	r.PrefixResponses["sha256sum"] = digestOf(bin) + "  " + remoteAgentBin

	if _, err := quietProvisioner().Upgrade(context.Background(), r, upgradeInput(bin), ModeApply); err != nil {
		t.Fatalf("Upgrade on an intact upload failed: %v", err)
	}
	if !r.RanCommand("systemctl restart wgfleet-agent") {
		t.Error("agent was never restarted after a good upload")
	}
}

// The real incident: an interrupted transfer left a truncated binary that every
// command reported as success, and the service SEGV-crash-looped.
func TestUpgradeAbortsAndDoesNotRestartOnDigestMismatch(t *testing.T) {
	bin := []byte("the full agent binary")
	truncated := digestOf([]byte("the full agent bin")) // what actually landed

	r := NewMockRunner()
	r.PrefixResponses["sha256sum"] = truncated + "  " + remoteAgentBin

	_, err := quietProvisioner().Upgrade(context.Background(), r, upgradeInput(bin), ModeApply)
	if err == nil {
		t.Fatal("Upgrade accepted a corrupt upload")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error %q does not name the corruption", err)
	}
	if r.RanCommand("systemctl restart wgfleet-agent") {
		t.Fatal("agent was restarted into a binary that failed verification")
	}
}

func TestUpgradeFailsWhenTheDigestCannotBeTaken(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
	}{
		{name: "sha256sum missing", out: "sha256sum: not found", err: errors.New("exit 127")},
		{name: "empty output", out: "", err: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin := []byte("binary")
			r := NewMockRunner()
			cmd := "sha256sum '" + remoteAgentBin + "'"
			r.Responses[cmd] = tc.out
			if tc.err != nil {
				r.Errors[cmd] = tc.err
			}
			if _, err := quietProvisioner().Upgrade(context.Background(), r, upgradeInput(bin), ModeApply); err == nil {
				t.Fatal("an unverifiable binary was accepted")
			}
			if r.RanCommand("systemctl restart wgfleet-agent") {
				t.Error("agent restarted despite an unverifiable binary")
			}
		})
	}
}

func TestUpgradePlanModeTouchesNothing(t *testing.T) {
	r := NewMockRunner()
	if _, err := quietProvisioner().Upgrade(context.Background(), r, upgradeInput([]byte("bin")), ModePlan); err != nil {
		t.Fatalf("plan mode: %v", err)
	}
	if len(r.Ran) != 0 || len(r.Uploaded) != 0 {
		t.Fatalf("plan mode mutated the node: ran=%v uploaded=%v", r.Ran, r.Uploaded)
	}
}

// --- rollback ---------------------------------------------------------------

func TestRollbackRestoresTheSnapshotAndRestarts(t *testing.T) {
	r := NewMockRunner()
	if _, err := quietProvisioner().Rollback(context.Background(), r, "anz3", ModeApply); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !r.RanCommand("cp -f '" + remoteAgentBinPrev + "'") {
		t.Errorf("previous binary was not restored; ran %v", r.Ran)
	}
	if !r.RanCommand("systemctl restart wgfleet-agent") {
		t.Error("agent was not restarted after the restore")
	}
}

// Restarting a node onto a snapshot that is not there would just relaunch the
// broken binary and report success.
func TestRollbackRefusesWithoutASnapshot(t *testing.T) {
	r := NewMockRunner()
	r.Errors["test -s '"+remoteAgentBinPrev+"'"] = errors.New("exit 1")

	_, err := quietProvisioner().Rollback(context.Background(), r, "anz3", ModeApply)
	if err == nil {
		t.Fatal("rollback succeeded with no snapshot present")
	}
	if r.RanCommand("systemctl restart wgfleet-agent") {
		t.Error("agent restarted despite having nothing to roll back to")
	}
}

// --- version probe ----------------------------------------------------------

func TestParseAgentVersion(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
		bad  bool
	}{
		{
			name: "tagged release keeps version+commit",
			out:  "wgfleet-agent v1.2.3 (commit abc1234, built 2026-07-19T10:00:00Z, go1.24)",
			want: "v1.2.3+abc1234",
		},
		{
			name: "untagged build collapses to the commit",
			out:  "wgfleet-agent fe60db2 (commit fe60db2, built 2026-07-19T10:00:00Z, go1.24)",
			want: "fe60db2",
		},
		{
			name: "dirty tree keeps the dirty marker",
			out:  "wgfleet-agent fe60db2 (commit fe60db2-dirty, built 2026-07-19T10:00:00Z, go1.24)",
			want: "fe60db2-dirty",
		},
		{
			name: "unstamped dev build has no commit",
			out:  "wgfleet-agent dev (commit none, built unknown, go1.24)",
			want: "dev",
		},
		{
			name: "trailing wire-contract line is ignored",
			out:  "wgfleet-agent v2 (commit deadbee, built x, go1.24)\nwire-contract version 3\n",
			want: "v2+deadbee",
		},
		{name: "unrelated output is rejected", out: "bash: wgfleet-agent: not found", bad: true},
		{name: "empty output is rejected", out: "", bad: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAgentVersion(tc.out)
			if tc.bad {
				if err == nil {
					t.Fatalf("parsed %q as %q, want an error", tc.out, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAgentVersion(%q): %v", tc.out, err)
			}
			if got != tc.want {
				t.Errorf("parseAgentVersion(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

func TestProbeAgentVersionReadsTheBinaryOnTheNode(t *testing.T) {
	r := NewMockRunner()
	r.PrefixResponses["'"+remoteAgentBin+"' --version"] = "wgfleet-agent v9 (commit cafe123, built x, go1.24)"

	got, err := ProbeAgentVersion(context.Background(), r)
	if err != nil {
		t.Fatalf("ProbeAgentVersion: %v", err)
	}
	if want := "v9+cafe123"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A binary that is the right size and digest but cannot execute (wrong arch)
// must fail here, not be inferred later from the node going silent.
func TestProbeAgentVersionFailsWhenTheBinaryCannotRun(t *testing.T) {
	r := NewMockRunner()
	r.Errors["'"+remoteAgentBin+"' --version"] = errors.New("exec format error")

	if _, err := ProbeAgentVersion(context.Background(), r); err == nil {
		t.Fatal("expected an error when the uploaded binary cannot execute")
	}
}

// TestProbeLocalAgentVersionReadsTheBinaryOnDisk covers the local sibling of
// ProbeAgentVersion. A rolling upgrade selects nodes against this value, so it
// must be the identity of the binary that will actually be pushed — reading it
// from anywhere else is what let a rollout "succeed" while installing the
// version each node already had.
func TestProbeLocalAgentVersionReadsTheBinaryOnDisk(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "wgfleet-agent")
	script := "#!/bin/sh\necho 'wgfleet-agent v0.1.5-8-g3ae9df0 (commit 3ae9df0, built 2026-07-27T10:35:22Z, go1.26.5)'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake agent: %v", err)
	}

	got, err := ProbeLocalAgentVersion(context.Background(), bin)
	if err != nil {
		t.Fatalf("ProbeLocalAgentVersion: %v", err)
	}
	if want := version.ShortOf("v0.1.5-8-g3ae9df0", "3ae9df0"); got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
}

// A binary that cannot run must report an error, not an empty version — an empty
// want would silently select every node in the fleet.
func TestProbeLocalAgentVersionErrorsOnAnUnrunnableBinary(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "not-an-agent")
	if err := os.WriteFile(bad, []byte("not executable content"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := ProbeLocalAgentVersion(context.Background(), bad); err == nil {
		t.Errorf("expected an error, got version %q", got)
	}
}
