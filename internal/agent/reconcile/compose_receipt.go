package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
)

// composeBin is the docker binary the bring-up runs; tests swap it for true/false.
var composeBin = "docker"

// A compose file on disk records what SHOULD run, not what does. The `up -d` that
// applies it can be killed mid-pass (the agent restarted by a rollout) or fail (an
// image that will not pull), and on the next pass the file is unchanged and the
// OLD containers are running — a planner that only asks "did the file change"
// and "is the stack up" then never retries, leaving a master on the previous
// mihomo image after a rollout, with every check green.
//
// The receipt closes it: a file next to the compose file holding the hash of the
// content the last SUCCESSFUL `up -d` applied. No receipt, or one for different
// content, means the file has not been applied yet.

// composeReceiptPath is where the receipt for file lives.
func composeReceiptPath(file string) string { return file + ".applied" }

func composeDigest(rendered []byte) string {
	sum := sha256.Sum256(rendered)
	return hex.EncodeToString(sum[:])
}

// ComposeApplied reports whether the last successful `up -d` applied exactly
// rendered. Read-only, so a plan may call it.
func ComposeApplied(file string, rendered []byte) bool {
	got, err := os.ReadFile(composeReceiptPath(file))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(got)) == composeDigest(rendered)
}

func recordComposeApplied(file string, rendered []byte) {
	path := composeReceiptPath(file)
	if err := os.WriteFile(path, []byte(composeDigest(rendered)+"\n"), 0o644); err != nil {
		// Without the receipt the next pass repeats the up -d, which docker turns into
		// a no-op: noisy, not harmful. Say why it keeps happening.
		slog.Warn("could not record the applied compose file; the next pass repeats `docker compose up -d`",
			"path", path, "err", err)
	}
}

// ComposeUpAction is `docker compose -f file up -d` that records the receipt for
// rendered once the command has succeeded — never on a failure, so a bring-up
// that did not happen is retried on the next pass.
func ComposeUpAction(summary, file string, rendered []byte) Action {
	a := ExecAction(summary, composeBin, "compose", "-f", file, "up", "-d")
	a.Display = "docker compose -f " + file + " up -d"
	captured := append([]byte(nil), rendered...)
	return a.OnApplied(func() { recordComposeApplied(file, captured) })
}

// MarkComposeAppliedForTest records the receipt as a successful `up -d` would, so
// planner tests can model a stack that is already converged.
func MarkComposeAppliedForTest(file string, rendered []byte) { recordComposeApplied(file, rendered) }
