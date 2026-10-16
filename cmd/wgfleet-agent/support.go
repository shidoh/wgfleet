// --support-bundle: a read-only diagnostic archive a beta tester can send to a
// maintainer with no access to their servers. Everything in it is plain text,
// and it is built so a refusal (a secret would leak) leaves nothing on disk.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/exit"
	"github.com/shidoh/wgfleet/internal/agent/master"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/support"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

// supportCommandTimeout bounds every collector command. Collectors shell out to
// things that can wedge (docker, zerotier-cli) with no timeout of their own, and
// a wedged host is exactly when a tester runs this — one hung command must not
// stall the whole bundle. Every command in NodeCollectors normally completes in
// well under a second on a live host; this leaves generous headroom for a loaded
// box while still bounding a truly hung daemon.
//
// supportCommandWaitDelay bounds how long Cmd.Wait keeps blocking, after the
// process group has been killed, for the I/O copy goroutines to notice the
// pipes closed — see the Setpgid/Cancel comment below for why this matters.
const (
	supportCommandTimeout   = 10 * time.Second
	supportCommandWaitDelay = 2 * time.Second
)

// execRunner runs a collector's command locally via sh -c, implementing
// support.Runner. A non-zero exit becomes an error carrying the combined
// output (Collect records err.Error() as the section body on failure), and a
// command that outruns its timeout is reported as a timeout the same way — so
// a wedged docker/zerotier-cli daemon shows up as one failed section, not a
// hung bundle.
type execRunner struct {
	// timeout bounds each command; zero (the production zero-value execRunner{}
	// used everywhere in this file) means supportCommandTimeout. It exists as a
	// field, not just the const, so a test can drive it down to ~100ms and
	// prove the group-kill below actually cuts a hung command off — without
	// waiting out the real 10s production bound to do it.
	timeout time.Duration
}

func (r execRunner) Run(ctx context.Context, cmd string) (string, error) {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = supportCommandTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := exec.CommandContext(cctx, "sh", "-c", cmd)
	// Run in its own process group and kill THAT (not just the immediate `sh`)
	// on timeout. exec.CommandContext's default Cancel only signals the direct
	// child; a compound/piped shell command (or a tool like docker/zerotier-cli
	// that forks a helper) can leave a grandchild running after `sh` itself
	// dies, and that grandchild keeps stdout/stderr's write end open — so
	// CombinedOutput blocks reading until IT exits, on its own schedule, long
	// after the deadline supposedly cut the command off. Verified live: without
	// this, `sleep 30` run through `sh -c` took the full 30s to return despite
	// a 10s timeout, because `sh`'s child `sleep` was orphaned instead of
	// killed. Setpgid+group-kill closes that hole; WaitDelay is the backstop in
	// case some descendant still doesn't die (e.g. one that ignores SIGKILL
	// briefly, or a namespace quirk) so Wait itself cannot hang past it either.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	}
	c.WaitDelay = supportCommandWaitDelay

	out, err := c.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("timed out after %s", timeout)
	}
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// supportSection is an in-process section, appended after the real collectors
// run. Production never sets any; extra exists so a test can inject a section
// without a real collector — it is what let Task 4's leak test simulate "a
// collector emitted a value the node declares secret" without shelling out.
type supportSection struct {
	File string
	Name string
	Body string
}

// supportOpts configures one call to writeSupportBundle.
type supportOpts struct {
	Out     string   // archive path to write; must not exist until the gate passes
	Node    string   // node id, becomes the archive's <node>/ directory
	Role    string   // "master" or "exit" — selects NodeCollectors
	Note    string   // tester's own description of the problem, scrubbed+gated then embedded in MANIFEST.txt
	Secrets []string // this node's own secret values; Gate refuses if any appears verbatim

	// extra is a test seam: production passes none.
	extra []supportSection
}

// writeSupportBundle collects, scrubs, gates, and only then writes the archive.
// Order matters: the output file is created after Gate passes, never before, so
// a refusal leaves nothing on disk for a tester to send by accident.
func writeSupportBundle(ctx context.Context, opts supportOpts) error {
	collectors := support.NodeCollectors(opts.Role)
	node, err := support.Collect(ctx, execRunner{}, collectors, support.Options{
		Node: opts.Node,
		Role: opts.Role,
	})
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}

	// Defence in depth on the real collector output. Collect's allowlist (what
	// commands run at all) is the actual guarantee; Scrub masks anything
	// secret-shaped that slipped through in uncontrolled text (container logs).
	for f, body := range node.Files {
		node.Files[f] = support.Scrub(body)
	}

	// Appended AFTER Scrub, deliberately unscrubbed: extra simulates a collector's
	// raw output reaching Gate, which is what the leak test exercises. Scrubbing
	// it here would mask the very value the test injects and the gate would never
	// see anything to refuse.
	for _, s := range opts.extra {
		node.Files[s.File] += fmt.Sprintf("== %s ==\n", s.Name) + s.Body + "\n"
		node.Entries = append(node.Entries, support.ManifestEntry{File: s.File, Name: s.Name, Bytes: len(s.Body)})
	}

	// Same defence in depth for MANIFEST.txt as node.Files above: Collect
	// already bounds and collapses ManifestEntry.Err to one line (see
	// collapseManifestErr), but a failing collector's error text can still
	// carry the failed command's raw combined output verbatim — the one
	// place collected output otherwise reached Gate unmasked. Cmd is a
	// static string per collector and never secret-shaped today, but
	// scrubbing it too costs nothing when the input is already known safe,
	// and means a future collector whose Cmd embeds a value cannot become a
	// silent exception to this pass. Must run before Gate, same as Files.
	for i := range node.Entries {
		node.Entries[i].Cmd = support.Scrub(node.Entries[i].Cmd)
		node.Entries[i].Err = support.Scrub(node.Entries[i].Err)
	}

	// --note is free-form text a tester types (or pastes) describing what went
	// wrong — the single likeliest place someone drops a key or a config
	// fragment without meaning to. It never lives in node.Files (it is embedded
	// directly into MANIFEST.txt's header via Meta.Note below), so without this
	// it would skip both Scrub and Gate entirely: found by review, reproduced
	// against the first version of this file (a secret pasted into --note
	// shipped in MANIFEST.txt with the gate reporting no error), fixed here.
	scrubbedNote := support.Scrub(opts.Note)

	nodes := []support.Node{*node}

	// Gate the note in the SAME pass as the real nodes, via a throwaway node
	// that is never appended to `nodes` and never reaches WriteArchive — it
	// exists only so Gate's exact-secret-match and secret-key-name checks run
	// over the note text too. Its File is named "MANIFEST.txt" (matching where
	// the note actually lands) so a refusal's LeakError points at the real
	// destination, not an invented one.
	gateInput := append(append([]support.Node{}, nodes...), support.Node{
		Name:  opts.Node,
		Files: map[string]string{"MANIFEST.txt": scrubbedNote},
	})
	if err := support.Gate(gateInput, opts.Secrets); err != nil {
		return err
	}

	// Only now does anything touch disk. 0600, not os.Create's default
	// (0666 & umask, typically 0644): the archive carries no secrets by
	// construction, but journal tails and nftables rulesets are not
	// something to leave world-readable on a shared box.
	f, err := os.OpenFile(opts.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	meta := support.Meta{
		Note:         scrubbedNote,
		NotCollected: support.NotCollected(),
		CreatedAt:    time.Now().UTC(),
	}
	if err := support.WriteArchive(f, nodes, meta); err != nil {
		_ = f.Close()
		_ = os.Remove(opts.Out)
		return fmt.Errorf("write archive: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(opts.Out)
		return fmt.Errorf("close archive: %w", err)
	}

	return support.PrintBundleSummary(opts.Out)
}

// runSupportBundle handles --support-bundle end to end. It deliberately never
// dials the controller: a wedged node with no controller reachability is
// exactly when a tester needs this bundle, so the flag must not depend on the
// connection that may be exactly what is broken. See gatherSecrets for what
// that means for the gate's coverage.
func runSupportBundle(role domain.Role, paths exit.Paths, stateDir, nodeID, note string) error {
	mp := master.DefaultPaths()
	if stateDir != "" {
		mp = master.PathsUnder(stateDir)
	}

	out := fmt.Sprintf("wgfleet-support-%s-%s.tar.gz", nodeID, time.Now().UTC().Format("20060102T150405Z"))
	return writeSupportBundle(context.Background(), supportOpts{
		Out:     out,
		Node:    nodeID,
		Role:    string(role),
		Note:    note,
		Secrets: gatherSecrets(role, paths, mp),
	})
}

// gatherSecrets collects this node's own persisted secret material for
// support.Gate's exact-match set. It only reads what is already on disk — it
// never generates a key, so a node with nothing persisted yet simply
// contributes nothing to check (there is nothing on disk yet that could leak
// it either).
//
// Deliberately NOT included here, and not invented as a plausible substitute:
//
//   - The derived per-tunnel master keys (ADR-0030). Deriving one requires the
//     exit-tunnel list from the pulled NodeSpec (wg.DeriveTunnelKey(masterKey,
//     tunnelName) — see internal/agent/exit/planners.go / main.go
//     publishTunnelKeys), and PullSpec needs a live mTLS session with the
//     controller. Requiring that here would make --support-bundle depend on the
//     very reachability a wedged host may have lost.
//   - The mihomo Clash API secret. It lives inside the operator's free-form
//     mihomo config overrides (internal/mihomo/render.go, merged from
//     spec.Master.Custom.Overrides["secret"]) with no fixed key path of its
//     own — reading it back reliably needs either a YAML parse of a file whose
//     shape is entirely operator-defined, or trusting a location that might not
//     hold it. Either is a guess dressed up as coverage, which is worse than
//     reporting the gap plainly.
func gatherSecrets(role domain.Role, paths exit.Paths, mp master.Paths) []string {
	var out []string
	add := func(v string) {
		if v != "" {
			out = append(out, v)
		}
	}

	add(readTrimmedFile(paths.WGKey))
	if role == domain.RoleExit {
		add(readTrimmedFile(paths.XrayKey))
	}
	if role == domain.RoleMaster {
		add(readTrimmedFile(paths.ClientVLESSKey))
		add(readTrimmedFile(mp.RealityPortalKey))
		if pass, err := wgeasy.ReadAdminPassword(mp.WGEasyAdmin); err == nil {
			add(pass)
		}
	}
	return out
}

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
