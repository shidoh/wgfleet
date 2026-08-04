// --support-bundle --fleet: the controller's read-only diagnostic bundle. It
// follows cmd/wgfleet-agent/support.go's ordering exactly (Collect → Scrub →
// Gate → only then create the file) and adds the two things only the
// controller can: an inventory rendered from its own store, and a walk over
// every exit's manifest SSH target using the same support.NodeCollectors the
// agent runs locally — one set of collectors, two entry points.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/support"
)

// sshDial opens a provisioner.Runner to an SSH target. Injectable so tests use
// a fake — the same seam provmgr.DialFunc uses — so no test in this package
// ever dials real SSH.
type sshDial func(domain.SSHTarget) (provisioner.Runner, error)

// supportFleetOpts configures one call to writeFleetSupportBundle.
type supportFleetOpts struct {
	Out   string              // archive path to write; must not exist until the gate passes
	Note  string              // tester's own description of the problem, scrubbed+gated then embedded in MANIFEST.txt
	Fleet config.FleetSection // the manifest's masters/exits; only Exits are walked over SSH
	Store store.Store         // nil ⇒ inventory records why (no store reachable)
	Dial  sshDial             // nil ⇒ provisioner.DialSSH

	// Secrets are the controller's own secret values Gate refuses to write
	// verbatim. See gatherControllerSecrets for what this covers and,
	// deliberately, does not.
	Secrets []string
}

// writeFleetSupportBundle collects the controller's inventory plus every
// exit's diagnostics, scrubs, gates ALL nodes together, and only then writes
// the archive. An unreachable exit or an unreadable store is not an error
// here: each becomes a Node whose one section records why, so the walk never
// aborts partway and the operator still gets everything that WAS reachable.
func writeFleetSupportBundle(ctx context.Context, opts supportFleetOpts) error {
	dial := opts.Dial
	if dial == nil {
		dial = func(t domain.SSHTarget) (provisioner.Runner, error) { return provisioner.DialSSH(t, nil) }
	}

	nodes := []support.Node{inventoryNode(ctx, opts.Store)}
	for _, e := range opts.Fleet.Exits {
		nodes = append(nodes, walkExit(ctx, e, dial))
	}

	// Defence in depth on the real collector output, exactly as the agent does.
	for i := range nodes {
		for f, body := range nodes[i].Files {
			nodes[i].Files[f] = support.Scrub(body)
		}
	}

	// --note is free-form text an operator types describing what a tester
	// reported — the same risk cmd/wgfleet-agent/support.go's regression test
	// pins: it never lives in node.Files, so without gating it separately it
	// would skip both Scrub and Gate.
	scrubbedNote := support.Scrub(opts.Note)

	// Gate ALL nodes together, in the SAME pass, before anything is written: one
	// node's leak must stop the whole archive. The note rides along via a
	// throwaway node that is never appended to `nodes` and never reaches
	// WriteArchive — it exists only so Gate's checks run over the note text too,
	// with a LeakError pointing at MANIFEST.txt, where the note actually lands.
	gateInput := append(append([]support.Node{}, nodes...), support.Node{
		Name:  "controller",
		Files: map[string]string{"MANIFEST.txt": scrubbedNote},
	})
	if err := support.Gate(gateInput, opts.Secrets); err != nil {
		return err
	}

	// Only now does anything touch disk.
	f, err := os.Create(opts.Out)
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

	return printBundleSummary(opts.Out)
}

// inventoryNode renders the controller's own view of the fleet: per node, its
// name, role, state, agent version, last seen, and drain/decommission flags —
// mgmt address is fine, no keys, no client list, nothing beyond what the
// dashboard already shows an operator. It runs through support.Collect (an
// Fn-backed Collector, so the Runner argument is never invoked) rather than
// hand-building a Node, so it goes through the exact same shape the exit walk
// does.
//
// A store that cannot be opened or read degrades to a Node whose one entry
// records why, rather than aborting the whole bundle: the store's own trouble
// must not cost the operator the fleet's exit diagnostics too.
func inventoryNode(ctx context.Context, st store.Store) support.Node {
	collectors := []support.Collector{{
		File: "inventory.txt",
		Name: "fleet inventory",
		Fn:   func(ctx context.Context) (string, error) { return renderInventory(ctx, st) },
	}}
	node, _ := support.Collect(ctx, nil, collectors, support.Options{Node: "controller", Role: "controller"})
	return *node
}

// renderInventory lists every node the store knows about, one line each. No
// address beyond mgmt, no public/session keys, no client list — a strict
// subset of what the Web UI dashboard already shows an operator.
func renderInventory(ctx context.Context, st store.Store) (string, error) {
	if st == nil {
		return "", fmt.Errorf("no store reachable")
	}
	nodes, err := st.ListNodes(ctx)
	if err != nil {
		return "", fmt.Errorf("list nodes: %w", err)
	}

	var b strings.Builder
	for _, n := range nodes {
		version := n.AgentVersion
		if version == "" {
			version = "-"
		}
		lastSeen := "-"
		if !n.LastSeen.IsZero() {
			lastSeen = n.LastSeen.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "name=%s\trole=%s\tstate=%s\tagent_version=%s\tmgmt_addr=%s\tlast_seen=%s\tdrain=%t\tdecommission=%t\n",
			n.Name, n.Role, n.State, version, n.MgmtAddr, lastSeen, n.Drain, n.Decommission)
	}
	return b.String(), nil
}

// walkExit dials one exit's manifest SSH target and runs the same collectors
// the agent runs locally, producing one support.Node. An exit with no SSH
// target configured, or one that fails to dial, is not a failure: it is a
// Node whose single section records why — the bundle is wanted precisely when
// something is down, and a walk that aborts on the first unreachable exit
// collects nothing on the day it matters.
func walkExit(ctx context.Context, e config.ExitConfig, dial sshDial) support.Node {
	if e.SSH.Host == "" || e.SSH.KeyPath == "" {
		return unreachableExit(e.Name, "no ssh target configured in the fleet manifest")
	}

	runner, err := dial(toSSHTarget(e.SSH))
	if err != nil {
		return unreachableExit(e.Name, fmt.Sprintf("ssh dial failed: %v", err))
	}
	defer func() { _ = runner.Close() }()

	node, _ := support.Collect(ctx, runner, support.NodeCollectors(string(domain.RoleExit)), support.Options{
		Node: e.Name,
		Role: string(domain.RoleExit),
	})
	return *node
}

// unreachableExit is the stanza an unreachable exit becomes: one file, one
// manifest entry, both naming why. It is deliberately NOT an error return —
// the whole point of the fleet walk is to keep going past the first exit that
// does not answer.
func unreachableExit(name, reason string) support.Node {
	body := fmt.Sprintf("== fleet walk ==\nexit %q was not reachable for this bundle: %s\n", name, reason)
	return support.Node{
		Name: name,
		Role: string(domain.RoleExit),
		Files: map[string]string{
			"unreachable.txt": body,
		},
		Entries: []support.ManifestEntry{{
			File: "unreachable.txt",
			Name: "fleet walk",
			Err:  reason,
		}},
	}
}

// toSSHTarget converts a manifest SSH target into the domain type the
// provisioner dials, expanding a leading ~ the same way every other dial path
// in this codebase does (os.ReadFile does not understand it).
func toSSHTarget(s config.SSHConfig) domain.SSHTarget {
	return domain.SSHTarget{
		Host: s.Host, Port: s.Port, User: s.User,
		KeyPath:               config.ExpandPath(s.KeyPath),
		HostKey:               s.HostKey,
		InsecureIgnoreHostKey: s.InsecureIgnoreHostKey,
	}
}

// bestEffortCA attempts to load the fleet CA for a diagnostic bundle's
// secret-gathering only. Unlike every other CA-dependent path in main.go, a
// support bundle must still be produced when this fails — a broken or
// missing CA is itself something the bundle should help diagnose, not
// something that blocks it. Failure is logged, not returned; the CA private
// key simply drops out of Gate's secret set (see gatherControllerSecrets).
func bestEffortCA(cfg *config.ControllerConfig) *pki.CA {
	provider, err := config.NewSecretProvider(context.Background(), cfg)
	if err != nil {
		slog.Warn("support bundle: could not init secret provider; CA key will not be in the gate's secret set", "err", err)
		return nil
	}
	ca, err := loadCA(cfg, provider)
	if err != nil {
		slog.Warn("support bundle: could not load CA; CA key will not be in the gate's secret set", "err", err)
		return nil
	}
	return ca
}

// runFleetSupportBundle handles `--support-bundle --fleet` end to end: the
// controller's own inventory plus a walk over every exit's manifest SSH
// target. The store is opened best-effort — a controller whose store cannot
// be opened still gets a bundle with the exit walk and a recorded reason for
// the inventory gap, rather than nothing at all.
func runFleetSupportBundle(cfg *config.ControllerConfig, ca *pki.CA, note string) error {
	var st store.Store
	sqliteStore, err := store.Open(cfg.Controller.Store)
	if err != nil {
		slog.Warn("support bundle: could not open store; inventory will record the gap", "err", err)
	} else {
		st = sqliteStore
		defer func() { _ = sqliteStore.Close() }()
	}

	out := fmt.Sprintf("wgfleet-support-fleet-%s.tar.gz", time.Now().UTC().Format("20060102T150405Z"))
	return writeFleetSupportBundle(context.Background(), supportFleetOpts{
		Out:     out,
		Note:    note,
		Fleet:   cfg.Fleet,
		Store:   st,
		Secrets: gatherControllerSecrets(cfg, ca),
	})
}

// gatherControllerSecrets collects secret material the CONTROLLER itself
// legitimately holds and can reach without SSH, for support.Gate's
// exact-match set: the fleet CA private key (re-derived in memory via
// ca.Marshal — never read from or written to disk here) and every exit's SSH
// bootstrap key (read from local disk; the controller dials exits with these,
// so it always has them locally regardless of whether any exit answers).
//
// Deliberately NOT covered, and not invented as a plausible substitute: an
// exit's own on-disk secrets (its WireGuard key, its xray key, its REALITY
// key, ...). Reading those back over SSH to check them would be collecting
// exactly the material this feature promises never to collect — the gap is
// real, and support.NotCollected() names it rather than this function
// papering over it with a guess. Likewise the web-panel admin credential
// (its stored form is a bcrypt hash and an HMAC signing key, not the raw
// password) and the derived per-tunnel master keys (ADR-0030) and the mihomo
// Clash API secret (operator-defined YAML, no fixed path) are out of reach
// here for the same reasons cmd/wgfleet-agent/support.go's gatherSecrets
// documents.
func gatherControllerSecrets(cfg *config.ControllerConfig, ca *pki.CA) []string {
	var out []string
	add := func(v string) {
		if v != "" {
			out = append(out, v)
		}
	}

	if ca != nil {
		if kp, err := ca.Marshal(); err == nil {
			add(strings.TrimSpace(string(kp.KeyPEM)))
		}
	}
	for _, e := range cfg.Fleet.Exits {
		add(readTrimmedFileController(config.ExpandPath(e.SSH.KeyPath)))
	}
	return out
}

func readTrimmedFileController(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// printBundleSummary shows the operator exactly what they are about to send:
// the archive path, every file with its real archived byte count (read back
// from the tar itself, not recomputed), and the commands to inspect or unpack
// it before sending it anywhere. Mirrors cmd/wgfleet-agent/support.go's
// printBundleSummary — kept as a separate copy since the two are independent
// `main` packages and this feature is Go-stdlib-only.
func printBundleSummary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reopen archive for summary: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("read archive for summary: %w", err)
	}
	defer gz.Close()

	fmt.Printf("support bundle written: %s\n\n", path)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive for summary: %w", err)
		}
		fmt.Printf("  %-40s %8d bytes\n", hdr.Name, hdr.Size)
	}
	fmt.Println()
	fmt.Println("Read it before sending it to anyone:")
	fmt.Printf("  tar tzf %s\n", path)
	fmt.Printf("  tar xzf %s\n", path)
	return nil
}
