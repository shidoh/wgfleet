// Package support builds a read-only diagnostic bundle a beta tester can send
// without sending secrets. Everything it emits is plain text, and the archive
// records both what it collected and what it deliberately did not.
package support

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// DefaultMaxSection and DefaultMaxTotal bound the archive. Logs are the risk:
// unbounded, a "small text bundle" becomes something nobody can read or send.
const (
	DefaultMaxSection = 256 << 10 // 256 KiB per section
	DefaultMaxTotal   = 8 << 20   // 8 MiB across all sections
)

// Runner executes a shell command and returns its combined output. Implemented
// locally by the agent and over SSH by the controller's fleet walk, so one set
// of collectors serves both.
type Runner interface {
	Run(ctx context.Context, cmd string) (string, error)
}

// Collector is one named observation. Cmd is recorded verbatim in the manifest
// so the tester can see exactly what was run. Fn overrides Cmd for sections
// produced in-process (the plan output, the metrics scrape); exactly one of the
// two is set.
type Collector struct {
	File string
	Name string
	Cmd  string
	Fn   func(ctx context.Context) (string, error)
}

// Options configures one node's collection.
type Options struct {
	Node       string
	Role       string
	MaxSection int // 0 ⇒ DefaultMaxSection
	MaxTotal   int // 0 ⇒ DefaultMaxTotal
}

// ManifestEntry is the manifest's record of one collector's result.
type ManifestEntry struct {
	File  string
	Name  string
	Cmd   string
	Bytes int
	Err   string
}

// Node is one node's collected files plus the manifest entries describing them.
type Node struct {
	Name    string
	Role    string
	Files   map[string]string
	Entries []ManifestEntry
}

// Meta is archive-level context: the tester's own description of the problem and
// the explicit boundary of what was not collected.
type Meta struct {
	Note         string
	NotCollected []string
	CreatedAt    time.Time
}

// Collect runs each collector in order against r, appending each section to
// Files[File] and recording a ManifestEntry for every collector, including
// failures. A failing collector does not stop collection: a missing tool on a
// tester's box is expected, and the bundle must exist anyway.
func Collect(ctx context.Context, r Runner, cs []Collector, opt Options) (*Node, error) {
	maxSection := opt.MaxSection
	if maxSection <= 0 {
		maxSection = DefaultMaxSection
	}
	maxTotal := opt.MaxTotal
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotal
	}

	n := &Node{
		Name:  opt.Node,
		Role:  opt.Role,
		Files: map[string]string{},
	}

	total := 0
	capped := false

	for _, c := range cs {
		if capped {
			break
		}

		if total >= maxTotal {
			n.Entries = append(n.Entries, ManifestEntry{
				File: c.File,
				Name: "(bundle cap)",
				Cmd:  "",
				Err:  fmt.Sprintf("stopped collecting: total bundle size reached %d bytes", maxTotal),
			})
			capped = true
			break
		}

		body, errStr := runCollector(ctx, r, c)

		section := body
		if errStr != "" {
			section = "ERROR: " + errStr
		}

		truncatedBytes := 0
		if len(section) > maxSection {
			truncatedBytes = len(section) - maxSection
			section = section[:maxSection] + fmt.Sprintf("\n... truncated (%d bytes dropped) ...\n", truncatedBytes)
		}

		header := fmt.Sprintf("== %s ==\n$ %s\n", c.Name, c.Cmd)
		n.Files[c.File] += header + section + "\n"

		total += len(header) + len(section)

		n.Entries = append(n.Entries, ManifestEntry{
			File:  c.File,
			Name:  c.Name,
			Cmd:   c.Cmd,
			Bytes: len(section),
			Err:   errStr,
		})
	}

	return n, nil
}

// runCollector executes a single collector, preferring Fn over Cmd (exactly one
// of the two is set on any Collector), and returns the raw body plus an error
// string (empty on success).
func runCollector(ctx context.Context, r Runner, c Collector) (body string, errStr string) {
	var out string
	var err error
	if c.Fn != nil {
		out, err = c.Fn(ctx)
	} else {
		out, err = r.Run(ctx, c.Cmd)
	}
	if err != nil {
		return "", err.Error()
	}
	return out, ""
}

// WriteArchive emits a gzip+tar archive to w: MANIFEST.txt first, then each
// node's files under <node>/<file>. Map keys are iterated in sorted order so
// the same input produces a byte-identical archive.
func WriteArchive(w io.Writer, nodes []Node, meta Meta) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	manifest := renderManifest(nodes, meta)
	if err := writeTarFile(tw, "MANIFEST.txt", manifest); err != nil {
		return err
	}

	nodeNames := make([]string, len(nodes))
	byName := make(map[string]Node, len(nodes))
	for i, n := range nodes {
		nodeNames[i] = n.Name
		byName[n.Name] = n
	}
	sort.Strings(nodeNames)

	for _, name := range nodeNames {
		n := byName[name]
		fileNames := make([]string, 0, len(n.Files))
		for f := range n.Files {
			fileNames = append(fileNames, f)
		}
		sort.Strings(fileNames)

		for _, f := range fileNames {
			path := n.Name + "/" + f
			if err := writeTarFile(tw, path, n.Files[f]); err != nil {
				return err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// PrintBundleSummary shows the operator exactly what they are about to send:
// the archive path, every file with its real archived byte count (read back
// from the tar itself, not recomputed), and the commands to inspect or unpack
// it before sending it anywhere. Shared by both entry points — the agent's
// local bundle and the controller's fleet bundle — so this transparency
// promise has one implementation, not two copies that can drift.
func PrintBundleSummary(path string) error {
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

func writeTarFile(tw *tar.Writer, name, body string) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0o644,
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := io.WriteString(tw, body)
	return err
}

// renderManifest builds the tester's index: created-at, the note, a table of
// <node>/<file>, collector name, command, byte count and any error, and a
// final NOT COLLECTED section listing the deliberate boundary.
func renderManifest(nodes []Node, meta Meta) string {
	var b strings.Builder

	createdAt := meta.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	fmt.Fprintf(&b, "created-at: %s\n", createdAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "note: %s\n\n", meta.Note)

	nodeNames := make([]string, len(nodes))
	byName := make(map[string]Node, len(nodes))
	for i, n := range nodes {
		nodeNames[i] = n.Name
		byName[n.Name] = n
	}
	sort.Strings(nodeNames)

	for _, name := range nodeNames {
		n := byName[name]
		entries := append([]ManifestEntry(nil), n.Entries...)
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].File != entries[j].File {
				return entries[i].File < entries[j].File
			}
			return entries[i].Name < entries[j].Name
		})
		for _, e := range entries {
			path := n.Name + "/" + e.File
			line := fmt.Sprintf("%s\tname=%s\tcmd=%s\tbytes=%d", path, e.Name, e.Cmd, e.Bytes)
			if e.Err != "" {
				line += "\terror=" + e.Err
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	b.WriteString("\nNOT COLLECTED\n")
	for _, nc := range meta.NotCollected {
		b.WriteString(nc)
		b.WriteString("\n")
	}

	return b.String()
}
