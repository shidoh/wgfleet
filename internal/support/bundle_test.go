package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeRunner struct{ out map[string]string }

func (f fakeRunner) Run(_ context.Context, cmd string) (string, error) {
	if v, ok := f.out[cmd]; ok {
		return v, nil
	}
	return "", errors.New("command not found: " + cmd)
}

// erroringRunner always fails with a fixed error string, standing in for
// execRunner.Run's real shape: `fmt.Errorf("%v: %s", err, output)` on a
// non-zero exit, where output can be a failed command's entire (possibly
// large, possibly multi-line) combined stdout+stderr.
type erroringRunner struct{ err string }

func (e erroringRunner) Run(_ context.Context, _ string) (string, error) {
	return "", errors.New(e.err)
}

func readArchive(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	files := map[string]string{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", h.Name, err)
		}
		files[h.Name] = string(b)
	}
	return files
}

// A collector that fails must not abort the bundle: a missing tool on a sender's
// box is expected, and a bundle that refuses to exist because `conntrack` is not
// installed is useless exactly when it is needed.
func TestCollectRecordsFailuresAndKeepsGoing(t *testing.T) {
	r := fakeRunner{out: map[string]string{"ip addr": "1: lo <LOOPBACK>"}}
	cs := []Collector{
		{File: "network.txt", Name: "addresses", Cmd: "ip addr"},
		{File: "network.txt", Name: "conntrack", Cmd: "conntrack -C"},
	}
	n, err := Collect(context.Background(), r, cs, Options{Node: "exit-de-1", Role: "exit"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	body := n.Files["network.txt"]
	if !strings.Contains(body, "1: lo <LOOPBACK>") {
		t.Error("successful collector output missing")
	}
	if !strings.Contains(body, "conntrack") || !strings.Contains(body, "command not found") {
		t.Error("failed collector must record its error in its own section")
	}
	if len(n.Entries) != 2 {
		t.Errorf("manifest entries = %d, want 2 (one per collector, including the failure)", len(n.Entries))
	}
}

// The size cap is a safety property, not a nicety: an unbounded log section is
// how a "small text bundle" becomes a gigabyte nobody can read or send.
func TestCollectTruncatesAnOversizedSection(t *testing.T) {
	huge := strings.Repeat("x\n", 100_000)
	r := fakeRunner{out: map[string]string{"journalctl": huge}}
	cs := []Collector{{File: "logs.txt", Name: "journal", Cmd: "journalctl"}}

	n, err := Collect(context.Background(), r, cs, Options{Node: "n1", Role: "exit", MaxSection: 4096})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := len(n.Files["logs.txt"]); got > 4096+512 {
		t.Errorf("section is %d bytes, want it capped near 4096", got)
	}
	if !strings.Contains(n.Files["logs.txt"], "truncated") {
		t.Error("a truncated section must say so — silent truncation reads as complete data")
	}
}

// A failing collector's error can carry the ENTIRE combined output of the
// command that failed (execRunner.Run's `fmt.Errorf("%v: %s", err, output)`
// on a non-zero exit — see `docker logs --tail 100 mihomo` in collectors.go).
// Before this fix, ManifestEntry.Err stored that whole string untouched:
// MANIFEST.txt's one-row-per-entry table broke on the first embedded
// newline, and the error escaped every size cap the rest of the archive is
// bound by. This pins both: the manifest's copy is collapsed to one line and
// capped, while the full error remains readable in the file's own section
// (which has its own, separate, much larger cap).
func TestCollectBoundsAndCollapsesManifestErr(t *testing.T) {
	huge := strings.Repeat("line-of-container-log\n", 50)
	r := erroringRunner{err: "exit status 1: " + huge}
	cs := []Collector{{File: "containers.txt", Name: "mihomo log", Cmd: "docker logs --tail 100 mihomo"}}

	n, err := Collect(context.Background(), r, cs, Options{Node: "master-1", Role: "master"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(n.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(n.Entries))
	}

	e := n.Entries[0]
	if strings.Contains(e.Err, "\n") {
		t.Errorf("ManifestEntry.Err contains a raw newline — it must be collapsed to fit MANIFEST.txt's one-row-per-entry table: %q", e.Err)
	}
	if len(e.Err) > maxManifestErr+64 { // +slack for the "...(truncated, N bytes dropped)" suffix
		t.Errorf("ManifestEntry.Err is %d bytes, want it capped near maxManifestErr (%d)", len(e.Err), maxManifestErr)
	}
	if !strings.Contains(e.Err, "truncated") {
		t.Error("a truncated manifest error must say so, not truncate silently")
	}

	if !strings.Contains(n.Files["containers.txt"], "line-of-container-log") {
		t.Error("the full error must still be readable in the file's own section")
	}
}

// The manifest copy of a failing collector's error must count toward the
// bundle's total-size accounting, same as the file section does — otherwise
// the total-size cap can be crossed several entries later than it should be,
// purely because the manifest was never charged for what it carries.
func TestCollectCountsManifestErrTowardTotal(t *testing.T) {
	r := erroringRunner{err: "boom"}
	cs := []Collector{
		{File: "a.txt", Name: "x", Cmd: "y"},      // header(12) + section(11) + manifestErr(4) = 27
		{File: "a.txt", Name: "second", Cmd: "z"}, // must be capped if the 27 above is fully counted
	}
	// 25 sits strictly between 23 (header+section alone) and 27 (with
	// manifestErr counted): the second collector runs under the old
	// accounting and is capped under the fixed accounting.
	n, err := Collect(context.Background(), r, cs, Options{Node: "n1", Role: "exit", MaxTotal: 25})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(n.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (first collector, then the bundle-cap stand-in for the second)", len(n.Entries))
	}
	if n.Entries[1].Name != "(bundle cap)" {
		t.Errorf("second entry = %+v, want the bundle-cap stand-in — ManifestEntry.Err must count toward `total` or the cap fires a collector too late", n.Entries[1])
	}
}

// WriteArchive keys nodes by Name only for sort order, never for identity —
// two nodes CAN share a Name (config validation only rejects duplicate
// *exit* names; nothing stops an operator naming an exit "controller", which
// collides with the hardcoded inventory node). A map[string]Node keyed on
// Name would silently keep only the LAST node assigned to that key, dropping
// the other's files entirely. Iterating the slice directly must keep both.
func TestWriteArchiveKeepsBothNodesWhenNamesCollide(t *testing.T) {
	nodes := []Node{
		{Name: "controller", Files: map[string]string{"inventory.txt": "controller inventory\n"}},
		{Name: "controller", Files: map[string]string{"identity.txt": "exit named controller\n"}},
	}
	var buf bytes.Buffer
	if err := WriteArchive(&buf, nodes, Meta{}); err != nil {
		t.Fatalf("WriteArchive: %v", err)
	}
	files := readArchive(t, buf.Bytes())
	if _, ok := files["controller/inventory.txt"]; !ok {
		t.Error("first same-named node's file is missing from the archive")
	}
	if _, ok := files["controller/identity.txt"]; !ok {
		t.Error("second same-named node's file is missing from the archive — a map keyed on Name would have collapsed one node into the other")
	}
}

// renderManifest must show the same "both nodes kept" behavior as
// WriteArchive — it has its own independent map-keyed-on-Name construction,
// so fixing one without the other would leave the manifest's own table
// silently dropping one same-named node's entries even if the tar were
// already correct.
func TestRenderManifestListsBothNodesWhenNamesCollide(t *testing.T) {
	nodes := []Node{
		{Name: "controller", Entries: []ManifestEntry{{File: "inventory.txt", Name: "fleet inventory", Bytes: 5}}},
		{Name: "controller", Entries: []ManifestEntry{{File: "identity.txt", Name: "hostname", Bytes: 7}}},
	}
	man := renderManifest(nodes, Meta{})
	if !strings.Contains(man, "controller/inventory.txt") {
		t.Error("manifest is missing the first same-named node's entry")
	}
	if !strings.Contains(man, "controller/identity.txt") {
		t.Error("manifest is missing the second same-named node's entry — a map keyed on Name would have collapsed one node into the other")
	}
}

// The manifest is the sender's index of what they are about to send. It must
// list every file actually in the archive, and the boundary of what was not
// collected, or "you can see what you send" is not true.
func TestWriteArchiveManifestMatchesContents(t *testing.T) {
	n := Node{
		Name:  "exit-de-1",
		Files: map[string]string{"network.txt": "addrs\n", "logs.txt": "lines\n"},
		Entries: []ManifestEntry{
			{File: "network.txt", Name: "addresses", Cmd: "ip addr", Bytes: 6},
			{File: "logs.txt", Name: "journal", Cmd: "journalctl", Bytes: 6},
		},
	}
	var buf bytes.Buffer
	meta := Meta{Note: "phone stopped loading sites", NotCollected: []string{"controller.yaml", "node.key"}}
	if err := WriteArchive(&buf, []Node{n}, meta); err != nil {
		t.Fatalf("WriteArchive: %v", err)
	}

	files := readArchive(t, buf.Bytes())
	man, ok := files["MANIFEST.txt"]
	if !ok {
		t.Fatal("archive has no MANIFEST.txt")
	}
	for _, want := range []string{
		"exit-de-1/network.txt", "exit-de-1/logs.txt", // every file, by archive path
		"ip addr", "journalctl", // the exact command behind each
		"phone stopped loading sites", // the operator note
		"controller.yaml", "node.key", // the NOT-collected boundary
	} {
		if !strings.Contains(man, want) {
			t.Errorf("manifest missing %q", want)
		}
	}
	for name := range files {
		if name == "MANIFEST.txt" {
			continue
		}
		if !strings.Contains(man, name) {
			t.Errorf("archive contains %s but the manifest does not list it", name)
		}
	}
}
