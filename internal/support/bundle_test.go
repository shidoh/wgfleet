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

// A collector that fails must not abort the bundle: a missing tool on a tester's
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

// The manifest is the tester's index of what they are about to send. It must
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
