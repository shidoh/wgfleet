// Package atomicfile writes a file so that a reader never sees a half-written one.
//
// It exists because the same few lines were written correctly in one place and
// carelessly in five others, and the difference only shows on the day a node loses
// power mid-write. The correct copy lived in the certificate renewer, with a
// comment explaining exactly why the fsync matters for the node's identity — and
// the node's WireGuard key, its REALITY key and its client key were written with a
// bare os.WriteFile a few files away.
//
// What a torn write costs is not a lost file but a stuck node: a zero-length key
// still EXISTS, so the code that generates one when it is missing never runs
// again, and every pass fails on a key that cannot be parsed until somebody
// deletes it by hand.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// syncDir fsyncs a directory so a rename inside it is durable. A variable so a
// test can observe that the step happens at all: its absence is invisible in the
// result — the file is right there, correct, until the power cut that the sync
// exists for.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Write puts data at path via a temporary file in the same directory, fsynced
// before the rename, and fsyncs the directory after it. Same directory because a
// rename is only atomic within one filesystem; fsync before it because a rename
// that lands ahead of the bytes is exactly the torn write this is here to
// prevent.
//
// The directory sync is the half that was missing, and the file sync read as if
// it covered it. It does not: fsync on the file persists the bytes, while the
// rename that gives them their NAME is a directory change, and a directory change
// is not durable until the directory is synced. A power cut in that window leaves
// the new content on disk under no name and the old name pointing at the old
// content — a node that comes back with the identity it just replaced, which is
// the one outcome a "renew" must never produce.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".atomic-*")
	if err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: write %q: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: chmod %q: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: sync %q: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close %q: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("atomicfile: rename into %q: %w", path, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		// The file IS in place — the rename succeeded — but nothing guarantees it
		// survives a power cut, and the caller asked for a durable write. Say which
		// half failed so this is never read as "the write did not happen".
		return fmt.Errorf("atomicfile: %q was written but its directory could not be synced, so the change may not survive a power cut: %w", path, err)
	}
	return nil
}
