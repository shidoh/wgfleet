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

// Write puts data at path via a temporary file in the same directory, fsynced
// before the rename. Same directory because a rename is only atomic within one
// filesystem; fsync before it because a rename that lands ahead of the bytes is
// exactly the torn write this is here to prevent.
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
	return os.Rename(tmp.Name(), path)
}
