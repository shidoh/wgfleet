package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PlannedWrite describes one file restore: its destination, the mode it will be
// written with, and the .bak path the prior file was moved to ("" if none).
type PlannedWrite struct {
	Dest   string
	Mode   os.FileMode
	Backup string
}

// RestorePlan is the outcome of a restore (apply or plan).
type RestorePlan struct {
	Layers   []Layer
	Writes   []PlannedWrite
	Warnings []string
}

// RestoreOptions configures Restore.
type RestoreOptions struct {
	Decrypt     DecryptFunc
	WireVersion int // the running controller's wire-contract version
	Plan        bool
	Now         func() time.Time
}

// Restore decrypts and unpacks an archive. In apply mode it moves each existing
// destination aside to <dest>.bak-<ts> then writes the archived file atomically.
// In plan mode it validates and returns the plan without touching disk.
func Restore(ctx context.Context, archive []byte, opts RestoreOptions) (RestorePlan, error) {
	if opts.Decrypt == nil {
		return RestorePlan{}, fmt.Errorf("restore: Decrypt func is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	plaintext, err := opts.Decrypt(ctx, archive)
	if err != nil {
		return RestorePlan{}, fmt.Errorf("decrypt archive: %w", err)
	}
	m, items, err := ParseTar(plaintext)
	if err != nil {
		return RestorePlan{}, err
	}
	if m.WireVersion > opts.WireVersion {
		return RestorePlan{}, fmt.Errorf("archive wire version %d is newer than this controller (%d); upgrade before restoring", m.WireVersion, opts.WireVersion)
	}

	ts := now().UTC().Format("20060102T150405Z")
	plan := RestorePlan{Layers: m.Layers}
	if len(m.Layers) == 1 && m.Layers[0] == LayerController {
		plan.Warnings = append(plan.Warnings, "archive has no master layer: wg-easy clients and node identity are not restored")
	}

	for _, it := range items {
		if it.Dest == "" {
			return RestorePlan{}, fmt.Errorf("item %q has no restore destination", it.Name)
		}
		pw := PlannedWrite{Dest: it.Dest, Mode: it.Mode}
		if _, err := os.Stat(it.Dest); err == nil {
			pw.Backup = it.Dest + ".bak-" + ts
		}
		plan.Writes = append(plan.Writes, pw)

		if opts.Plan {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(it.Dest), 0o755); err != nil {
			return RestorePlan{}, fmt.Errorf("mkdir for %q: %w", it.Dest, err)
		}
		if pw.Backup != "" {
			if err := os.Rename(it.Dest, pw.Backup); err != nil {
				return RestorePlan{}, fmt.Errorf("preflight backup %q: %w", it.Dest, err)
			}
		}
		if err := writeAtomic(it.Dest, it.Data, it.Mode); err != nil {
			return RestorePlan{}, err
		}
	}
	return plan, nil
}

// writeAtomic writes data to a temp file in the destination's directory then
// renames it into place, so a crash never leaves a half-written file.
func writeAtomic(dest string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".wgfleet-restore-*")
	if err != nil {
		return fmt.Errorf("temp for %q: %w", dest, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %q: %w", dest, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp for %q: %w", dest, err)
	}
	if err := os.Chmod(tmpName, mode.Perm()); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod %q: %w", dest, err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename into %q: %w", dest, err)
	}
	return nil
}
