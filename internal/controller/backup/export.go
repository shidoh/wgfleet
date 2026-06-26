package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ExportOptions configures Export.
type ExportOptions struct {
	Sources     Sources
	WireVersion int
	Now         func() time.Time
	Encrypt     EncryptFunc
}

// Export snapshots the store, gathers the irreplaceable files, packs them into a
// tar, and returns the age-encrypted archive bytes.
func Export(ctx context.Context, opts ExportOptions) ([]byte, error) {
	if opts.Encrypt == nil {
		return nil, fmt.Errorf("export: Encrypt func is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	snapDir, err := os.MkdirTemp("", "wgfleet-backup-snap-")
	if err != nil {
		return nil, fmt.Errorf("temp snapshot dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(snapDir) }()
	snapPath := filepath.Join(snapDir, "state.db")

	if err := SnapshotDB(ctx, opts.Sources.StateDB, snapPath); err != nil {
		return nil, err
	}

	items, layers, err := GatherItems(opts.Sources, snapPath, os.Stat)
	if err != nil {
		return nil, err
	}

	m := Manifest{
		Schema:      ArchiveSchema,
		WireVersion: opts.WireVersion,
		Layers:      layers,
		CreatedAt:   now().UTC().Format(time.RFC3339),
	}
	for _, it := range items {
		m.Entries = append(m.Entries, Entry{Name: it.Name, Dest: it.Dest, Mode: uint32(it.Mode), Layer: it.Layer})
	}

	tarBytes, err := BuildTar(m, items)
	if err != nil {
		return nil, err
	}
	ciphertext, err := opts.Encrypt(ctx, tarBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt archive: %w", err)
	}
	return ciphertext, nil
}
