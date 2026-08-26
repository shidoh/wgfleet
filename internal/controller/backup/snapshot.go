package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite" // pure-Go sqlite driver, registered as "sqlite"
)

// SnapshotDB writes a consistent copy of the sqlite database at srcPath to
// dstPath using VACUUM INTO. Unlike a raw file copy it is safe while the
// controller holds the live db open (WAL): the snapshot is a transactionally
// consistent point-in-time image. dstPath must not exist.
func SnapshotDB(ctx context.Context, srcPath, dstPath string) error {
	db, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return fmt.Errorf("open %q: %w", srcPath, err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dstPath); err != nil {
		return fmt.Errorf("vacuum into %q: %w", dstPath, err)
	}
	// VACUUM INTO creates a fresh file at SQLite's default 0644, and this snapshot
	// is a complete copy of the store — every client's private key included. The
	// enclosing temp dir is 0700, but the mode travels into the archive manifest
	// and back out on restore, so fix it at the source.
	if err := os.Chmod(dstPath, 0o600); err != nil {
		return fmt.Errorf("restrict snapshot mode: %w", err)
	}
	return nil
}
