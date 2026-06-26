package backup

import (
	"context"
	"database/sql"
	"fmt"

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
	return nil
}
