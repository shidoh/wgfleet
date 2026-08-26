package wgeasy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// wg-easy stores its runtime settings in a single-row general_table (id=1,
// seeded by its migrations). The Prometheus metrics endpoint (/metrics/prometheus
// on wg-easy's web port) is gated by the metrics_prometheus boolean column, which
// is otherwise only togglable from the admin UI. We flip it on directly, the same
// way we set the AWG obfuscation columns (ADR-0008). No container restart is
// needed: wg-easy reads the column per request.

// ReadMetricsPrometheus returns whether the Prometheus metrics endpoint is
// enabled. found is false (no error) when the general row does not exist yet
// (wg-easy not set up), which callers treat as "pending" rather than a failure.
func ReadMetricsPrometheus(ctx context.Context, dbPath string) (enabled, found bool, err error) {
	db, err := openReadOnly(dbPath)
	if errors.Is(err, os.ErrNotExist) {
		// wg-easy is not set up here. Callers treat this as "pending", the same as an
		// absent row, rather than as a failure.
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer func() { _ = db.Close() }()

	var v int
	err = db.QueryRowContext(ctx,
		`SELECT COALESCE(metrics_prometheus, 0) FROM general_table ORDER BY id LIMIT 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read wg-easy metrics setting: %w", err)
	}
	return v != 0, true, nil
}

// EnablePrometheus turns the Prometheus metrics endpoint on. It errors if the
// general row does not exist (wg-easy must be set up first).
func EnablePrometheus(ctx context.Context, dbPath string) error {
	db, err := open(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	res, err := db.ExecContext(ctx, `UPDATE general_table SET metrics_prometheus = 1`)
	if err != nil {
		return fmt.Errorf("enable wg-easy prometheus metrics: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("enable wg-easy prometheus metrics: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("wg-easy general settings row not found (set up wg-easy first)")
	}
	return nil
}

// EnablePrometheusSQL is the human-readable rendering of the UPDATE EnablePrometheus
// runs, for dry-run plan output.
func EnablePrometheusSQL() string {
	return "UPDATE general_table SET metrics_prometheus = 1;"
}
