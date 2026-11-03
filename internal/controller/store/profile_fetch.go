package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// fetchTimeLayout is fixed-width UTC — unlike timeLayout, which trims trailing
// zeros — so the conflict clause can order rows by comparing the text.
const fetchTimeLayout = "2006-01-02T15:04:05.000000000Z"

// RecordProfileFetch implements Store. One statement; the time comes from the
// caller. A write older than the stored row is dropped rather than rolling the
// row back: two portals recording the same device must converge on the latest.
func (s *SQLiteStore) RecordProfileFetch(ctx context.Context, f domain.ProfileFetch) error {
	switch {
	case f.DeviceID == "":
		return errors.New("store: profile fetch needs a device ID")
	case f.At.IsZero():
		return errors.New("store: profile fetch time is required (the caller stamps it, not the store)")
	case f.Kind != domain.FetchProfile && f.Kind != domain.FetchProvider:
		return fmt.Errorf("store: unknown profile fetch kind %q", f.Kind)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO client_device_fetches (device_id, kind, fetched_at, user_agent) VALUES (?,?,?,?)
		ON CONFLICT(device_id, kind) DO UPDATE SET
			fetched_at = excluded.fetched_at,
			user_agent = excluded.user_agent
		WHERE excluded.fetched_at >= client_device_fetches.fetched_at`,
		f.DeviceID, string(f.Kind), f.At.UTC().Format(fetchTimeLayout), f.UserAgent); err != nil {
		return fmt.Errorf("record profile fetch for device %q: %w", f.DeviceID, err)
	}
	return nil
}

// ListProfileFetches implements Store.
func (s *SQLiteStore) ListProfileFetches(ctx context.Context) ([]domain.ProfileFetch, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT device_id, kind, fetched_at, user_agent FROM client_device_fetches ORDER BY device_id, kind`)
	if err != nil {
		return nil, fmt.Errorf("list profile fetches: %w", err)
	}
	defer rows.Close()
	var out []domain.ProfileFetch
	for rows.Next() {
		var f domain.ProfileFetch
		var kind, at string
		if err := rows.Scan(&f.DeviceID, &kind, &at, &f.UserAgent); err != nil {
			return nil, fmt.Errorf("list profile fetches: %w", err)
		}
		f.Kind, f.At = domain.ProfileFetchKind(kind), parseTime(at)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list profile fetches: %w", err)
	}
	return out, nil
}
