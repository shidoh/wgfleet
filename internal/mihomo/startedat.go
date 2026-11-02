package mihomo

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// StartedAt reports when the named container last started, as docker records it.
//
// It exists for a restart loop seen in production: a planner restarted
// mihomo every pass, three exits fell out of rotation in three minutes, and the
// only record was the master agent's journal. Every restart — a self-heal, a
// crash, docker's own restart policy — moves this timestamp, so changes() over
// the resulting series counts restarts no single restarter has to confess to.
func StartedAt(ctx context.Context, container string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, LogScanTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.StartedAt}}", container).Output()
	if err != nil {
		return time.Time{}, err
	}
	return parseStartedAt(string(out))
}

// parseStartedAt is the parsing half, kept free of exec so it is testable. Docker
// reports the zero time for a container that was created but never started; that
// is not a start, and a gauge set to year one would read as a restart the moment
// the container actually came up.
func parseStartedAt(out string) (time.Time, error) {
	s := strings.TrimSpace(out)
	if s == "" {
		return time.Time{}, errors.New("docker inspect returned no start time")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	if t.IsZero() || t.Year() <= 1 {
		return time.Time{}, errors.New("container has never started")
	}
	return t, nil
}
