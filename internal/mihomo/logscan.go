package mihomo

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"
)

// LogScanTimeout bounds one read of the container's log. Docker is not always
// healthy when mihomo is unhappy, and a wedged dockerd would otherwise inherit the
// reconcile pass's whole budget (15 minutes) for what is meant to be a glance.
const LogScanTimeout = 3 * time.Second

// ScanErrors counts the error lines mihomo wrote since `since`, and returns the
// timestamp of the last line it counted so the next call can continue from there.
//
// It exists because mihomo's own errors were invisible. The TPROXY reply failure
// that black-holed every client QUIC flow from 2026-08-28 announced itself 97787
// times in the container log and produced no metric, no alert and no state change:
// the fleet stayed green for eight days while a whole protocol was dead. Anything
// the data plane says about itself has to reach a counter.
//
// Deduplication is by Docker's OWN timestamp, not the one inside mihomo's message.
// The message carries whole seconds, and the errors arrive in bursts inside a
// single second — so a second-resolution cursor either double-counts or drops the
// remainder of a burst at every window boundary. `--timestamps` gives RFC3339 with
// nanoseconds, which is unique enough to cut on.
func ScanErrors(ctx context.Context, container string, since time.Time) (count int, last time.Time, err error) {
	ctx, cancel := context.WithTimeout(ctx, LogScanTimeout)
	defer cancel()

	args := []string{"logs", "--timestamps", container}
	if !since.IsZero() {
		args = append(args, "--since", since.UTC().Format(time.RFC3339Nano))
	} else {
		// First call: do not walk the whole file just to establish a cursor.
		args = append(args, "--tail", "1")
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return 0, since, err
	}
	return countErrorLines(strings.NewReader(string(out)), since)
}

// countErrorLines is the parsing half, kept free of exec so it is testable. A line
// looks like `<RFC3339Nano> time="..." level=error msg="..."`; anything without a
// parseable leading timestamp is ignored rather than guessed at.
func countErrorLines(r io.Reader, since time.Time) (count int, last time.Time, err error) {
	last = since
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		stamp, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		ts, perr := time.Parse(time.RFC3339Nano, stamp)
		if perr != nil {
			continue
		}
		// `--since` is inclusive, so the cursor line itself comes back every time.
		if !since.IsZero() && !ts.After(since) {
			continue
		}
		if ts.After(last) {
			last = ts
		}
		if strings.Contains(rest, "level=error") {
			count++
		}
	}
	return count, last, sc.Err()
}
