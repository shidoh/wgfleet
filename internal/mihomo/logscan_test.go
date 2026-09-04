package mihomo

import (
	"strings"
	"testing"
	"time"
)

// Errors arrive in BURSTS inside one second — the live master logged several
// `listenLocalConn` failures per second for eight days — so the cursor has to be
// finer than a second or every window boundary either double-counts a burst or
// drops its tail. Docker's own `--timestamps` is nanosecond; the timestamp inside
// mihomo's message is not.
func TestCountErrorLinesCutsOnNanosecondsNotSeconds(t *testing.T) {
	const logs = `2026-09-04T08:46:50.402579203Z time="2026-09-04T08:46:50Z" level=error msg="listenLocalConn failed with error: address already in use"
2026-09-04T08:46:50.443983718Z time="2026-09-04T08:46:50Z" level=error msg="listenLocalConn failed with error: address already in use"
2026-09-04T08:46:50.787656258Z time="2026-09-04T08:46:50Z" level=info msg="something fine"
2026-09-04T08:46:51.586897317Z time="2026-09-04T08:46:51Z" level=error msg="dns resolve failed"
`
	count, last, err := countErrorLines(strings.NewReader(logs), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3 error lines (the info line must not count)", count)
	}
	if want := "2026-09-04T08:46:51.586897317Z"; last.UTC().Format(time.RFC3339Nano) != want {
		t.Errorf("cursor = %v, want the last line seen (%s)", last, want)
	}

	// Continuing from the middle of the burst must not re-count what came before it.
	mid, _ := time.Parse(time.RFC3339Nano, "2026-09-04T08:46:50.443983718Z")
	count, _, err = countErrorLines(strings.NewReader(logs), mid)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count = %d after resuming mid-burst, want 1 — the cursor is too coarse", count)
	}
}

// Unparseable lines must be skipped, not guessed at: a bogus timestamp would move
// the cursor and silently swallow everything after it.
func TestCountErrorLinesIgnoresLinesWithoutATimestamp(t *testing.T) {
	count, last, err := countErrorLines(strings.NewReader("garbage level=error\n\nlevel=error msg=x\n"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 — lines with no timestamp were counted", count)
	}
	if !last.IsZero() {
		t.Errorf("cursor moved to %v on unparseable input", last)
	}
}
