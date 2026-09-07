package mihomo

import (
	"testing"
	"time"
)

func TestParseStartedAt(t *testing.T) {
	got, err := parseStartedAt("2026-09-07T06:04:16.94372975Z\n")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 7, 6, 4, 16, 943729750, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// Docker reports the zero time for a container that was created but never
// started. That is not a start, and a gauge set to year one would read as a
// restart the moment the container actually comes up.
func TestParseStartedAtRejectsNeverStarted(t *testing.T) {
	if _, err := parseStartedAt("0001-01-01T00:00:00Z"); err == nil {
		t.Fatal("never-started container must not yield a start time")
	}
	if _, err := parseStartedAt(""); err == nil {
		t.Fatal("empty output must be an error")
	}
}
