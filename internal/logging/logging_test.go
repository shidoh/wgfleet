package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevelAcceptsEveryOperatorWord(t *testing.T) {
	for word, want := range map[string]slog.Level{
		"": slog.LevelInfo, "info": slog.LevelInfo, "INFO": slog.LevelInfo,
		"debug": slog.LevelDebug, "trace": LevelTrace, "warn": slog.LevelWarn,
		"warning": slog.LevelWarn, "error": slog.LevelError,
	} {
		got, err := ParseLevel(word)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", word, got, err, want)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("an unknown word must be refused, not read as info")
	}
}

// Trace lines must print as TRACE, and must not print at all one level up.
func TestTraceIsNamedAndGated(t *testing.T) {
	var buf bytes.Buffer
	lv := Configure(&buf, "text", LevelTrace)
	log := slog.Default()
	Trace(log, "deep detail", "k", "v")
	if !strings.Contains(buf.String(), "level=TRACE") || !strings.Contains(buf.String(), "deep detail") {
		t.Fatalf("trace line missing or misnamed:\n%s", buf.String())
	}
	buf.Reset()
	lv.Set(slog.LevelDebug)
	Trace(log, "hidden")
	log.Debug("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("level gate wrong at debug:\n%s", buf.String())
	}
	buf.Reset()
	Configure(&buf, "json", LevelTrace)
	Trace(slog.Default(), "json trace")
	if !strings.Contains(buf.String(), `"level":"TRACE"`) {
		t.Fatalf("json handler did not name the level:\n%s", buf.String())
	}
}

// SIGUSR1 walks info → debug → trace and stops; SIGUSR2 snaps back to what was
// configured, whatever the current level.
func TestStepLevelPolicy(t *testing.T) {
	l := slog.LevelInfo
	for _, want := range []slog.Level{slog.LevelDebug, LevelTrace, LevelTrace} {
		l = StepLevel(l, true, slog.LevelInfo)
		if l != want {
			t.Fatalf("step to %v, want %v", l, want)
		}
	}
	if got := StepLevel(l, false, slog.LevelWarn); got != slog.LevelWarn {
		t.Fatalf("SIGUSR2 returned %v, want the configured warn", got)
	}
	if got := StepLevel(slog.LevelError, true, slog.LevelInfo); got != slog.LevelInfo {
		t.Fatalf("from error, one step more verbose should be info, got %v", got)
	}
}
