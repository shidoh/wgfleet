// Package logging is the one place both binaries decide how much they say.
//
// The level used to be a constant: Info, with a handful of Debug calls in the
// code that no build could ever print. When the controller silently removed an
// exit from the load balancer several times in a few minutes, the question "what did it decide and why" had no answer at any setting, because
// there was no setting. Five levels now, a flag and a config key to pick one,
// and two signals to move between them on a running process — a node under
// investigation must not need a restart to start talking.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// LevelTrace sits below slog.LevelDebug: per-RPC, per-action, per-probe detail
// that is too much for debug and exactly what a live incident needs.
const LevelTrace slog.Level = slog.LevelDebug - 4

// Levels, most to least verbose, as the operator names them.
var Levels = []string{"trace", "debug", "info", "warn", "error"}

// ParseLevel maps an operator's word to a level. Empty means info.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want one of %s)", s, strings.Join(Levels, ", "))
}

// LevelName renders a level the way ParseLevel reads it, TRACE included.
func LevelName(l slog.Level) string {
	if l <= LevelTrace {
		return "TRACE"
	}
	return l.String()
}

// Configure installs the process-wide logger and returns the variable that holds
// its level, so the level can be moved later without touching the handler.
func Configure(w io.Writer, format string, level slog.Level) *slog.LevelVar {
	lv := &slog.LevelVar{}
	lv.Set(level)
	opts := &slog.HandlerOptions{Level: lv, ReplaceAttr: replaceLevel}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	slog.SetDefault(slog.New(h))
	return lv
}

// replaceLevel names the custom level; without it slog prints "DEBUG-4".
func replaceLevel(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if l, ok := a.Value.Any().(slog.Level); ok && l <= LevelTrace {
			a.Value = slog.StringValue("TRACE")
		}
	}
	return a
}

// Trace logs at LevelTrace. slog has no Trace method, and a call site that has
// to spell out the level every time is one nobody writes.
func Trace(log *slog.Logger, msg string, args ...any) {
	if log == nil {
		return
	}
	log.Log(context.Background(), LevelTrace, msg, args...)
}

// WatchSignals moves the level on a running process: SIGUSR1 one step MORE
// verbose (info → debug → trace), SIGUSR2 back to the configured level. Every
// change is announced at Info, whatever the level, so a journal always shows
// when its own verbosity changed. Returns a stop function.
func WatchSignals(lv *slog.LevelVar, configured slog.Level, log *slog.Logger) func() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGUSR1, syscall.SIGUSR2)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				before := lv.Level()
				after := StepLevel(before, sig == syscall.SIGUSR1, configured)
				if after == before {
					continue
				}
				lv.Set(after)
				if log != nil {
					log.Log(context.Background(), slog.LevelInfo, "log level changed by signal",
						"signal", sig.String(), "from", LevelName(before), "to", LevelName(after))
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// StepLevel is the signal policy, kept pure so it is testable: verbose=true
// takes one step toward trace and stops there; verbose=false returns to
// configured.
func StepLevel(current slog.Level, verbose bool, configured slog.Level) slog.Level {
	if !verbose {
		return configured
	}
	switch {
	case current > slog.LevelInfo:
		return slog.LevelInfo
	case current > slog.LevelDebug:
		return slog.LevelDebug
	default:
		return LevelTrace
	}
}
