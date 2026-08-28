package main

import (
	"log/slog"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Go terminates on SIGHUP by default, and the controller listened only for SIGINT
// and SIGTERM. The agent catches SIGHUP deliberately and logs that it did — which
// teaches the operator that the signal is harmless, on every machine except the one
// that coordinates the fleet.
func TestSIGHUPDoesNotKillTheController(t *testing.T) {
	// syncBuf, not bytes.Buffer: the signal goroutine writes the log line while the
	// polling loop below reads it, which is a genuine data race the -race detector
	// fails on. (Shared with listen_test.go in this package.)
	var buf syncBuf
	stop := ignoreSIGHUP(slog.New(slog.NewTextHandler(&buf, nil)))
	defer stop()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "SIGHUP ignored") {
			// Surviving is most of it; saying why is the rest. A signal that silently
			// does nothing is only marginally better than one that kills the process.
			if !strings.Contains(buf.String(), "restart") {
				t.Errorf("the message does not tell the operator what to do instead:\n%s", buf.String())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("SIGHUP was swallowed without a word; log was:\n%s", buf.String())
}

// --plan is a modifier. On its own it used to reach serve() — so the flag whose
// entire meaning is "change nothing" started the control plane: a port conflict on
// a live master, a second unsupervised controller on a stopped one.
func TestBarePlanIsRefusedNotServed(t *testing.T) {
	if anySubcommand("", "", "", "", "", "") {
		t.Fatal("anySubcommand said yes to nothing at all")
	}
	if !anySubcommand("", "exit-de-1", "") {
		t.Error("anySubcommand missed a selected subcommand")
	}
}
