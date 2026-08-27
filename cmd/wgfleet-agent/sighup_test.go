package main

import (
	"bytes"
	"log/slog"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Without a handler Go terminates on SIGHUP, so `kill -HUP` on a running agent
// kills it and the death looks unexplained. This test would take the whole test
// binary down if the handler were removed — which is exactly the regression worth
// guarding.
func TestSIGHUPDoesNotKillTheAgent(t *testing.T) {
	var buf bytes.Buffer
	stop := ignoreSIGHUP(slog.New(slog.NewTextHandler(&buf, nil)))
	defer stop()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "SIGHUP ignored") {
			return // survived, and said why
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("SIGHUP was swallowed without a word; log was:\n%s", buf.String())
}

// Silently ignoring it would be its own trap: the operator waits for an effect
// that never arrives. The message must name the reason.
func TestSIGHUPMessageSaysWhyNothingHappened(t *testing.T) {
	var buf bytes.Buffer
	stop := ignoreSIGHUP(slog.New(slog.NewTextHandler(&buf, nil)))
	defer stop()
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if out := buf.String(); strings.Contains(out, "controller") && strings.Contains(out, "reconcile") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("the message does not point at where configuration actually comes from:\n%s", buf.String())
}
