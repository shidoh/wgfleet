package main

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// safeBuf is a Writer the handler goroutine and the test can share. slog writes
// from the signal goroutine while the test polls, so a bare bytes.Buffer is a
// data race — and this package is tested with -race.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Without a handler Go terminates on SIGHUP, so `kill -HUP` on a running agent
// kills it and the death looks unexplained. This test would take the whole test
// binary down if the handler were removed — which is exactly the regression worth
// guarding.
func TestSIGHUPDoesNotKillTheAgent(t *testing.T) {
	var buf safeBuf
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
	var buf safeBuf
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
