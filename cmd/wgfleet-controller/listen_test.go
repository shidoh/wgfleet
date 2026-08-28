package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// A bind that fails at startup must be retried, not logged and abandoned.
//
// All three HTTP surfaces bind the management address, which on a master belongs to
// ZeroTier and routinely appears after the unit does. Logging and giving up left the
// process `active` with no Web UI and no metrics until somebody restarted it by
// hand — a healthy-looking controller that was not serving.
func TestServeWithRetryKeepsTryingUntilTheAddressAppears(t *testing.T) {
	// Occupy a port so the first binds fail, then free it.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := blocker.Addr().String()

	var buf syncBuf
	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	go serveWithRetry("test", srv, slog.New(slog.NewTextHandler(&buf, nil)))

	// Give it a couple of failed attempts, then let go of the port.
	time.Sleep(300 * time.Millisecond)
	if !strings.Contains(buf.String(), "bind failed, retrying") {
		t.Fatalf("no retry was attempted:\n%s", buf.String())
	}
	blocker.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "listening") {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("never bound after the address was freed:\n%s", buf.String())
}

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
