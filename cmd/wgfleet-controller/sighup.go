package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// ignoreSIGHUP keeps `kill -HUP` from killing the control plane.
//
// Go's default disposition for SIGHUP is terminate, and the controller listened
// only for SIGINT and SIGTERM — so the reflex an operator reaches for after editing
// a config file took the whole control plane down. Worse, the AGENT catches SIGHUP
// on purpose and says so in the journal, which teaches exactly that reflex: the
// signal is safe on every node in the fleet and fatal on the one machine that
// coordinates them.
//
// It is ignored rather than wired to a reload because there is no reload: the
// manifest is read once at startup, and every subcommand that acts on it re-reads it
// itself. Saying that out loud is the point — a signal that silently does nothing is
// only marginally better than one that kills the process.
func ignoreSIGHUP(log *slog.Logger) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				log.Info("SIGHUP ignored: the controller has no reloadable configuration",
					"detail", "controller.yaml is read at startup only; edit it and restart the service to apply it")
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
