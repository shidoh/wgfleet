package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// ignoreSIGHUP keeps a running agent alive when someone sends it SIGHUP, and says
// why nothing happened. It returns a stop function.
//
// Go's default disposition for SIGHUP is to TERMINATE, so today `kill -HUP` on an
// agent kills it — and the death looks unexplained: no error, no stack, just a
// gone process and a systemd restart. An operator reaching for SIGHUP is reaching
// for "reload your config", which is a reasonable reflex on any daemon.
//
// There is nothing to reload. agent.yaml carries the controller address, the
// certificates and the reconcile interval — read once at startup by design.
// Everything that actually shapes this node arrives as a spec from the controller
// and is already applied on the next pass without a restart. So the honest
// behaviour is to catch the signal, state that, and keep running: silently
// ignoring it would leave the operator waiting for an effect that never comes.
func ignoreSIGHUP(log *slog.Logger) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				log.Info("SIGHUP ignored: the agent has no reloadable configuration",
					"detail", "agent.yaml is read at startup; the node spec comes from the controller and is applied on the next reconcile without a restart")
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
