package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// serveWithRetry runs srv, retrying the BIND until it succeeds.
//
// All three of the controller's HTTP surfaces — the Web UI, the client portal and
// /metrics — bind the management address, and on a master that address belongs to
// ZeroTier, which routinely comes up after the unit does. `EADDRNOTAVAIL` at
// startup is therefore ordinary rather than exceptional.
//
// What made it costly is that each of these ran ListenAndServe in a goroutine and
// merely logged the failure: the process stayed `active`, so systemd saw a healthy
// controller, the operator saw a healthy controller, and the Web UI and metrics
// were simply gone until someone restarted it by hand. The agent has solved this
// for its own metrics listener since the beginning; the controller had not.
//
// Retrying forever rather than a bounded number of times is deliberate. The bound
// on the agent's version means a node whose overlay is slow to appear gives up
// permanently and needs a restart — the same failure, only quieter. There is
// nothing better to do here than keep trying, and every attempt is logged so the
// wait is visible.
func serveWithRetry(name string, srv *http.Server, log *slog.Logger) {
	const (
		firstDelay = 2 * time.Second
		maxDelay   = 30 * time.Second
	)
	delay := firstDelay
	for {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			log.Warn("bind failed, retrying", "surface", name, "addr", srv.Addr, "retry_in", delay, "err", err)
			time.Sleep(delay)
			if delay *= 2; delay > maxDelay {
				delay = maxDelay
			}
			continue
		}
		log.Info("listening", "surface", name, "addr", srv.Addr)
		err = srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			return // shutdown, not a fault
		}
		log.Error("server stopped", "surface", name, "addr", srv.Addr, "err", err)
		// Serve returning anything else means the listener died under us; go back to
		// binding rather than leaving the surface silently down.
		delay = firstDelay
	}
}
