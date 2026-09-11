package provmgr

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/domain"
)

// dialCtx opens an SSH connection but gives up when ctx does.
//
// Every caller in this package runs under a deadline — the rolling upgrade's
// per-node bound, the UI action's request context, the version gate's own timeout
// — and none of them could enforce it, because DialFunc takes no context and a
// blocked dial simply never returns. A deadline can only be noticed by a call that
// comes back.
//
// That is not theoretical. The fleet's public master→exit path wedges in a
// specific way: the TCP connection ESTABLISHES and then swallows everything, so
// the dial blocks inside the SSH handshake with nothing to time it out. Measured
// 2026-09-11: a rolling upgrade sat 13 minutes on its first node under a
// five-minute per-node deadline, upgraded nothing, and had to be SIGKILLed.
//
// provisioner.DialSSH now bounds its own handshake, which fixes the case we have
// hit. This is the belt to that pair of braces: it holds for ANY DialFunc,
// including an injected one, and it is what makes the caller's deadline mean
// something rather than depend on the politeness of the dialler.
//
// A dial that lands after we gave up is closed on a goroutine rather than leaked:
// abandoning it would hold a file descriptor and a session on the node for as long
// as the controller runs.
func dialCtx(ctx context.Context, dial DialFunc, target domain.SSHTarget) (provisioner.Runner, error) {
	type result struct {
		runner provisioner.Runner
		err    error
	}
	// Buffered: the goroutine must never block trying to hand back a dial nobody
	// is waiting for any more.
	ch := make(chan result, 1)
	go func() {
		r, err := dial(target)
		ch <- result{r, err}
	}()

	select {
	case r := <-ch:
		return r.runner, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.runner != nil {
				_ = r.runner.Close()
			}
		}()
		return nil, fmt.Errorf("ssh dial abandoned: %w", ctx.Err())
	}
}
