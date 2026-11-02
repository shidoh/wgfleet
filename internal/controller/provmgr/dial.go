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
// A public master→exit path can wedge in a specific way: the TCP connection
// ESTABLISHES and then swallows everything, so the dial blocks inside the SSH
// handshake with nothing to time it out. A rolling upgrade then sits on its first
// node well past a five-minute per-node deadline, upgrades nothing, and has to be
// killed.
//
// provisioner.DialSSH now bounds its own handshake, which fixes the case above.
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

// dialNode opens SSH to a node: its manifest ssh target first, and when that
// fails, the node's mgmt (overlay) address with the same port, user and key.
//
// The public master→exit path and the overlay fail independently, and the public
// one fails in a way that looks alive — the TCP connection opens and the SSH
// handshake then times out. A rollout can skip exits on exactly that while the
// controller holds a working control channel to them over the overlay. Pointing ssh.host at the overlay by hand fixes one node and is a
// step the operator has to know to take; the fallback makes it unnecessary.
//
// The order is deliberate. A first bootstrap has no overlay yet, so the manifest
// target is the only path that can work there; and for a node already managed
// over its mgmt address there is no second path, so it is dialled once.
func (m *Manager) dialNode(ctx context.Context, node domain.Node) (provisioner.Runner, error) {
	runner, err := dialCtx(ctx, m.opts.Dial, node.SSH)
	if err == nil {
		return runner, nil
	}
	if node.MgmtAddr == "" || node.MgmtAddr == node.SSH.Host || ctx.Err() != nil {
		return nil, err
	}
	m.log.Warn("ssh to the node's manifest address failed; trying its mgmt address",
		"node", node.Name, "host", node.SSH.Host, "mgmt_addr", node.MgmtAddr, "err", err)
	overlay := node.SSH
	overlay.Host = node.MgmtAddr
	runner, mgmtErr := dialCtx(ctx, m.opts.Dial, overlay)
	if mgmtErr != nil {
		return nil, fmt.Errorf("%w; mgmt address: %w", err, mgmtErr)
	}
	return runner, nil
}
