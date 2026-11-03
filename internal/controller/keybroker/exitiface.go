package keybroker

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// exitInterface is everything about one exit's awg0 that every master must agree
// on. The exit runs ONE interface and every master is a peer on it; AmneziaWG's
// S1-S4/H1-H4 and its generation belong to the interface, so they cannot follow
// the master that happens to be rendering — both ends of every tunnel take them
// from here, and from nowhere else.
type exitInterface struct {
	seed   string
	anchor string
	awg3   bool
}

// exitInterface resolves the interface-level identity of exit from the fleet's
// anchor label. ok=false when there is no label: a fleet with no master, which
// has nobody to peer with and nothing to derive from.
//
// AmneziaWG 3.0 is on when the operator opted in and every end that IS on the
// interface can speak it: the exit, and each master that has registered a key or
// reported a wire version. A master with no record, or a stub that has done
// neither, is left out — it is either not deployed yet or gone, and counting it as
// "too old" would downgrade and restart every exit over a node that is not there.
// A registered master that sends no wire version is an agent too old for 3.0, and
// counts.
func (b *Broker) exitInterface(ctx context.Context, exit config.ExitConfig, exitNode domain.Node) (exitInterface, bool, error) {
	anchor := b.fleet.AnchorLabel()
	if anchor == "" {
		return exitInterface{}, false, nil
	}
	optIn := b.fleet.AWG3For(exit)
	ends := []domain.Node{exitNode}
	for _, m := range b.fleet.Masters {
		node, pub, err := b.lookupPubKey(ctx, m.Name)
		if err != nil {
			return exitInterface{}, false, err
		}
		if node.WireVersion == 0 && pub == "" {
			continue
		}
		ends = append(ends, node)
		// The spec says only that the interface is on 2.0. With several masters the
		// operator cannot tell which of them is the reason without this line.
		if optIn && node.WireVersion < api.WireAWG3TrackB {
			b.warnOnce("awg3-held-by-master:"+exit.Name+"/"+m.Name, fmt.Sprint(node.WireVersion),
				"AmneziaWG 3.0 is switched on for this exit, but a master holds this exit's interface at AmneziaWG 2.0: its agent is too old",
				"exit", exit.Name, "master", m.Name, "master_wire", node.WireVersion, "need_wire", api.WireAWG3TrackB)
		}
	}
	seed := wg.TunnelSeed(exit.Name, anchor, awgSalt)
	return exitInterface{seed: seed, anchor: anchor, awg3: awg3Enabled(optIn, ends...)}, true, nil
}

// masterEndLabel names a master's end of the tunnel for the LOCAL AmneziaWG
// parameters (Jc/Jmin/Jmax, I1-I5), which may differ per end and so must: the
// base master keeps the label a one-master fleet has always used.
func masterEndLabel(master config.MasterConfig) string {
	if master.IsBase() {
		return "master"
	}
	return "master|" + master.Name
}
