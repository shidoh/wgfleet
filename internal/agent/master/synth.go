package master

import (
	"context"
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netns"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Names for the master's own client. Exported nowhere: nothing outside this file
// needs to know how the prober is built, only what it reports.
const (
	synthNetns = "wgfleet-synth"
	synthIface = "wgs0"
)

// synthPlanner builds the master's own client: a real AmneziaWG peer whose
// decrypted side lives in an isolated namespace.
//
// The shape is decided by one kernel behaviour, verified on the stand
// 2026-09-04: a WireGuard device keeps its UDP socket in the namespace where it
// was CREATED, even after the device is moved elsewhere. So the interface is
// created in the host namespace — where it can dial the master's own client port
// on loopback — and then moved into a namespace of its own, where its decrypted
// traffic is the only traffic there is. No veth, no address for it to collide
// with, and no route on the host that could leak.
//
// Why bother: every component metric was green for the eight days client QUIC was
// dead, because each measured a component and every component was fine. This is
// the only thing that measures the sentence that matters — a packet entering the
// client interface comes back.
type synthPlanner struct {
	confPath   string     // setconf file for the prober's device
	synthKey   wg.KeyPair // the prober's identity; zero ⇒ no prober
	serverPub  string     // the master's client-interface public key
	run        netns.Runner
	clientPort int
}

func (synthPlanner) Component() string { return "client path prober" }

func (p synthPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	cw := clientWGSpec(spec)
	if cw == nil || p.synthKey.PublicKey == "" || p.serverPub == "" {
		return []reconcile.Action{reconcile.NoChangeAction("client path prober",
			"not configured; the client path is not being measured")}, nil
	}
	addr, err := domain.SyntheticClientAddress(cw.AddressPool)
	if err != nil {
		// A pool too small to seat a prober still serves clients. Measuring is worth
		// less than being able to use the thing measured.
		return []reconcile.Action{reconcile.NoChangeAction("client path prober",
			"client pool has no room for a prober; the client path is not being measured")}, nil
	}
	port := p.clientPort
	if port == 0 {
		port = cw.ListenPort
	}
	// Loopback, deliberately. The client interface binds the wildcard, so its own
	// host can reach it at 127.0.0.1 — which keeps the prober's encrypted leg off
	// every real interface and makes it impossible for this traffic to leave the box
	// by any path but the tunnel it is testing.
	conf, err := wg.RenderSyntheticSetConf(wg.SyntheticSetConfInput{
		Spec:            *cw,
		Client:          wg.SyntheticClient(addr, p.synthKey.PrivateKey, p.synthKey.PublicKey),
		ServerPublicKey: p.serverPub,
		Endpoint:        fmt.Sprintf("127.0.0.1:%d", port),
	})
	if err != nil {
		return []reconcile.Action{reconcile.NoChangeAction("client path prober",
			"cannot render the prober: "+err.Error())}, nil
	}
	file, err := reconcile.FileAction(p.confPath, []byte(conf), 0o600, wg.RedactConfig)
	if err != nil {
		return nil, err
	}
	actions := []reconcile.Action{file}

	run := p.run
	if run == nil {
		run = netns.Exec
	}
	if out, nerr := run(ctx, "ip", "netns", "list"); nerr != nil || !strings.Contains(out, synthNetns) {
		actions = append(actions, reconcile.ExecAction(
			"create the prober's network namespace", "ip", "netns", "add", synthNetns))
	}

	nsExec := func(summary string, argv ...string) reconcile.Action {
		return reconcile.ExecAction(summary, append([]string{"ip", "netns", "exec", synthNetns}, argv...)...)
	}
	_, ifErr := run(ctx, "ip", "netns", "exec", synthNetns, "ip", "link", "show", synthIface)
	switch {
	case ifErr != nil:
		// Created HERE and moved THERE: the socket stays in this namespace, which is
		// the only reason the prober can dial 127.0.0.1 at all.
		actions = append(actions,
			reconcile.ExecAction("create the prober's interface", "ip", "link", "add", synthIface, "type", "amneziawg"),
			reconcile.ExecAction("configure the prober's device", "awg", "setconf", synthIface, p.confPath),
			reconcile.ExecAction("move the prober's interface into its namespace",
				"ip", "link", "set", synthIface, "netns", synthNetns),
			nsExec("address the prober", "ip", "addr", "add", addr, "dev", synthIface),
			nsExec("bring the prober up", "ip", "link", "set", synthIface, "up"),
			nsExec("bring the prober's loopback up", "ip", "link", "set", "lo", "up"),
			nsExec("route everything through the prober", "ip", "route", "replace", "default", "dev", synthIface),
		)
	case file.Changes():
		// The device exists and its configuration moved — re-apply in place rather
		// than tearing the interface down, so a params change does not cost a
		// measurement gap.
		actions = append(actions, nsExec("re-apply the prober's device config",
			"awg", "setconf", synthIface, p.confPath))
	default:
		actions = append(actions, reconcile.NoChangeAction("client path prober", "prober already up"))
	}
	return actions, nil
}
