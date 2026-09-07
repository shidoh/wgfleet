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
	// synthResolvConf is where `ip netns exec` looks for the namespace's own
	// /etc/resolv.conf: it bind-mounts /etc/netns/<name>/* over /etc/*.
	synthResolvConf = "/etc/netns/" + synthNetns + "/resolv.conf"
)

// clientGateway is the master's own address in the client pool — what a client
// sends its DNS to.
func clientGateway(cw domain.ClientWGSpec) string {
	if cw.ServerAddress != "" {
		return cw.ServerAddress
	}
	return ""
}

// proberResolvers is the resolver list the prober's namespace gets: the one the
// clients are handed, else the gateway. Duplicates collapse — a list that names
// the same address twice would only make a failing probe wait twice as long.
func proberResolvers(cw domain.ClientWGSpec) []string {
	var out []string
	seen := map[string]bool{}
	for _, ns := range cw.DNS {
		ns = strings.TrimSpace(ns)
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true
		out = append(out, ns)
	}
	if len(out) == 0 {
		if gw := clientGateway(cw); gw != "" {
			out = append(out, gw)
		}
	}
	return out
}

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
	resolvPath string     // the namespace's own resolv.conf; "" ⇒ the canonical path
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

	// The prober's resolver, and it must be the CLIENT's resolver.
	//
	// `ip netns exec` bind-mounts /etc/netns/<name>/* over /etc/*, which is how a
	// namespace gets its own resolv.conf. Without one the prober inherits the host's
	// — on a systemd box that is 127.0.0.53, a stub resolver that does not exist
	// inside the namespace — and every probe fails on name resolution while the
	// tunnel underneath is perfectly healthy. That is a prober that reports the path
	// broken when it is fine, which is worse than no prober at all.
	//
	// "Where clients resolve" is the list the controller writes into every client
	// config (cw.DNS) — the master's own blocky at the gateway address when the
	// master runs one, the exits' resolvers otherwise. It used to be the gateway
	// unconditionally, which on a master WITHOUT dns_filter is an address nothing
	// listens on: every tcp/443 probe died on "Resolving timed out", the move
	// reverted, and after three of those the node parked itself on the host path
	// for good — while real clients, pointed at the exits, resolved fine. A fresh
	// stand, 2026-09-08. The gateway remains the fallback for a spec that carries
	// no list at all.
	if servers := proberResolvers(*cw); len(servers) > 0 {
		resolvPath := p.resolvPath
		if resolvPath == "" {
			resolvPath = synthResolvConf
		}
		var b strings.Builder
		b.WriteString("# Rendered by wgfleet — the prober resolves where clients resolve.\n")
		for _, ns := range servers {
			b.WriteString("nameserver " + ns + "\n")
		}
		resolv, rerr := reconcile.FileAction(resolvPath, []byte(b.String()), 0o644, nil)
		if rerr != nil {
			return nil, rerr
		}
		actions = append(actions, resolv)
	}

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
	// Created HERE and moved THERE: the socket stays in this namespace, which is
	// the only reason the prober can dial 127.0.0.1 at all.
	build := []reconcile.Action{
		// Clear a leftover in THIS namespace before creating one here.
		//
		// The device is created here and moved there, so a build interrupted between
		// those two steps leaves the interface on the host — where the check above,
		// which looks only inside the namespace, cannot see it. Every pass afterwards
		// plans the same `ip link add` and gets `File exists`, forever. Found on the
		// stand 2026-09-06: the prober had been wedged since the previous day, and
		// because this device is the judge of the automatic revert, the migration was
		// reverted three times and then abandoned — by a netdev sitting in the wrong
		// namespace. Best-effort: on the normal path there is nothing to delete.
		reconcile.BestEffortExecAction("clear a half-built prober left in the host namespace",
			"ip", "link", "del", synthIface),
		reconcile.ExecAction("create the prober's interface", "ip", "link", "add", synthIface, "type", "amneziawg"),
		reconcile.ExecAction("configure the prober's device", "awg", "setconf", synthIface, p.confPath),
		reconcile.ExecAction("move the prober's interface into its namespace",
			"ip", "link", "set", synthIface, "netns", synthNetns),
		nsExec("address the prober", "ip", "addr", "add", addr, "dev", synthIface),
		nsExec("bring the prober up", "ip", "link", "set", synthIface, "up"),
		nsExec("bring the prober's loopback up", "ip", "link", "set", "lo", "up"),
		nsExec("route everything through the prober", "ip", "route", "replace", "default", "dev", synthIface),
	}
	switch {
	case ifErr != nil:
		actions = append(actions, build...)
	case file.Changes() || p.deviceHasStaleHeaderProtection(ctx, run, conf):
		// The device is REBUILT, not re-configured in place.
		//
		// `awg setconf` applies what the file says and cannot express what it no
		// longer says: a parameter the device already carries and the config has
		// dropped stays on the device. Measured on the stand 2026-09-05 — the prober
		// was created while the spec carried AmneziaWG 3.x parameters, the spec then
		// went back to 2.0, `setconf` re-applied cleanly, and the device kept its
		// header protection key. The server had none, so not one handshake completed
		// and every client-path probe was red — with the config file on disk looking
		// exactly right.
		//
		// That failure is worse here than anywhere else: this device is the judge of
		// the automatic revert, so a prober that cannot handshake makes every
		// migration look broken and reverts it. One pass without a measurement is the
		// cheaper mistake.
		//
		// The trigger is not the config file alone. On the stand the file was already
		// correct — it had been rewritten by an earlier pass — while the DEVICE still
		// carried the old key, so `file.Changes()` was false and nothing ever repaired
		// it. What has to be compared is the kernel against the intent, which is the
		// same lesson NFTApply learned about `.applied` markers.
		actions = append(actions, nsExec("remove the prober's interface (its parameters changed)",
			"ip", "link", "del", synthIface))
		actions = append(actions, build...)
	default:
		actions = append(actions, reconcile.NoChangeAction("client path prober", "prober already up"))
	}
	return actions, nil
}

// deviceHasStaleHeaderProtection reports whether the live prober device carries a
// header protection key that the rendered config does not set.
//
// Only this one parameter, and that is a statement about AmneziaWG rather than a
// shortcut: of everything 3.x added, the header protection key is the one that
// breaks the wire outright — two ends disagreeing about it exchange packets
// neither can parse, and no handshake ever completes. The timers and padding
// negotiate or are ignored. So this is the parameter whose survival on a device
// silently kills the prober, and the one worth reading the kernel for.
//
// The output holds key material, so it is tested for presence and never kept,
// logged, or put in an error.
func (p synthPlanner) deviceHasStaleHeaderProtection(ctx context.Context, run netns.Runner, cfg string) bool {
	if strings.Contains(cfg, "HeaderProtectionKey") {
		return false // the config asks for one; whatever the device has is intended
	}
	out, err := run(ctx, "ip", "netns", "exec", synthNetns, "awg", "show", synthIface)
	if err != nil {
		return false // cannot look; do not rebuild on a guess
	}
	return strings.Contains(out, "header protection key:")
}
