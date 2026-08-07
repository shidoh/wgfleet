// Package tuning holds node-level kernel tuning reconcilers shared by both agent
// roles. The BBR planner is the first: it switches TCP to the BBR congestion
// control with fq pacing, and enables packetization-layer PMTU discovery so a
// path that black-holes oversized segments cannot wedge a connection forever.
//
// Why this matters for wgfleet specifically: client traffic rides a multi-hop,
// partly-userspace obfuscated path (client userspace AWG → master → mihomo
// userspace WireGuard → exit → WARP). Such paths have non-trivial jitter and the
// odd packet loss. The default CUBIC congestion control treats every loss as
// congestion and collapses the window, so a single drop tanks throughput and a
// lost packet on a single long-lived connection (HTTP/2) stalls it for a full RTO
// backoff (~seconds). BBR is loss-tolerant — it paces by measured bandwidth/RTT
// and does NOT collapse on sporadic loss — which is exactly the right model for a
// lossy tunnel. It directly addresses both the low ZeroTier-overlay throughput and
// the HTTP/2-to-far-servers stalls observed live (see the project memory).
//
// Applied on every managed node (master AND exits): the master terminates the
// client↔mihomo and mihomo↔exit TCP, and any node-originated TCP (control plane,
// metrics, package pulls) benefits too. It cannot change the congestion control of
// endpoints wgfleet does not manage (the client device, a ZeroTier peer) — set BBR
// there separately.
package tuning

import (
	"context"
	"os"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

const (
	ccPath       = "/proc/sys/net/ipv4/tcp_congestion_control"
	availPath    = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	qdiscPath    = "/proc/sys/net/core/default_qdisc"
	mtuProbePath = "/proc/sys/net/ipv4/tcp_mtu_probing"
	wantCC       = "bbr"
	wantQdisc    = "fq"
	bbrModule    = "tcp_bbr"
	// mtuProbeOff is the kernel default: PLPMTUD disabled. Any non-zero value
	// enables probing (1 = after a suspected black hole, 2 = always), so the
	// planner only acts on "0" and never downgrades an operator's 2 to 1.
	mtuProbeOff = "0"
)

// bbrPlanner ensures BBR congestion control + fq pacing are active. Reads are
// injectable so tests neither touch /proc nor exec.
type bbrPlanner struct {
	// read returns the trimmed contents of a /proc/sys path, or "" on error.
	// nil ⇒ the real os.ReadFile.
	read func(path string) string
}

// BBRPlanner returns the node-tuning planner that enables BBR + fq.
func BBRPlanner() reconcile.Planner { return bbrPlanner{} }

func (bbrPlanner) Component() string { return "tcp tuning (bbr)" }

func (p bbrPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	cc := p.cur(ccPath)
	if cc == "" {
		// No /proc/sys (non-Linux dev box) or unreadable — nothing to tune, and this
		// must not be a "change" or it would churn forever / fail dry-run elsewhere.
		return []reconcile.Action{reconcile.NoChangeAction("tcp tuning", "unavailable (no /proc/sys)")}, nil
	}

	// Every step is BEST-EFFORT: BBR is a throughput/latency optimization, not a
	// correctness requirement, so a failure (sysctl missing, bbr genuinely
	// unavailable) must NEVER abort the reconcile and leave the node unconfigured.
	var actions []reconcile.Action

	// Load the module if BBR is not yet an available algorithm. Writing "bbr" to the
	// sysctl auto-loads it on most kernels, but not all — modprobe is the
	// belt-and-suspenders (harmless if BBR is built-in or already up).
	if !strings.Contains(p.cur(availPath), wantCC) {
		actions = append(actions, reconcile.BestEffortExecAction("load tcp_bbr module", "modprobe", bbrModule))
	}

	// Congestion control — the functionally critical bit (applies to new connections
	// immediately).
	if cc == wantCC {
		actions = append(actions, reconcile.NoChangeAction("tcp_congestion_control", "already bbr"))
	} else {
		actions = append(actions, reconcile.BestEffortExecAction("set TCP congestion control to bbr",
			"sysctl", "-w", "net.ipv4.tcp_congestion_control="+wantCC))
	}

	// Default qdisc: fq gives BBR its pacing offload. Changing it only affects newly
	// created qdiscs, so it never disrupts a live interface.
	if p.cur(qdiscPath) == wantQdisc {
		actions = append(actions, reconcile.NoChangeAction("default_qdisc", "already fq"))
	} else {
		actions = append(actions, reconcile.BestEffortExecAction("set default qdisc to fq (bbr pacing)",
			"sysctl", "-w", "net.core.default_qdisc="+wantQdisc))
	}

	// Packetization-layer PMTU discovery. With this off (the kernel default) a path
	// whose real MTU is below the interface MTU, and which filters the ICMP
	// "fragmentation needed" that would say so, becomes a black hole: the kernel keeps
	// retransmitting full-size segments that physically cannot pass, collapsing cwnd to
	// 1 and backing the RTO off to minutes. The connection never recovers — it hangs
	// rather than fails, which is far worse to diagnose.
	//
	// Observed live 2026-08-07 on the master→exit path: an agent binary upload wedged
	// with 41% of bytes retransmitted, only 2 KB ever acked, and no ACK for 9 minutes,
	// while small packets flowed fine. Enabling probing lets the kernel shrink the
	// segment size on its own and the transfer completes.
	//
	// Especially apt for this project: every managed node terminates or forwards
	// traffic over multi-hop obfuscated paths whose MTU we do not control (an earlier finding
	// and #18 are the same failure mode seen from the tunnel side).
	//
	// Only "0" is corrected — a non-zero value means probing is already on, and an
	// operator who chose the more aggressive mode 2 keeps it.
	if probe := p.cur(mtuProbePath); probe == "" {
		// Kernel too old to expose the knob (or no /proc): nothing to do, and it must
		// not read as a change or the planner would churn every pass.
		actions = append(actions, reconcile.NoChangeAction("tcp_mtu_probing", "unavailable"))
	} else if probe != mtuProbeOff {
		actions = append(actions, reconcile.NoChangeAction("tcp_mtu_probing", "already enabled (mode "+probe+")"))
	} else {
		actions = append(actions, reconcile.BestEffortExecAction("enable TCP MTU probing (escape PMTU black holes)",
			"sysctl", "-w", "net.ipv4.tcp_mtu_probing=1"))
	}

	return actions, nil
}

func (p bbrPlanner) cur(path string) string {
	if p.read != nil {
		return p.read(path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
