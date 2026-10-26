package exit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
)

// warpEndpointStaleAfter is when wgcf's latest handshake counts as silence. A
// live tunnel with a 25 s keepalive stays well under it: when we initiated the
// session we rekey every 2 min; when Cloudflare did, our keypair expires at
// 180 s and the next keepalive re-handshakes, so the age peaks near 3.5 min.
// 5 min leaves 90 s — eighteen 5 s handshake retries — on top of that.
const warpEndpointStaleAfter = 5 * time.Minute

// warpEndpointWindow is how long silence must be OBSERVED, pass after pass,
// before the tunnel moves to the next endpoint. It counts from the first pass
// that saw the silence, never from the agent's start, so a wgcf brought up for
// any reason gets the full window to handshake first.
const warpEndpointWindow = 3 * time.Minute

// warpEndpointMaxDwell caps the back-off once every endpoint has failed: a
// Cloudflare-wide or uplink outage bounces wgcf at most this often.
const warpEndpointMaxDwell = 30 * time.Minute

// warpEndpointPorts are the UDP ports Cloudflare's WARP endpoint serves. One
// port can be refused while the others answer: on 2026-10-26 an exit's
// handshakes to :2408 drew ICMP port-unreachable and :500, :1701, :4500 answered.
var warpEndpointPorts = []string{"2408", "500", "1701", "4500"}

const bootIDPath = "/proc/sys/kernel/random/boot_id"

// warpEndpointState is the fallback's memory, kept on disk because planners are
// rebuilt every pass. Endpoint is the pick (empty: the profile's). SilentSince is
// the first pass that saw silence on it, valid only within BootID's boot. Rounds
// counts full passes over the candidates without a handshake (the back-off).
type warpEndpointState struct {
	Endpoint    string    `json:"endpoint,omitempty"`
	Since       time.Time `json:"since,omitzero"`
	SilentSince time.Time `json:"silent_since,omitzero"`
	Rounds      int       `json:"rounds,omitempty"`
	BootID      string    `json:"boot_id,omitempty"`
}

func (s warpEndpointState) watching() bool { return !s.SilentSince.IsZero() }

func readWARPEndpointState(path string) (warpEndpointState, bool) {
	if path == "" {
		return warpEndpointState{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("WARP endpoint state unreadable; using the profile endpoint", "path", path, "err", err)
		}
		return warpEndpointState{}, false
	}
	var st warpEndpointState
	if err := json.Unmarshal(data, &st); err != nil {
		slog.Warn("WARP endpoint state corrupt; using the profile endpoint", "path", path, "err", err)
		return warpEndpointState{}, false
	}
	return st, true
}

func writeWARPEndpointState(path string, st warpEndpointState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode warp endpoint state: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write warp endpoint state: %w", err)
	}
	return nil
}

// warpEndpointCandidates lists the endpoints to try, the profile's own first,
// then Cloudflare's default host on each WARP port.
func warpEndpointCandidates(profile string) []string {
	if profile == "" {
		profile = egress.DefaultWARPEndpoint
	}
	out := []string{profile}
	host, _, err := net.SplitHostPort(egress.DefaultWARPEndpoint)
	if err != nil {
		return out
	}
	for _, port := range warpEndpointPorts {
		if ep := net.JoinHostPort(host, port); !slices.Contains(out, ep) {
			out = append(out, ep)
		}
	}
	return out
}

// pickedWARPEndpoint is the endpoint wgcf.conf should carry: the fallback's pick
// when it is one of the candidates, else the profile's. With no pick on disk the
// rendered file is byte-for-byte what it was before the fallback existed.
func pickedWARPEndpoint(profile, statePath string) string {
	st, ok := readWARPEndpointState(statePath)
	if ok && st.Endpoint != "" && slices.Contains(warpEndpointCandidates(profile), st.Endpoint) {
		return st.Endpoint
	}
	return profile
}

// warpEndpointDwell is how long silence is watched in the given round.
func warpEndpointDwell(rounds int) time.Duration {
	d := warpEndpointWindow
	for i := 0; i < rounds && d < warpEndpointMaxDwell; i++ {
		d *= 2
	}
	return min(d, warpEndpointMaxDwell)
}

// warpEndpointPlanner moves wgcf to the next WARP endpoint once silence on the
// current one has been watched for a full window. It only writes the state
// file; the WARP planner renders the pick into wgcf.conf, and since the tunnel
// is already dead at that moment the wg-quick bounce costs nothing.
type warpEndpointPlanner struct {
	statePath string
	wgcfPath  string
	warp      *egress.WARPConfig
	now       func() time.Time
	// bootID identifies this boot; nil ⇒ the kernel's boot_id.
	bootID func() string
	// handshake reads wgcf's latest handshake (zero: none yet); nil ⇒ `wg show`.
	handshake func(ctx context.Context, iface string) (time.Time, error)
}

func newWARPEndpointPlanner(in Input) warpEndpointPlanner {
	return warpEndpointPlanner{statePath: in.Paths.WARPEndpointState, wgcfPath: in.Paths.WGCF, warp: in.WARP}
}

func (warpEndpointPlanner) Component() string { return "warp endpoint fallback" }

// Scheduled: a move is the planner reacting to the path, not spec drift.
func (warpEndpointPlanner) Scheduled() bool { return true }

func (p warpEndpointPlanner) nowTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p warpEndpointPlanner) boot() string {
	if p.bootID != nil {
		return p.bootID()
	}
	b, err := os.ReadFile(bootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (p warpEndpointPlanner) readHandshake(ctx context.Context) (time.Time, error) {
	if p.handshake != nil {
		return p.handshake(ctx, ifaceName(p.wgcfPath))
	}
	return wgLatestHandshake(ctx, ifaceName(p.wgcfPath))
}

// warpHandshakeLive reports whether a handshake this recent means the endpoint answers.
func warpHandshakeLive(lastHS, now time.Time) bool {
	return !lastHS.IsZero() && now.Sub(lastHS) < warpEndpointStaleAfter
}

func (p warpEndpointPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	const target = "warp endpoint"
	switch {
	case !spec.EgressChainHas(domain.EgressWARP):
		return []reconcile.Action{reconcile.NoChangeAction(target, "WARP not in the egress chain")}, nil
	case p.warp == nil:
		return []reconcile.Action{reconcile.NoChangeAction(target, "WARP not registered yet")}, nil
	case p.statePath == "":
		return []reconcile.Action{reconcile.NoChangeAction(target, "no state path configured")}, nil
	}

	now := p.nowTime()
	boot := p.boot()
	st, _ := readWARPEndpointState(p.statePath)
	if st.BootID != boot {
		st.SilentSince = time.Time{} // silence seen in another boot says nothing about this one
	}
	if st.SilentSince.After(now) {
		st.SilentSince = time.Time{} // stamped in the future (clock stepped back): watch afresh
	}
	candidates := warpEndpointCandidates(p.warp.Endpoint)
	current := pickedWARPEndpoint(p.warp.Endpoint, p.statePath)
	if !slices.Contains(candidates, current) {
		current = candidates[0]
	}

	lastHS, err := p.readHandshake(ctx)
	if err != nil {
		// Not knowing is never a reason to move, nor to keep counting silence.
		if !st.watching() {
			return []reconcile.Action{reconcile.NoChangeAction(target, "handshake unreadable: "+err.Error())}, nil
		}
		st.SilentSince = time.Time{}
		return []reconcile.Action{p.write(st, "handshake unreadable ("+err.Error()+"): stop watching "+current, nil)}, nil
	}

	if warpHandshakeLive(lastHS, now) {
		if !st.watching() && st.Rounds == 0 {
			return []reconcile.Action{reconcile.NoChangeAction(target, "handshaking on "+current)}, nil
		}
		rounds := st.Rounds
		st.SilentSince, st.Rounds = time.Time{}, 0
		return []reconcile.Action{p.write(st, "WARP handshakes on "+current+": stop watching", func() {
			slog.Info("WARP handshakes again; endpoint kept", "endpoint", current, "failed_rounds", rounds)
		})}, nil
	}

	if !st.watching() {
		st.Endpoint, st.SilentSince, st.BootID = current, now, boot
		return []reconcile.Action{p.write(st, "no WARP handshake on "+current+": start watching", nil)}, nil
	}
	silent, dwell := now.Sub(st.SilentSince), warpEndpointDwell(st.Rounds)
	if silent < dwell {
		return []reconcile.Action{reconcile.NoChangeAction(target,
			fmt.Sprintf("no handshake on %s for %s of %s", current, silent.Round(time.Second), dwell))}, nil
	}

	nextIdx := (slices.Index(candidates, current) + 1) % len(candidates)
	rounds := st.Rounds
	if nextIdx == 0 {
		rounds++
	}
	next := warpEndpointState{Endpoint: candidates[nextIdx], Since: now, SilentSince: now, Rounds: rounds, BootID: boot}
	summary := fmt.Sprintf("no WARP handshake on %s for %s: switch to %s", current, silent.Round(time.Second), next.Endpoint)
	move := p.write(next, summary, func() {
		slog.Warn("WARP endpoint gives no handshake; switching to the next one",
			"from", current, "to", next.Endpoint, "silent_for", silent.Round(time.Second),
			"failed_rounds", rounds, "next_window", warpEndpointDwell(rounds))
	})
	// Ask once more right before the write: a handshake that arrived since Plan
	// read it cancels the move. Best-effort, so a cancelled move is a warning in
	// the log, not a failed pass that would mark the node Degraded.
	return []reconcile.Action{move.OnlyIf("wgcf still has no handshake", func(ctx context.Context) bool {
		hs, err := p.readHandshake(ctx)
		return err == nil && !warpHandshakeLive(hs, p.nowTime())
	}).BestEffort()}, nil
}

func (p warpEndpointPlanner) write(st warpEndpointState, summary string, logIt func()) reconcile.Action {
	return reconcile.CustomAction(reconcile.ActionUpdate, p.statePath, summary, st.Endpoint,
		func(context.Context) error {
			if err := writeWARPEndpointState(p.statePath, st); err != nil {
				return err
			}
			if logIt != nil {
				logIt()
			}
			return nil
		})
}

// wgLatestHandshake reads the freshest handshake on a vanilla WireGuard
// interface (wgcf). Zero time: no handshake yet.
func wgLatestHandshake(ctx context.Context, iface string) (time.Time, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "wg", "show", iface, "latest-handshakes").Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("wg show %s latest-handshakes: %w", iface, err)
	}
	return parseWGHandshake(string(out)), nil
}

// parseWGHandshake returns the newest timestamp in `wg show latest-handshakes`
// output (one "<pubkey>\t<unix>" line per peer); zero when there is none.
func parseWGHandshake(out string) time.Time {
	var newest int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil && n > newest {
			newest = n
		}
	}
	if newest == 0 {
		return time.Time{}
	}
	return time.Unix(newest, 0)
}
