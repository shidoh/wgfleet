package exit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
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
// port can be refused while the others answer: an exit's handshakes to :2408 can
// draw ICMP port-unreachable while :500, :1701, :4500 answer.
var warpEndpointPorts = []string{"2408", "500", "1701", "4500"}

// warpResolveTimeout bounds one lookup of the endpoint host.
const warpResolveTimeout = 5 * time.Second

const bootIDPath = "/proc/sys/kernel/random/boot_id"

// warpEndpointState is the fallback's memory, kept on disk because planners are
// rebuilt every pass. Candidate is the picked candidate's key and Endpoint what
// wgcf.conf carries for it: an address literal resolved when the candidate was
// picked, or the name itself for a by-name candidate. A state without a
// candidate (none yet, or written by an older agent) is no pick. SilentSince is
// the first pass that saw silence on it, valid only within BootID's boot. Rounds
// counts full passes over the candidates without a handshake (the back-off).
type warpEndpointState struct {
	Candidate   string    `json:"candidate,omitempty"`
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

// warpCandidate is one way to reach Cloudflare's WARP endpoint: an address
// family and a port on the endpoint host, or (Family empty) a name handed to
// wg-quick as is, which resolves it itself.
type warpCandidate struct {
	Family domain.WARPIPFamily
	Host   string
	Port   string
}

func (c warpCandidate) hostPort() string { return net.JoinHostPort(c.Host, c.Port) }

// key names the candidate in the state file and the log.
func (c warpCandidate) key() string {
	if c.Family == "" {
		return c.hostPort()
	}
	return string(c.Family) + " " + c.hostPort()
}

// network is the resolver network for the candidate's family.
func (c warpCandidate) network() string {
	if c.Family == domain.WARPIPFamilyIPv6 {
		return "ip6"
	}
	return "ip4"
}

// accepts reports whether endpoint is what wgcf.conf may carry for c: the name
// itself for a by-name candidate, else an address of c's family on c's port.
// It guards the render against a state file that says anything else.
func (c warpCandidate) accepts(endpoint string) bool {
	if c.Family == "" {
		return endpoint == c.hostPort()
	}
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil || strconv.Itoa(int(ap.Port())) != c.Port {
		return false
	}
	if c.Family == domain.WARPIPFamilyIPv6 {
		return ap.Addr().Is6() && !ap.Addr().Is4In6()
	}
	return ap.Addr().Is4()
}

// warpEndpointCandidates lists the ways to reach WARP in the order they are
// tried. Each family gets every WARP port on Cloudflare's endpoint host, the
// profile's port first; auto tries IPv4, then IPv6, and ends with the profile's
// endpoint by name. A profile endpoint off Cloudflare's host goes first in auto.
func warpEndpointCandidates(profile string, family domain.WARPIPFamily) []warpCandidate {
	if profile == "" {
		profile = egress.DefaultWARPEndpoint
	}
	host, defPort, err := net.SplitHostPort(egress.DefaultWARPEndpoint)
	if err != nil {
		return nil
	}
	ports := []string{defPort}
	pHost, pPort, perr := net.SplitHostPort(profile)
	if perr == nil && pHost == host {
		ports = []string{pPort}
	}
	for _, port := range warpEndpointPorts {
		if !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	var families []domain.WARPIPFamily
	switch family.OrAuto() {
	case domain.WARPIPFamilyIPv4:
		families = []domain.WARPIPFamily{domain.WARPIPFamilyIPv4}
	case domain.WARPIPFamilyIPv6:
		families = []domain.WARPIPFamily{domain.WARPIPFamilyIPv6}
	default:
		families = []domain.WARPIPFamily{domain.WARPIPFamilyIPv4, domain.WARPIPFamilyIPv6}
	}

	var out []warpCandidate
	byName := warpCandidate{Host: pHost, Port: pPort}
	auto := family.OrAuto() == domain.WARPIPFamilyAuto
	if auto && perr == nil && pHost != host {
		out = append(out, byName)
	}
	for _, f := range families {
		for _, port := range ports {
			out = append(out, warpCandidate{Family: f, Host: host, Port: port})
		}
	}
	if auto && perr == nil && pHost == host {
		out = append(out, byName)
	}
	return out
}

// pickedWARPCandidate returns the index of the state's pick among candidates and
// the endpoint it renders, or -1 when the state holds no valid pick.
func pickedWARPCandidate(candidates []warpCandidate, st warpEndpointState) (int, string) {
	if st.Candidate == "" {
		return -1, ""
	}
	for i, c := range candidates {
		if c.key() == st.Candidate && c.accepts(st.Endpoint) {
			if c.Family == "" {
				return i, st.Endpoint
			}
			return i, netip.MustParseAddrPort(st.Endpoint).String()
		}
	}
	return -1, ""
}

// pickedWARPEndpoint is the endpoint wgcf.conf should carry: the fallback's pick
// when it is a valid one for this family, else the profile's (until the
// fallback planner makes its first pick).
func pickedWARPEndpoint(profile string, family domain.WARPIPFamily, statePath string) string {
	st, _ := readWARPEndpointState(statePath)
	if i, ep := pickedWARPCandidate(warpEndpointCandidates(profile, family), st); i >= 0 {
		return ep
	}
	if profile == "" {
		return egress.DefaultWARPEndpoint
	}
	return profile
}

// resolveWARPCandidate turns a candidate into the endpoint wgcf.conf carries:
// the name as is for a by-name candidate, else the first address of the
// candidate's family.
func resolveWARPCandidate(ctx context.Context, c warpCandidate, lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)) (string, error) {
	if c.Family == "" {
		return c.hostPort(), nil
	}
	cctx, cancel := context.WithTimeout(ctx, warpResolveTimeout)
	defer cancel()
	addrs, err := lookup(cctx, c.network(), c.Host)
	if err != nil {
		return "", fmt.Errorf("resolve %s (%s): %w", c.Host, c.Family, err)
	}
	for _, a := range addrs {
		cand := net.JoinHostPort(a.Unmap().String(), c.Port)
		if c.accepts(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("resolve %s: no %s address", c.Host, c.Family)
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
	// lookup resolves the endpoint host; nil ⇒ the system resolver.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
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

func (p warpEndpointPlanner) resolve(ctx context.Context, c warpCandidate) (string, error) {
	lookup := p.lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	return resolveWARPCandidate(ctx, c, lookup)
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
	candidates := warpEndpointCandidates(p.warp.Endpoint, spec.WARPIPFamily)
	idx, current := pickedWARPCandidate(candidates, st)
	if idx < 0 {
		// No pick yet (a fresh node, or state from an agent that dialled the name):
		// take the first candidate that resolves. On a node that was handshaking by
		// name this costs one wgcf restart, the price of not leaving the family to
		// the resolver's AAAA-first order.
		return []reconcile.Action{p.pick(candidates, 0, warpEndpointState{BootID: boot}, now,
			"no WARP endpoint picked yet: take the first that resolves", false).BestEffort()}, nil
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
		st.SilentSince, st.BootID = now, boot
		return []reconcile.Action{p.write(st, "no WARP handshake on "+current+": start watching", nil)}, nil
	}
	silent, dwell := now.Sub(st.SilentSince), warpEndpointDwell(st.Rounds)
	if silent < dwell {
		return []reconcile.Action{reconcile.NoChangeAction(target,
			fmt.Sprintf("no handshake on %s for %s of %s", current, silent.Round(time.Second), dwell))}, nil
	}

	summary := fmt.Sprintf("no WARP handshake on %s for %s: switch to the next endpoint", current, silent.Round(time.Second))
	move := p.pick(candidates, idx+1, warpEndpointState{Rounds: st.Rounds, BootID: boot}, now, summary, true)
	// Ask once more right before the write: a handshake that arrived since Plan
	// read it cancels the move. Best-effort, so a cancelled move is a warning in
	// the log, not a failed pass that would mark the node Degraded.
	return []reconcile.Action{move.OnlyIf("wgcf still has no handshake", func(ctx context.Context) bool {
		hs, err := p.readHandshake(ctx)
		return err == nil && !warpHandshakeLive(hs, p.nowTime())
	}).BestEffort()}, nil
}

// pick writes the first candidate from index from on (wrapping) that resolves.
// Wrapping past the end counts a round of the back-off. watch starts the
// silence watch on the new pick, so a dead one is left a window later even if
// it never handshakes.
func (p warpEndpointPlanner) pick(candidates []warpCandidate, from int, base warpEndpointState, now time.Time, summary string, watch bool) reconcile.Action {
	return reconcile.CustomAction(reconcile.ActionUpdate, p.statePath, summary, candidates[from%len(candidates)].key(),
		func(ctx context.Context) error {
			var errs []error
			for n := range len(candidates) {
				i := (from + n) % len(candidates)
				c := candidates[i]
				ep, err := p.resolve(ctx, c)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				st := base
				st.Candidate, st.Endpoint, st.Since = c.key(), ep, now
				if from+n >= len(candidates) && watch {
					st.Rounds++
				}
				if watch {
					st.SilentSince = now
				}
				if err := writeWARPEndpointState(p.statePath, st); err != nil {
					return err
				}
				if watch {
					slog.Warn("WARP endpoint gives no handshake; switching to the next one",
						"to", ep, "candidate", st.Candidate, "failed_rounds", st.Rounds,
						"next_window", warpEndpointDwell(st.Rounds).String())
				} else {
					slog.Info("WARP endpoint picked", "endpoint", ep, "candidate", st.Candidate)
				}
				return nil
			}
			return fmt.Errorf("no WARP endpoint candidate resolves: %w", errors.Join(errs...))
		})
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
