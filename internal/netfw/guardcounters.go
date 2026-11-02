package netfw

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// GuardChains are the chains whose whole purpose is to catch what must not happen:
// a client address reaching the wire, and a client packet leaving by a path nobody
// chose. Named here rather than discovered so a chain that disappears from the
// ruleset is reported as gone rather than silently stopping being observed.
var GuardChains = []string{"egress_leak_guard", "egress_path_guard"}

// GuardDrops reads each guard chain's packet counter.
//
// Counters that nothing exports can drop client packets for days without anyone
// noticing, until someone runs `nft list chain` by hand. A number that is only readable by
// hand is a number nobody reads.
//
// A missing chain is omitted rather than reported as zero: on a master that has
// not moved, egress_path_guard is not rendered at all, and "zero drops" would be a
// claim about a rule that does not exist.
func GuardDrops(ctx context.Context, run func(ctx context.Context, name string, args ...string) (string, error)) map[string]int {
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return string(out), err
		}
	}
	drops := map[string]int{}
	for _, chain := range GuardChains {
		out, err := run(ctx, "nft", "list", "chain", "ip", MasterNATTable, chain)
		if err != nil {
			continue
		}
		if n, ok := firstCounter(out); ok {
			drops[chain] = n
		}
	}
	return drops
}

// firstCounter pulls the packet count out of `nft list chain` output. Each guard
// chain holds exactly one counted rule; a chain that grows a second one would need
// this to say which, so it takes the first and the callers know it.
func firstCounter(out string) (int, bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		for i, f := range fields {
			if f != "packets" || i+1 >= len(fields) {
				continue
			}
			if n, err := strconv.Atoi(fields[i+1]); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}
