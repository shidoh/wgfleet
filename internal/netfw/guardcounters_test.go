package netfw

import (
	"context"
	"errors"
	"testing"
)

// Guard counters readable only by hand hide client packet drops nobody sees.
func TestGuardDropsReadsWhatTheChainsCaught(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) < 5 {
			return "", errors.New("unexpected")
		}
		switch args[4] {
		case "egress_leak_guard":
			return "table ip wgfleet_master {\n\tchain egress_leak_guard {\n\t\ttype filter hook postrouting priority srcnat + 10; policy accept;\n\t\tip saddr 10.73.0.0/24 counter packets 200 bytes 20585 drop\n\t}\n}\n", nil
		case "egress_path_guard":
			return "table ip wgfleet_master {\n\tchain egress_path_guard {\n\t\ttype filter hook postrouting priority srcnat - 10; policy accept;\n\t\tip saddr 10.73.0.0/24 counter packets 0 bytes 0 drop\n\t}\n}\n", nil
		}
		return "", errors.New("no such chain")
	}
	got := GuardDrops(context.Background(), run)
	if got["egress_leak_guard"] != 200 {
		t.Errorf("the leak guard's 200 dropped packets were not read: %v", got)
	}
	if n, ok := got["egress_path_guard"]; !ok || n != 0 {
		t.Errorf("a guard that caught nothing must still be reported as zero: %v", got)
	}
}

// A chain that is not in the ruleset is absent, not zero: on a master that has not
// moved, egress_path_guard is not rendered at all, and "no drops" would be a claim
// about a rule that does not exist.
func TestAChainThatIsNotRenderedIsNotReportedAsZero(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if args[4] == "egress_leak_guard" {
			return "\t\tcounter packets 3 bytes 180 drop\n", nil
		}
		return "Error: No such file or directory", errors.New("exit status 1")
	}
	got := GuardDrops(context.Background(), run)
	if _, present := got["egress_path_guard"]; present {
		t.Errorf("a chain the ruleset does not have was reported anyway: %v", got)
	}
	if got["egress_leak_guard"] != 3 {
		t.Errorf("the chain that does exist was not read: %v", got)
	}
}
