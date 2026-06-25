package netfw

import "os/exec"

// TableLoaded reports whether the live kernel currently has the nft table
// <family> <name> (e.g. "inet" wgfleet, "ip" wgfleet_master). It is the shared
// kernel probe behind the agents' firewall/NAT self-heal: `nft list table
// <family> <name>` succeeds only when the table is present. Any exec error
// (table absent, non-Linux dev box, missing nft) reports "not loaded", so the
// caller re-applies — harmless in plan mode, self-healing on a real node.
func TableLoaded(family, name string) bool {
	return exec.Command("nft", "list", "table", family, name).Run() == nil
}
