package main

import (
	"net"
	"testing"
)

// TestListenersDoNotUseMPTCP guards the `godebug multipathtcp=0` line in go.mod:
// Go 1.24+ opens MPTCP listeners by default, and an MPTCP listener is what the
// CVE-2026-98432 remote root exploit needs. MultipathTCP reports the effective
// default, so this fails if the go.mod line goes away.
func TestListenersDoNotUseMPTCP(t *testing.T) {
	var lc net.ListenConfig
	if lc.MultipathTCP() {
		t.Fatal("listeners default to MPTCP; keep `godebug multipathtcp=0` in go.mod")
	}
}
