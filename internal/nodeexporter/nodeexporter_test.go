package nodeexporter

import (
	"strings"
	"testing"
)

// The exporter must bind the management overlay and nothing else: node metrics
// list every listening socket and mounted filesystem on the box, which is a map
// of the node for anyone who can reach the port.
func TestRenderDefaultsBindsTheMgmtAddress(t *testing.T) {
	got := RenderDefaults("172.29.3.10")
	if !strings.Contains(got, `--web.listen-address=172.29.3.10:9100`) {
		t.Fatalf("defaults do not bind the mgmt address:\n%s", got)
	}
	if !strings.Contains(got, "\nARGS=") {
		t.Fatalf("Debian's unit reads $ARGS from this file; got:\n%s", got)
	}
}

// No mgmt address is not a licence to bind everything: the package default is
// 0.0.0.0, and a node whose overlay address is unknown must fall back to loopback.
func TestRenderDefaultsWithoutMgmtFallsBackToLoopback(t *testing.T) {
	got := RenderDefaults("")
	if !strings.Contains(got, "127.0.0.1:9100") {
		t.Fatalf("empty mgmt must bind loopback, got:\n%s", got)
	}
	if strings.Contains(got, "0.0.0.0") {
		t.Fatalf("must never bind the wildcard:\n%s", got)
	}
}

// The overlay address exists only once ZeroTier has joined, and the exporter
// cannot bind an address the kernel does not have yet. The drop-in orders it
// after the overlay and keeps retrying instead of giving up at boot.
func TestDropInSurvivesBootBeforeTheOverlay(t *testing.T) {
	for _, want := range []string{"After=zerotier-one.service", "Restart=on-failure", "RestartSec=", "StartLimitIntervalSec=0"} {
		if !strings.Contains(DropIn, want) {
			t.Errorf("drop-in lacks %q:\n%s", want, DropIn)
		}
	}
}
