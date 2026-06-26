package exit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func TestEffectiveWARPMTU(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "warp-mtu")

	// No override, no cache ⇒ DefaultWARPMTU.
	if got := effectiveWARPMTU(domain.NodeSpec{}, cache); got != wg.DefaultWARPMTU {
		t.Errorf("default = %d, want %d", got, wg.DefaultWARPMTU)
	}
	// Cache present ⇒ cached value.
	_ = os.WriteFile(cache, []byte("1340\n"), 0o644)
	if got := effectiveWARPMTU(domain.NodeSpec{}, cache); got != 1340 {
		t.Errorf("cached = %d, want 1340", got)
	}
	// Operator override wins over the cache.
	if got := effectiveWARPMTU(domain.NodeSpec{WARPMTU: 1320}, cache); got != 1320 {
		t.Errorf("override = %d, want 1320", got)
	}
	// Garbage cache ⇒ default (not a crash / not a too-small value).
	_ = os.WriteFile(cache, []byte("nope\n"), 0o644)
	if got := effectiveWARPMTU(domain.NodeSpec{}, cache); got != wg.DefaultWARPMTU {
		t.Errorf("garbage cache = %d, want default", got)
	}
}
