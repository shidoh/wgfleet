package wg

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// amneziawg-tools' config.c parses RandomTrailers as "on"/"off" and ignores an
// unknown key without a word, so the spelling is the whole contract.
func TestWriteAWG3RandomTrailers(t *testing.T) {
	var b strings.Builder
	writeAWG3(&b, domain.AWGShared{HeaderProtectionKey: "k", RandomTrailers: true})
	if !strings.Contains(b.String(), "RandomTrailers = on\n") {
		t.Errorf("rendered:\n%s", b.String())
	}
	b.Reset()
	writeAWG3(&b, domain.AWGShared{HeaderProtectionKey: "k"})
	if strings.Contains(b.String(), "RandomTrailers") {
		t.Errorf("trailers off but rendered:\n%s", b.String())
	}
}
