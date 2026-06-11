package domain

import (
	"strings"
	"testing"
)

func TestValidateUserspaceRejectsCtTags(t *testing.T) {
	base := validAWG()

	// <c> and <t> tags are valid in the kernel but break userspace WireGuard-Go.
	for _, tag := range []string{"<c>", "<t>", "<r 24><c>", "<b 0xc7><r 18><t>"} {
		p := base
		p.Local.I4 = tag
		// Plain Validate accepts them (kernel is fine).
		if err := p.Validate(); err != nil {
			t.Errorf("kernel Validate should accept %q: %v", tag, err)
		}
		// Userspace validation must reject them.
		if err := p.ValidateUserspace(); err == nil {
			t.Errorf("ValidateUserspace must reject %q", tag)
		} else if !strings.Contains(err.Error(), "userspace") {
			t.Errorf("error for %q should mention userspace: %v", tag, err)
		}
	}
}

func TestValidateUserspaceAcceptsSafeTags(t *testing.T) {
	p := validAWG()
	// Only <b>/<r>/<rc>/<rd> — safe for userspace.
	p.Local.I1 = "<r 2><b 0xdeadbeef>"
	p.Local.I2 = "<rc 8><rd 4>"
	if err := p.ValidateUserspace(); err != nil {
		t.Fatalf("safe tags should pass userspace validation: %v", err)
	}
}

func TestCustomConfigHasOverrides(t *testing.T) {
	if (CustomConfig{}).HasOverrides() {
		t.Error("empty custom config should have no overrides")
	}
	if !(CustomConfig{Overrides: map[string]any{"x": 1}}).HasOverrides() {
		t.Error("overrides map should count")
	}
	if !(CustomConfig{Files: []ManagedFile{{Path: "/x"}}}).HasOverrides() {
		t.Error("extra files should count")
	}
}
