package keybroker

import (
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestAWGModuleBuildsAtLeast(t *testing.T) {
	node := func(pkg string, reloadPending bool) domain.Node {
		return domain.Node{AWGModule: domain.AWGModuleBuild{PackageVersion: pkg, ReloadPending: reloadPending}}
	}
	var (
		current = node("1.0.0-0~202609061402+4569c4c", false)
		older   = node("1.0.0-0~202608121130+0a1b2c3", false)
		pending = node("1.0.0-0~202609061402+4569c4c", true)
		never   = domain.Node{}
	)
	tests := []struct {
		name string
		ends []domain.Node
		want bool
	}{
		{name: "one kernel end on a current build", ends: []domain.Node{current}, want: true},
		{name: "every kernel end current", ends: []domain.Node{current, current}, want: true},
		{name: "one end on an older build", ends: []domain.Node{current, older}, want: false},
		{name: "one end never reported", ends: []domain.Node{current, never}, want: false},
		{name: "one end waiting for a module reload", ends: []domain.Node{pending, current}, want: false},
		{name: "no ends", ends: nil, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := awgModuleBuildsAtLeast(awgTrackBMinBuild, tc.ends...); got != tc.want {
				t.Errorf("awgModuleBuildsAtLeast(%d, ...) = %v, want %v", awgTrackBMinBuild, got, tc.want)
			}
		})
	}
}
