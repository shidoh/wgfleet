package domain

import "testing"

func TestParseAWGBuildStamp(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    uint64
	}{
		{name: "ppa build", version: "1.0.0-0~202609061402+4569c4c", want: 202609061402},
		{name: "older ppa build", version: "1.0.0-0~202608121130+0a1b2c3", want: 202608121130},
		{name: "distro suffix after the commit", version: "1.0.0-0~202609061402+4569c4c~ubuntu24.04.1", want: 202609061402},
		{name: "surrounding whitespace", version: "  1.0.0-0~202609061402+4569c4c\n", want: 202609061402},
		{name: "no commit suffix", version: "1.0.0-0~202609061402", want: 202609061402},
		{name: "empty", version: "", want: 0},
		{name: "upstream version only", version: "1.0.0", want: 0},
		{name: "garbled", version: "~~~+++", want: 0},
		{name: "too few digits", version: "1.0.0-0~2026090614+4569c4c", want: 0},
		{name: "too many digits", version: "1.0.0-0~20260906140200+4569c4c", want: 0},
		{name: "impossible month", version: "1.0.0-0~202613061402+4569c4c", want: 0},
		{name: "impossible hour", version: "1.0.0-0~202609062502+4569c4c", want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseAWGBuildStamp(tc.version); got != tc.want {
				t.Errorf("ParseAWGBuildStamp(%q) = %d, want %d", tc.version, got, tc.want)
			}
		})
	}
}

func TestAWGModuleBuildAtLeast(t *testing.T) {
	const min = 202609060000
	tests := []struct {
		name  string
		build AWGModuleBuild
		want  bool
	}{
		{name: "newer build", build: AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c"}, want: true},
		{name: "exactly the minimum", build: AWGModuleBuild{PackageVersion: "1.0.0-0~202609060000+4569c4c"}, want: true},
		{name: "older build", build: AWGModuleBuild{PackageVersion: "1.0.0-0~202608121130+0a1b2c3"}, want: false},
		{name: "never reported", build: AWGModuleBuild{}, want: false},
		{name: "unparseable version", build: AWGModuleBuild{PackageVersion: "1.0.0"}, want: false},
		{
			name:  "new package on disk, old module still loaded",
			build: AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", ReloadPending: true},
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.build.AtLeast(min); got != tc.want {
				t.Errorf("%+v.AtLeast(%d) = %v, want %v", tc.build, min, got, tc.want)
			}
		})
	}
}

func TestAWGModuleBuildLabel(t *testing.T) {
	tests := []struct {
		name  string
		build AWGModuleBuild
		want  string
	}{
		{name: "known", build: AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c"}, want: "202609061402"},
		{name: "never reported", build: AWGModuleBuild{}, want: "unknown"},
		{name: "reload pending", build: AWGModuleBuild{PackageVersion: "1.0.0-0~202609061402+4569c4c", ReloadPending: true}, want: "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.build.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}
