package version

import "testing"

func TestShort(t *testing.T) {
	save := func() (string, string) { return Version, Commit }
	restore := func(v, c string) { Version, Commit = v, c }
	v0, c0 := save()
	defer restore(v0, c0)

	tests := []struct {
		name            string
		version, commit string
		want            string
	}{
		{"no commit", "v1.2.3", "none", "v1.2.3"},
		{"empty commit", "v1.2.3", "", "v1.2.3"},
		{"same sha is not doubled", "c6c2278", "c6c2278", "c6c2278"},
		{"dirty sha keeps the marker", "c6c2278", "c6c2278-dirty", "c6c2278-dirty"},
		{"tag plus commit", "v1.2.3", "abc1234", "v1.2.3+abc1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version, Commit = tt.version, tt.commit
			if got := Short(); got != tt.want {
				t.Fatalf("Short() with Version=%q Commit=%q = %q, want %q", tt.version, tt.commit, got, tt.want)
			}
		})
	}
}
