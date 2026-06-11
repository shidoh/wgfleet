package config

import "testing"

func TestResolveImage(t *testing.T) {
	const def = "spx01/blocky:latest"
	tests := []struct {
		name       string
		image, tag string
		def        string
		want       string
	}{
		{"all empty → default", "", "", def, "spx01/blocky:latest"},
		{"repo only → default tag", "spx01/blocky", "", def, "spx01/blocky:latest"},
		{"repo + explicit tag", "spx01/blocky", "v0.26", def, "spx01/blocky:v0.26"},
		{"explicit tag overrides default repo", "", "v0.26", def, "spx01/blocky:v0.26"},
		{"inline tag in image", "spx01/blocky:v0.25", "", def, "spx01/blocky:v0.25"},
		{"explicit tag beats inline tag", "spx01/blocky:v0.25", "v0.26", def, "spx01/blocky:v0.26"},
		{"custom repo + tag", "ghcr.io/me/blocky", "edge", def, "ghcr.io/me/blocky:edge"},
		{"registry port not a tag", "localhost:5000/blocky", "", def, "localhost:5000/blocky:latest"},
		{"registry port with explicit tag", "localhost:5000/blocky", "v1", def, "localhost:5000/blocky:v1"},
		{"default without tag, none given", "spx01/blocky", "", "metacubex/mihomo", "spx01/blocky"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveImage(tt.image, tt.tag, tt.def); got != tt.want {
				t.Errorf("ResolveImage(%q,%q,%q) = %q, want %q", tt.image, tt.tag, tt.def, got, tt.want)
			}
		})
	}
}
