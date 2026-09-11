package compose

import (
	"fmt"
	"path/filepath"
)

// DefaultBlockyImage (repository:tag) is used when the spec leaves the image
// unset. Exported so the controller resolves image/tag overrides against the
// same canonical default the renderer falls back to.
//
// Pinned, NOT :latest — same rule as mihomo and xray (docs/DESIGN.md #8). The
// moving tag gave neither reproducibility nor freshness: docker only re-reads a
// tag when something pulls it, so every exit sat on v0.32.1 (pulled 2026-06-20)
// while upstream had moved three releases on, and nothing in the fleet said so.
//
// Bumped :latest -> v0.35.0 (2026-09-10, upstream released 2026-09-05). What we
// care about in 0.33-0.35: DoH queries are retried when a pooled connection is
// stale, fallbackUpstream works again for rewritten queries, NOTFQDN gets a
// well-formed NXDOMAIN, and EDNS0 cookies are no longer passed through. Note the
// new "refused" block type is NOT for us — blockType stays nxDomain, because a
// non-answer is what keeps mihomo's health checks honest (zeroIP once poisoned
// them with 8400 false failures).
const DefaultBlockyImage = "spx01/blocky:v0.35.0"

// BlockyInput is everything needed to render the exit node's DNS-filter stack.
type BlockyInput struct {
	Image string // container image; defaults to spx01/blocky
	// ConfigPath is the host path of the rendered blocky config.yml; it is
	// mounted into the container at /app/config.yml.
	ConfigPath string
	// Timezone synchronizes container log timestamps with the host (optional).
	Timezone string
}

// RenderBlockyCompose renders docker-compose.yml for the exit's blocky resolver.
// blocky runs on the host network so its config-pinned binds (loopback + the
// mgmt/ZT address) are the real listen addresses, and NET_BIND_SERVICE lets it
// claim the privileged DNS ports without running as root.
func RenderBlockyCompose(in BlockyInput) (string, error) {
	if in.ConfigPath == "" {
		return "", fmt.Errorf("compose render: blocky config path is required")
	}
	image := orDefault(in.Image, DefaultBlockyImage)

	env := []any{}
	volumes := []any{in.ConfigPath + ":/app/config.yml:ro"}
	if in.Timezone != "" {
		env = append(env, "TZ="+in.Timezone)
		volumes = append([]any{"/etc/localtime:/etc/localtime:ro"}, volumes...)
	}

	svc := map[string]any{
		"image":          image,
		"container_name": "blocky",
		"restart":        "unless-stopped",
		"network_mode":   "host",
		"cap_add":        []any{"NET_BIND_SERVICE"},
		"volumes":        volumes,
		// Bound the log, for the reason the master's own stack learned it: docker's
		// json-file driver has no rotation at all, so a container that starts writing
		// errors in a loop fills the disk of a node whose whole job is to keep running.
		// Measured across the fleet 2026-09-05: two containers out of eighteen had a
		// limit, and this one had reached 45 MB on an exit nobody had looked at.
		"logging": map[string]any{
			"driver":  "json-file",
			"options": map[string]any{"max-size": "10m", "max-file": "3"},
		},
	}
	if len(env) > 0 {
		svc["environment"] = env
	}

	doc := map[string]any{
		"services": map[string]any{"blocky": svc},
	}

	out, err := marshalYAML(doc)
	if err != nil {
		return "", fmt.Errorf("compose render: %w", err)
	}
	return out, nil
}

// BlockyConfigPathFor returns the conventional config path next to a given
// compose file (same directory), so the planner and renderer agree on layout.
func BlockyConfigPathFor(composePath string) string {
	return filepath.Join(filepath.Dir(composePath), "config.yml")
}
