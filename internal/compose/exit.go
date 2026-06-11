package compose

import (
	"fmt"
	"path/filepath"
)

// DefaultBlockyImage (repository:tag) is used when the spec leaves the image
// unset. Exported so the controller resolves image/tag overrides against the
// same canonical default the renderer falls back to.
const DefaultBlockyImage = "spx01/blocky:latest"

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
