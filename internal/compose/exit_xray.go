package compose

import (
	"fmt"
	"path/filepath"
)

// DefaultXrayImage (repository:tag) is the pinned xray-core image used when the
// spec leaves the image unset (no implicit :latest — every container the platform
// runs pins image AND tag). Exported so the controller resolves image/tag
// overrides against the same canonical default the renderer falls back to.
const DefaultXrayImage = "ghcr.io/xtls/xray-core:26.3.27"

// XrayInput is everything needed to render the exit node's REALITY inbound stack.
type XrayInput struct {
	Image string // container image; defaults to DefaultXrayImage
	// ConfigPath is the host path of the rendered xray config.json; it is mounted
	// into the container at /etc/xray/config.json.
	ConfigPath string
	// Timezone synchronizes container log timestamps with the host (optional).
	Timezone string
}

// RenderXrayCompose renders docker-compose.yml for the exit's xray-core REALITY
// inbound. xray runs on the host network so its listen port and SO_MARK'd outbound
// (routed to WARP by host policy routing) operate in the host's network namespace,
// matching the wg-easy/mihomo/blocky model. A plain VLESS+REALITY inbound needs no
// elevated capabilities.
func RenderXrayCompose(in XrayInput) (string, error) {
	if in.ConfigPath == "" {
		return "", fmt.Errorf("compose render: xray config path is required")
	}
	image := orDefault(in.Image, DefaultXrayImage)

	env := []any{}
	volumes := []any{in.ConfigPath + ":/etc/xray/config.json:ro"}
	if in.Timezone != "" {
		env = append(env, "TZ="+in.Timezone)
		volumes = append([]any{"/etc/localtime:/etc/localtime:ro"}, volumes...)
	}

	svc := map[string]any{
		"image":          image,
		"container_name": "xray",
		"restart":        "unless-stopped",
		"network_mode":   "host",
		"command":        []any{"run", "-c", "/etc/xray/config.json"},
		"volumes":        volumes,
		// Run as root so xray can read the 0600 config (it holds the REALITY private
		// key, kept root-only on the host) — the xray-core image otherwise runs as a
		// non-root user and gets "permission denied".
		"user": "0:0",
		// NET_ADMIN lets the freedom outbound set SO_MARK (sockopt.mark), which the
		// host policy routing matches to send xray's egress through WARP (ADR-0025,
		// an earlier finding). Without it the mark is silently dropped and egress misroutes.
		"cap_add": []any{"NET_ADMIN"},
	}
	if len(env) > 0 {
		svc["environment"] = env
	}

	doc := map[string]any{
		"services": map[string]any{"xray": svc},
	}

	out, err := marshalYAML(doc)
	if err != nil {
		return "", fmt.Errorf("compose render: %w", err)
	}
	return out, nil
}

// XrayConfigPathFor returns the conventional config path next to a given compose
// file (same directory), so the planner and renderer agree on layout.
func XrayConfigPathFor(composePath string) string {
	return filepath.Join(filepath.Dir(composePath), "config.json")
}
