// Package compose renders the master node's container stack as a
// docker-compose.yml from the desired state. The master data plane runs as two
// containers: wg-easy (client-facing AmneziaWG server + UI) and mihomo (proxy
// router + load balancer). The agent writes this file and keeps the stack up
// with `docker compose up -d`; restarts of individual services happen when their
// mounted config changes (see the master reconcilers).
//
// The output is a structured map marshaled deterministically (yaml.v3 sorts map
// keys), which keeps dry-run diffs honest.
package compose

import (
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Host directories the stack mounts. They hold the agent-rendered configs.
const (
	wgEasyDir = "/etc/wireguard" // wg-easy db + generated wg configs (an earlier finding: per-node)
	mihomoDir = "/etc/mihomo"    // mihomo config.yaml + rule providers
)

// Default container images (repository:tag) when the spec leaves them unset.
// Exported so the controller can resolve operator image/tag overrides against
// the same canonical defaults the renderer falls back to.
const (
	DefaultWGEasyImage = "ghcr.io/wg-easy/wg-easy:15"
	DefaultMihomoImage = "metacubex/mihomo:latest"
	// DefaultWGEasyWebPort is the wg-easy admin UI port when the spec leaves it
	// unset. Exported so the controller UI can build a link to it.
	DefaultWGEasyWebPort = 44423
)

// RenderInput is everything needed to render the master compose file.
type RenderInput struct {
	Compose domain.ComposeSpec
	// ClientListenPort / ClientPool come from the master's client-facing AWG
	// server spec (WGServerSpec): the UDP port clients dial and their subnet.
	ClientListenPort int
	ClientPool       string
	// MgmtAddr is the master's ZeroTier address; admin endpoints bind it only.
	MgmtAddr string
}

// RenderMasterCompose renders docker-compose.yml for the master stack. The
// INIT_* environment variables seed wg-easy on first run only (it ignores them
// once set up); obfuscation is configured separately by writing wg-easy's
// SQLite DB (ADR-0008), since INIT_* cannot set it.
func RenderMasterCompose(in RenderInput) (string, error) {
	if in.MgmtAddr == "" {
		return "", fmt.Errorf("compose render: master mgmt address is required")
	}
	c := in.Compose

	wgEasyImage := orDefault(c.WGEasyImage, DefaultWGEasyImage)
	mihomoImage := orDefault(c.MihomoImage, DefaultMihomoImage)
	webPort := c.WGEasyWebPort
	if webPort == 0 {
		webPort = DefaultWGEasyWebPort
	}

	wgEasyEnv := []any{
		fmt.Sprintf("PORT=%d", webPort),
		"HOST=" + in.MgmtAddr,
		"INSECURE=true",
		"EXPERIMENTAL_AWG=true",
		"OVERRIDE_AUTO_AWG=awg",
	}
	// First-run seeding (host/port/CIDR/DNS/allowed-ips). wg-easy ignores these
	// after initial setup; the operator may remove them later.
	if in.ClientPool != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_ENABLED=true", "INIT_IPV4_CIDR="+in.ClientPool)
	}
	if c.PublicIP != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_HOST="+c.PublicIP)
	}
	if in.ClientListenPort > 0 {
		wgEasyEnv = append(wgEasyEnv, fmt.Sprintf("INIT_PORT=%d", in.ClientListenPort))
	}
	if len(c.ClientDNS) > 0 {
		wgEasyEnv = append(wgEasyEnv, "INIT_DNS="+strings.Join(c.ClientDNS, ","))
	}
	if c.ClientAllowedIPs != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_ALLOWED_IPS="+c.ClientAllowedIPs)
	}

	doc := map[string]any{
		"services": map[string]any{
			"wg-easy": map[string]any{
				"image":          wgEasyImage,
				"container_name": "wg-easy",
				"restart":        "unless-stopped",
				"network_mode":   "host",
				"cap_add":        []any{"NET_ADMIN", "SYS_MODULE"},
				"volumes": []any{
					wgEasyDir + ":/etc/wireguard",
					"/lib/modules:/lib/modules:ro",
				},
				"environment": wgEasyEnv,
			},
			"mihomo": map[string]any{
				"image":          mihomoImage,
				"container_name": "mihomo",
				"restart":        "always",
				"network_mode":   "host",
				"cap_add":        []any{"NET_ADMIN", "SYS_PTRACE"},
				"volumes":        []any{mihomoDir + ":/etc/mihomo"},
				"command":        "-d /etc/mihomo",
				"depends_on":     []any{"wg-easy"},
			},
		},
	}

	out, err := marshalYAML(doc)
	if err != nil {
		return "", fmt.Errorf("compose render: %w", err)
	}
	return out, nil
}

// MihomoDir / WGEasyDir expose the mounted host directories so the agent renders
// configs into the same place the containers read them.
func MihomoDir() string { return mihomoDir }
func WGEasyDir() string { return wgEasyDir }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func marshalYAML(v any) (string, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		// Close flushes the final node; a truncated flush would write a corrupt
		// config to disk. Surface it instead of shipping invalid YAML.
		return "", fmt.Errorf("flush yaml: %w", err)
	}
	return b.String(), nil
}
