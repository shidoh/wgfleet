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
	// Pinned, NOT :latest (docs/DESIGN.md #8) — reproducible/auditable deploys. v1.19.27 is the
	// operator's known-good prod version. (The AWG-param safety that keeps mihomo's
	// amneziawg-go from panicking is handled in the derivation: Jmin is floored ≥ S4, so no
	// junk packet underflows its S4-strip — see internal/wg junkS4Margin. So this pin is
	// for reproducibility, not a kernel↔mihomo version-match requirement.)
	DefaultMihomoImage = "metacubex/mihomo:v1.19.27"
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
	// First-run seeding (host/port/CIDR/DNS/allowed-ips). wg-easy applies INIT_*
	// only at first DB creation, AND several are conditionally gated in v15:
	// INIT_IPV4_CIDR applies only when INIT_IPV6_CIDR is ALSO set, and
	// INIT_HOST/INIT_PORT only inside the INIT_USERNAME+INIT_PASSWORD block — none of
	// which we set (ADR-0008: operator runs the setup wizard). So INIT_IPV4_CIDR/
	// INIT_HOST/INIT_PORT are effectively no-ops here; the port/pool/MTU are enforced
	// authoritatively by the agent's direct DB write (internal/wgeasy ColumnsFromSpec).
	// We still pass them as harmless intent + in case the operator later enables the
	// unattended-setup vars. INIT_DNS/INIT_ALLOWED_IPS DO apply on first run.
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
