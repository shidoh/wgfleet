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
	// Pinned, NOT :latest and NOT :Alpha (docs/DESIGN.md #8) — reproducible/auditable
	// deploys. (The AWG-param safety that keeps mihomo's amneziawg-go from panicking is
	// handled in the derivation: Jmin is floored ≥ S4, so no junk packet underflows its
	// S4-strip — see internal/wg junkS4Margin. So this pin is for reproducibility, not a
	// kernel↔mihomo version-match requirement.)
	//
	// Bumped 1.19.27 → 1.19.29 to retire the fleet's `mihomo_tag: "Alpha"` override. That
	// override existed because AWG 2.0 landed in Alpha before any release; it shipped in
	// v1.19.14 (2025-09-24), so the rationale is long obsolete — and `Alpha` is a MOVING
	// tag, which silently defeats the pin. Verified 2026-07-19 against the GitHub compare
	// API: v1.19.29...Alpha is `identical`, 0 commits apart, so this bump is a zero-code
	// delta from what the fleet already runs (live build alpha-8e2aba4).
	DefaultMihomoImage = "metacubex/mihomo:v1.19.29"
	// DefaultWGEasyWebPort is the wg-easy admin UI port when the spec leaves it
	// unset. Exported so the controller UI can build a link to it.
	DefaultWGEasyWebPort = 44423
	// defaultAdminUsername is the wg-easy admin account name used for unattended
	// setup when the input leaves the username empty (matches wgeasy.AdminUsername).
	defaultAdminUsername = "admin"
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
	// AdminUsername / AdminPassword drive wg-easy's unattended setup. They are
	// resolved agent-locally (the password is generated and persisted on-node,
	// never sent by the controller — ADR-0008). When the password is empty no
	// admin is seeded and wg-easy falls back to its interactive setup wizard.
	AdminUsername string
	AdminPassword string
}

// RenderMasterCompose renders docker-compose.yml for the master stack. The
// INIT_* environment variables seed wg-easy on first run only (it ignores them
// once set up); AmneziaWG obfuscation is configured separately by writing
// wg-easy's SQLite DB (ADR-0008), since INIT_* cannot set it.
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
	// First-run seeding. wg-easy applies INIT_* ONLY at first DB creation (it
	// ignores them once set up), and v15 gates them precisely (verified against
	// wg-easy 15.3.0 src/server/database/sqlite.ts initialSetup):
	//   - INIT_IPV4_CIDR applies only when INIT_IPV6_CIDR is ALSO set;
	//   - INIT_DNS / INIT_ALLOWED_IPS apply on their own (client-config defaults);
	//   - the setup WIZARD is skipped (setSetupStep(0)) ONLY when ALL of
	//     INIT_USERNAME + INIT_PASSWORD + INIT_HOST + INIT_PORT are present.
	// So to bring a fresh master up non-interactively we MUST supply the admin
	// credentials together with host+port — otherwise wg-easy stops at its setup
	// wizard asking for password/host/port (ADR-0008). The admin password is
	// resolved agent-locally and never crosses the wire. The interface columns
	// (port/pool/MTU + AmneziaWG obfuscation) are still enforced authoritatively by
	// the agent's direct DB write afterwards (internal/wgeasy ColumnsFromSpec).
	if in.ClientPool != "" || in.AdminPassword != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_ENABLED=true")
	}
	if in.ClientPool != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_IPV4_CIDR="+in.ClientPool)
	}
	if c.PublicIP != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_HOST="+c.PublicIP)
	}
	if in.ClientListenPort > 0 {
		wgEasyEnv = append(wgEasyEnv, fmt.Sprintf("INIT_PORT=%d", in.ClientListenPort))
	}
	if in.AdminPassword != "" {
		user := in.AdminUsername
		if user == "" {
			user = defaultAdminUsername
		}
		wgEasyEnv = append(wgEasyEnv,
			"INIT_USERNAME="+user,
			"INIT_PASSWORD="+in.AdminPassword,
		)
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

// redactedEnvKeys are the wg-easy env entries whose values are secret and must be
// masked in dry-run plan output / Web UI previews. The value still lands verbatim
// in the on-disk compose file (root-only).
var redactedEnvKeys = []string{"INIT_PASSWORD="}

// RedactComposeEnv masks secret env values (e.g. INIT_PASSWORD) in a rendered
// compose document so plan output and the Web UI never display them. It is the
// reconcile.Redactor for the master compose FileAction.
func RedactComposeEnv(yamlText string) string {
	lines := strings.Split(yamlText, "\n")
	for i, line := range lines {
		for _, key := range redactedEnvKeys {
			if idx := strings.Index(line, key); idx != -1 {
				lines[i] = line[:idx+len(key)] + "<redacted>"
				break
			}
		}
	}
	return strings.Join(lines, "\n")
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
