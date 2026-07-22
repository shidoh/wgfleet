package compose

import (
	"fmt"
	"path/filepath"
)

// DefaultXrayImage (repository:tag) is the pinned xray-core image used when the
// spec leaves the image unset (no implicit :latest — every container the platform
// runs pins image AND tag). Exported so the controller resolves image/tag
// overrides against the same canonical default the renderer falls back to.
const DefaultXrayImage = "ghcr.io/xtls/xray-core:26.6.22"

// XrayInput is everything needed to render an xray-core REALITY container (both the
// exit inbound and the client-facing master inbound render through this).
type XrayInput struct {
	Image string // container image; defaults to DefaultXrayImage
	// ConfigPath is the host path of the rendered xray config.json; it is mounted
	// into the container at /etc/xray/config.json.
	ConfigPath string
	// Timezone synchronizes container log timestamps with the host (optional).
	Timezone string
	// NetAdmin grants CAP_NET_ADMIN. Only the EXIT inbound needs it: its freedom
	// outbound sets SO_MARK so host policy routing sends egress through WARP (ADR-0025,
	// an earlier finding). The client-facing MASTER inbound forwards to a loopback SOCKS
	// (mihomo) and never marks a socket, so it leaves this false and runs with all
	// capabilities dropped (#9, least privilege).
	NetAdmin bool
	// ListenPort is the inbound's world-facing TCP port. When it is privileged
	// (< 1024, e.g. the exit REALITY inbound on 443) the container needs
	// CAP_NET_BIND_SERVICE to bind it: cap_drop [ALL] strips the default capability
	// that otherwise lets the container's root bind low ports (#9 regression). Zero
	// or a high port adds nothing.
	ListenPort int
}

// privilegedPortMax is the highest port that requires CAP_NET_BIND_SERVICE to
// bind; ports at or below it are privileged.
const privilegedPortMax = 1023

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
		// Least privilege (#9): drop ALL capabilities and forbid privilege escalation,
		// then add back ONLY what a leg needs. A REALITY inbound needs none by itself;
		// the exit's WARP egress adds NET_ADMIN below.
		"cap_drop":     []any{"ALL"},
		"security_opt": []any{"no-new-privileges:true"},
	}
	// Add back only the capabilities this leg actually needs, in a fixed order so the
	// rendered YAML stays byte-stable (a non-deterministic list would drift-loop the
	// reconciler). NET_ADMIN for the exit's WARP egress; NET_BIND_SERVICE when the
	// inbound sits on a privileged port.
	var capAdd []any
	if in.NetAdmin {
		// NET_ADMIN lets the freedom outbound set SO_MARK (sockopt.mark), which the
		// host policy routing matches to send xray's egress through WARP (ADR-0025,
		// an earlier finding). Without it the mark is silently dropped and egress misroutes.
		// The client-facing master inbound forwards to a loopback SOCKS and never marks
		// a socket, so it does not request this.
		capAdd = append(capAdd, "NET_ADMIN")
	}
	if in.ListenPort > 0 && in.ListenPort <= privilegedPortMax {
		// cap_drop [ALL] removes CAP_NET_BIND_SERVICE, without which even the
		// container's root cannot bind a port < 1024. The exit REALITY inbound is on
		// 443, so it must add it back or xray fails to listen (silent Degraded loop).
		capAdd = append(capAdd, "NET_BIND_SERVICE")
	}
	if len(capAdd) > 0 {
		svc["cap_add"] = capAdd
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
