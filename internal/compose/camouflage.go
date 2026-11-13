package compose

import "fmt"

// DefaultCaddyImage is the pinned web server of the own-domain camouflage site
// (ADR-0039).
const DefaultCaddyImage = "caddy:2.10.2-alpine"

// CamouflageContainer names the site's container. A container under this name
// that the agent did not start is a manual prototype the agent adopts.
const CamouflageContainer = "camouflage"

// CamouflageInput is what the site's compose file needs.
type CamouflageInput struct {
	Image     string // "" ⇒ DefaultCaddyImage
	Caddyfile string // host path, mounted read-only
	SiteDir   string // host path of the static page, mounted read-only at /srv
	DataDir   string // host path of the certificate storage, mounted at /data
	ConfigDir string // host path of Caddy's autosave dir, mounted at /config
	Timezone  string
}

// RenderCamouflageCompose renders docker-compose.yml for the camouflage site:
// Caddy on the host network (public 80 and 443, loopback target port), all
// capabilities dropped except binding the low ports.
func RenderCamouflageCompose(in CamouflageInput) (string, error) {
	if in.Caddyfile == "" || in.SiteDir == "" || in.DataDir == "" || in.ConfigDir == "" {
		return "", fmt.Errorf("compose render: camouflage paths are required")
	}
	volumes := []any{
		in.Caddyfile + ":/etc/caddy/Caddyfile:ro",
		in.SiteDir + ":/srv:ro",
		in.DataDir + ":/data",
		in.ConfigDir + ":/config",
	}
	// Plain TCP listeners: Caddy is a Go binary and would otherwise open MPTCP
	// ones (see RenderXrayCompose).
	env := []any{"GODEBUG=multipathtcp=0"}
	if in.Timezone != "" {
		env = append(env, "TZ="+in.Timezone)
		volumes = append([]any{"/etc/localtime:/etc/localtime:ro"}, volumes...)
	}
	svc := map[string]any{
		"image":          orDefault(in.Image, DefaultCaddyImage),
		"container_name": CamouflageContainer,
		"restart":        "unless-stopped",
		"network_mode":   "host",
		"volumes":        volumes,
		"environment":    env,
		"cap_drop":       []any{"ALL"},
		"cap_add":        []any{"NET_BIND_SERVICE"},
		"security_opt":   []any{"no-new-privileges:true"},
		"logging": map[string]any{
			"driver":  "json-file",
			"options": map[string]any{"max-size": "10m", "max-file": "3"},
		},
	}
	out, err := marshalYAML(map[string]any{"services": map[string]any{"caddy": svc}})
	if err != nil {
		return "", fmt.Errorf("compose render: %w", err)
	}
	return out, nil
}
