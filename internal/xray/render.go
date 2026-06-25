// Package xray renders the exit-side VLESS+REALITY+XHTTP inbound config for
// xray-core (ADR-0025). It is the REALITY counterpart of internal/dnsfilter
// (blocky) and internal/mihomo: a pure render of domain.RealityServerSpec into a
// config the agent writes and runs via docker compose. The REALITY x25519 private
// key is generated locally on the exit and injected here at render time; it never
// crosses the wire (keybroker principle #2).
package xray

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// DefaultImage is the pinned xray-core container image (no implicit :latest —
// every container the platform runs pins image AND tag).
const DefaultImage = "ghcr.io/xtls/xray-core:25.6.22"

// DefaultXHTTPMode mirrors mihomo.DefaultXHTTPMode: packet-up splits the upstream
// into many short POSTs (dodges the foreign-DC volume-freeze) and works without a
// CDN. It MUST match the client; set explicitly on both ends (auto+REALITY has an
// xray bug, #5635).
const DefaultXHTTPMode = "packet-up"

// EgressMark is the SO_MARK xray stamps on its outbound (freedom) sockets so the
// exit's host policy routing sends them through WARP, not the host default route.
// xray dials FROM THE HOST, so the client-pool `from <pool>` egress rule (earlier findings
// ) does not catch these; a dedicated fwmark rule does (added by the exit's
// routing planner). 0 ⇒ no sockopt.mark emitted (direct egress).
const EgressMark = 0x33 // 51

// RenderInput is everything needed to render the inbound: the desired server spec
// plus the locally-generated REALITY private key and the egress fwmark.
type RenderInput struct {
	Spec       domain.RealityServerSpec
	PrivateKey string // REALITY x25519 private key (exit-local; redacted in plans)
	EgressMark int    // SO_MARK for the freedom outbound (→ WARP); 0 = none
}

// config mirrors the subset of xray's config.json we emit. Typed structs keep the
// JSON field order deterministic (so the reconcile diff is stable).
type config struct {
	Log       logCfg     `json:"log"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
}

type logCfg struct {
	Loglevel string `json:"loglevel"`
}

type inbound struct {
	Listen         string         `json:"listen"`
	Port           int            `json:"port"`
	Protocol       string         `json:"protocol"`
	Settings       inboundSetting `json:"settings"`
	StreamSettings streamSettings `json:"streamSettings"`
}

type inboundSetting struct {
	Clients    []client `json:"clients"`
	Decryption string   `json:"decryption"`
}

type client struct {
	ID string `json:"id"`
}

type streamSettings struct {
	Network         string          `json:"network"`
	Security        string          `json:"security"`
	RealitySettings realitySettings `json:"realitySettings"`
	XHTTPSettings   xhttpSettings   `json:"xhttpSettings"`
}

type realitySettings struct {
	Show        bool     `json:"show"`
	Target      string   `json:"target"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

type xhttpSettings struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type outbound struct {
	Protocol       string             `json:"protocol"`
	Tag            string             `json:"tag"`
	StreamSettings *outStreamSettings `json:"streamSettings,omitempty"`
}

type outStreamSettings struct {
	Sockopt sockopt `json:"sockopt"`
}

type sockopt struct {
	Mark int `json:"mark"`
}

// RenderConfig renders xray's config.json for the inbound described by in.
func RenderConfig(in RenderInput) (string, error) {
	s := in.Spec
	switch {
	case in.PrivateKey == "":
		return "", fmt.Errorf("xray render: REALITY private key is required")
	case s.ListenPort <= 0 || s.ListenPort > 65535:
		return "", fmt.Errorf("xray render: listen port %d out of range", s.ListenPort)
	case s.UUID == "":
		return "", fmt.Errorf("xray render: VLESS uuid is required")
	case s.ServerName == "":
		return "", fmt.Errorf("xray render: REALITY server name (SNI) is required")
	case s.Dest == "":
		return "", fmt.Errorf("xray render: REALITY camouflage dest is required")
	}
	mode := s.XHTTPMode
	if mode == "" {
		mode = DefaultXHTTPMode
	}
	path := s.XHTTPPath
	if path == "" {
		path = "/"
	}
	// shortIds always carries "" (matches any client short-id) plus the configured
	// one when set — mirrors the documented REALITY template.
	shortIDs := []string{""}
	if s.ShortID != "" {
		shortIDs = []string{"", s.ShortID}
	}

	out := outbound{Protocol: "freedom", Tag: "direct"}
	if in.EgressMark > 0 {
		out.StreamSettings = &outStreamSettings{Sockopt: sockopt{Mark: in.EgressMark}}
	}

	cfg := config{
		Log: logCfg{Loglevel: "warning"},
		Inbounds: []inbound{{
			Listen:   "0.0.0.0",
			Port:     s.ListenPort,
			Protocol: "vless",
			Settings: inboundSetting{
				Clients:    []client{{ID: s.UUID}},
				Decryption: "none",
			},
			StreamSettings: streamSettings{
				Network:  "xhttp",
				Security: "reality",
				RealitySettings: realitySettings{
					Show:        false,
					Target:      s.Dest,
					ServerNames: []string{s.ServerName},
					PrivateKey:  in.PrivateKey,
					ShortIDs:    shortIDs,
				},
				XHTTPSettings: xhttpSettings{Path: path, Mode: mode},
			},
		}},
		Outbounds: []outbound{out},
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("xray render: %w", err)
	}
	return string(b) + "\n", nil
}

// RedactConfig masks the REALITY private key for plan/dry-run output.
func RedactConfig(cfg string) string {
	const key = `"privateKey": "`
	i := strings.Index(cfg, key)
	if i < 0 {
		return cfg
	}
	start := i + len(key)
	end := strings.IndexByte(cfg[start:], '"')
	if end < 0 {
		return cfg
	}
	return cfg[:start] + "REDACTED" + cfg[start+end:]
}
