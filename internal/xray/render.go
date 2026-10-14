// Package xray renders VLESS+REALITY+XHTTP inbound configs for xray-core. It
// serves two inbounds that share the REALITY machinery:
//
//   - the exit-side master↔exit transport (ADR-0025), a single fleet-internal
//     user, egressing via a freedom outbound (→ WARP); see RenderConfig.
//   - the master-side client-facing inbound (docs/research/2026-07-client-transport-dpi.md),
//     MANY end users, forwarding decrypted traffic to mihomo over a loopback SOCKS
//     outbound so VLESS clients share the AWG clients' routing; see RenderClientConfig.
//
// Both are pure renders of a domain spec into a config the agent writes and runs
// via docker compose. The REALITY x25519 private key is generated locally on the
// node and injected at render time; it never crosses the wire (keybroker principle #2).
package xray

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

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

// RenderInput is everything needed to render the exit inbound: the desired server
// spec plus the locally-generated REALITY private key and the egress fwmark.
type RenderInput struct {
	Spec       domain.RealityServerSpec
	PrivateKey string // REALITY x25519 private key (exit-local; redacted in plans)
	EgressMark int    // SO_MARK for the freedom outbound (→ WARP); 0 = none
}

// ClientRenderInput is everything needed to render the master's client-facing
// inbound: the desired server spec (with its issued clients) plus the master's
// locally-generated REALITY private key.
type ClientRenderInput struct {
	Spec       domain.ClientVLESSServerSpec
	PrivateKey string // REALITY x25519 private key (master-local; redacted in plans)
	// SocksHost is where mihomo's client-VLESS bridge listens; "" ⇒ the loopback.
	// It stops being the loopback the moment mihomo moves into its own network
	// namespace: xray stays on the host, so "127.0.0.1" then names a socket in a
	// namespace xray cannot see, and every client is accepted and then dropped.
	SocksHost string
}

// config mirrors the subset of xray's config.json we emit. Typed structs keep the
// JSON field order deterministic (so the reconcile diff is stable).
type config struct {
	Log       logCfg     `json:"log"`
	DNS       *dnsConfig `json:"dns,omitempty"` // set to pin resolution to IPv4 (AAAA-only dest black-hole, #20)
	Stats     *struct{}  `json:"stats,omitempty"`
	API       *apiCfg    `json:"api,omitempty"`
	Policy    *policyCfg `json:"policy,omitempty"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
}

// ClientStatsAPIAddr is where the master's client-facing xray serves its
// StatsService. Loopback only: xray runs on the host network next to the agent,
// the agent is the one reader, and nothing has to be opened in the firewall.
const ClientStatsAPIAddr = "127.0.0.1:10085"

// apiCfg is xray's API block in the "listen" form: the API gets its own listener,
// so no dokodemo inbound or routing rule is needed and its traffic is not counted.
type apiCfg struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Services []string `json:"services"`
}

type policyCfg struct {
	Levels map[string]levelPolicy `json:"levels"`
}

type levelPolicy struct {
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
	StatsUserOnline   bool `json:"statsUserOnline"`
}

// dnsConfig pins xray's resolver IP-version. queryStrategy "UseIPv4" makes xray
// request/use A records only (no servers ⇒ system resolver), so the REALITY steal
// to an AAAA-only dest can't black-hole on the IPv4-only data plane.
type dnsConfig struct {
	QueryStrategy string `json:"queryStrategy"`
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
	ID   string `json:"id"`
	Flow string `json:"flow,omitempty"` // "xtls-rprx-vision" in vision mode; empty for xhttp
	// Email is the name xray counts this user's traffic under; without it no
	// counter is registered. The client inbound sets it to domain.VLESSStatsID,
	// never to the UUID: it is published on the agent's open /metrics.
	Email string `json:"email,omitempty"`
	Level *int   `json:"level,omitempty"`
}

type streamSettings struct {
	Network         string          `json:"network"`
	Security        string          `json:"security"`
	RealitySettings realitySettings `json:"realitySettings"`
	XHTTPSettings   *xhttpSettings  `json:"xhttpSettings,omitempty"` // omitted in vision (TCP) mode
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
	Settings       any                `json:"settings,omitempty"` // *freedomSettings (exit) | *socksSettings (client)
	StreamSettings *outStreamSettings `json:"streamSettings,omitempty"`
}

// freedomSettings carries the freedom outbound's domainStrategy — "UseIPv4" pins
// the proxied-traffic egress to IPv4 (pairs with dns.queryStrategy for the steal).
type freedomSettings struct {
	DomainStrategy string `json:"domainStrategy"`
}

// socksSettings points the client-facing inbound's outbound at the master's mihomo
// loopback SOCKS listener, so decrypted client traffic is routed exactly like the
// AWG clients' (one data plane).
type socksSettings struct {
	Servers []socksServer `json:"servers"`
}

type socksServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type outStreamSettings struct {
	Sockopt sockopt `json:"sockopt"`
}

type sockopt struct {
	Mark int `json:"mark"`
}

// xhttpModeOr defaults an empty XHTTP mode to packet-up.
func xhttpModeOr(mode string) string {
	if mode == "" {
		return DefaultXHTTPMode
	}
	return mode
}

// pathOr defaults an empty XHTTP path to "/".
func pathOr(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

// serverNamesFor lists the SNIs the inbound accepts. emptySNI prepends "" so a
// ClientHello carrying no SNI extension is accepted (the client then sends no
// SNI) — a strong RU TSPU bypass.
func serverNamesFor(sni string, emptySNI bool) []string {
	if emptySNI {
		return []string{"", sni}
	}
	return []string{sni}
}

// realityStream builds the REALITY streamSettings. In vision mode it stays tcp
// (the caller sets client.Flow); otherwise xhttp with the given path/mode.
func realityStream(dest, privateKey string, serverNames, shortIDs []string, mode, xhttpMode, path string) streamSettings {
	ss := streamSettings{
		Network:  "tcp",
		Security: "reality",
		RealitySettings: realitySettings{
			Show:        false,
			Target:      dest,
			ServerNames: serverNames,
			PrivateKey:  privateKey,
			ShortIDs:    shortIDs,
		},
	}
	if mode != domain.RealityModeVision {
		ss.Network = "xhttp"
		ss.XHTTPSettings = &xhttpSettings{Path: path, Mode: xhttpMode}
	}
	return ss
}

// vlessClient builds one inbound client, setting the vision flow when in vision
// mode (never in xhttp mode — flow is incompatible with XHTTP).
func vlessClient(uuid, mode string) client {
	cl := client{ID: uuid}
	if mode == domain.RealityModeVision {
		cl.Flow = "xtls-rprx-vision"
	}
	return cl
}

// RenderConfig renders xray's config.json for the exit inbound described by in.
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
	// shortIds always carries "" (matches any client short-id) plus the configured
	// one when set — mirrors the documented REALITY template.
	shortIDs := []string{""}
	if s.ShortID != "" {
		shortIDs = []string{"", s.ShortID}
	}
	serverNames := serverNamesFor(s.ServerName, s.AllowEmptySNI)

	out := outbound{Protocol: "freedom", Tag: "direct"}
	if in.EgressMark > 0 {
		out.StreamSettings = &outStreamSettings{Sockopt: sockopt{Mark: in.EgressMark}}
	}
	// Pin xray to IPv4 unless the exit advertises real IPv6 egress: the data plane is
	// IPv4-only, so an AAAA-only dest (e.g. some Fastly anycast) would
	// black-hole the REALITY steal and the proxied egress. dns.queryStrategy covers
	// resolution (incl. the steal); freedom domainStrategy covers the proxied egress.
	var dnsCfg *dnsConfig
	if !s.AllowIPv6 {
		dnsCfg = &dnsConfig{QueryStrategy: "UseIPv4"}
		out.Settings = &freedomSettings{DomainStrategy: "UseIPv4"}
	}

	ss := realityStream(s.Dest, in.PrivateKey, serverNames, shortIDs, s.Mode, xhttpModeOr(s.XHTTPMode), pathOr(s.XHTTPPath))
	cfg := config{
		Log: logCfg{Loglevel: "warning"},
		DNS: dnsCfg,
		Inbounds: []inbound{{
			Listen:   "0.0.0.0",
			Port:     s.ListenPort,
			Protocol: "vless",
			Settings: inboundSetting{
				Clients:    []client{vlessClient(s.UUID, s.Mode)},
				Decryption: "none",
			},
			StreamSettings: ss,
		}},
		Outbounds: []outbound{out},
	}
	return marshal(cfg)
}

// RenderClientConfig renders xray's config.json for the master's client-facing
// inbound: a VLESS+REALITY+XHTTP inbound with one entry per issued client, whose
// decrypted traffic is forwarded to the master's mihomo loopback SOCKS listener.
// socksHost defaults the bridge address to the loopback, which is where mihomo
// listens whenever it shares this host's network namespace.
func socksHost(addr string) string {
	if addr == "" {
		return "127.0.0.1"
	}
	return addr
}

func RenderClientConfig(in ClientRenderInput) (string, error) {
	s := in.Spec
	switch {
	case in.PrivateKey == "":
		return "", fmt.Errorf("xray client render: REALITY private key is required")
	case s.ListenPort <= 0 || s.ListenPort > 65535:
		return "", fmt.Errorf("xray client render: listen port %d out of range", s.ListenPort)
	case s.ServerName == "":
		return "", fmt.Errorf("xray client render: REALITY server name (SNI) is required")
	case s.Dest == "":
		return "", fmt.Errorf("xray client render: REALITY camouflage dest is required")
	}
	// One inbound client per issued credential; shortIds unions "" (match-any) with
	// every client's short-id so each user's own short-id is accepted. An enabled
	// inbound with no issued clients is valid (it just authenticates no one yet).
	clients := make([]client, 0, len(s.Clients))
	shortIDs := []string{""}
	seenSID := map[string]struct{}{"": {}}
	level := 0
	for _, c := range s.Clients {
		cl := vlessClient(c.UUID, s.Mode)
		cl.Email = domain.VLESSStatsID(c.UUID)
		cl.Level = &level
		clients = append(clients, cl)
		if c.ShortID != "" {
			if _, dup := seenSID[c.ShortID]; !dup {
				shortIDs = append(shortIDs, c.ShortID)
				seenSID[c.ShortID] = struct{}{}
			}
		}
	}
	serverNames := serverNamesFor(s.ServerName, s.AllowEmptySNI)

	// The outbound forwards to the master's mihomo mixed/socks inbound, which then
	// applies the SAME geo/LB/exit routing as for AWG clients.
	out := outbound{
		Protocol: "socks",
		Tag:      "mihomo",
		Settings: &socksSettings{Servers: []socksServer{{Address: socksHost(in.SocksHost), Port: s.ResolvedSocksPort()}}},
	}
	// Pin the REALITY steal's resolution to IPv4 on the IPv4-only data plane (#20).
	// The proxied traffic itself is resolved by mihomo (downstream of the socks hop),
	// so no freedom domainStrategy applies here.
	var dnsCfg *dnsConfig
	if !s.AllowIPv6 {
		dnsCfg = &dnsConfig{QueryStrategy: "UseIPv4"}
	}

	ss := realityStream(s.Dest, in.PrivateKey, serverNames, shortIDs, s.Mode, xhttpModeOr(s.XHTTPMode), pathOr(s.XHTTPPath))
	cfg := config{
		Log: logCfg{Loglevel: "warning"},
		DNS: dnsCfg,
		// Per-client traffic and online counters, read by the master agent. Only
		// StatsService: HandlerService would let a local caller add users.
		Stats: &struct{}{},
		API:   &apiCfg{Tag: "api", Listen: ClientStatsAPIAddr, Services: []string{"StatsService"}},
		Policy: &policyCfg{Levels: map[string]levelPolicy{
			"0": {StatsUserUplink: true, StatsUserDownlink: true, StatsUserOnline: true},
		}},
		Inbounds: []inbound{{
			Listen:   "0.0.0.0",
			Port:     s.ListenPort,
			Protocol: "vless",
			Settings: inboundSetting{
				Clients:    clients,
				Decryption: "none",
			},
			StreamSettings: ss,
		}},
		Outbounds: []outbound{out},
	}
	return marshal(cfg)
}

func marshal(cfg config) (string, error) {
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
