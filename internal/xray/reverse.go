package xray

import (
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Exit-initiated REALITY (ADR-0038): the exit's xray is a reverse-proxy BRIDGE
// that dials the master's PORTAL and keeps mux flows up to it; the master sends
// client streams down them. The shapes below were measured on a live RU path
// (Xray 26.6.22) before they were written down here. They use their own types so
// the forward and client-facing renders above stay byte-for-byte as they are.

// Keepalive on every reverse flow: a flow dead in both directions is noticed in
// 15–20 s instead of never. A flow frozen one way is not — that is the exit
// agent's watchdog's job.
const (
	reverseKeepAliveIdle     = 10
	reverseKeepAliveInterval = 5
	reverseUserTimeoutMs     = 20000
)

// Tags of the portal's inbounds.
const (
	PortalInboundTag = "portal"
	PortalSocksTag   = "socks"
)

type reverseConfig struct {
	Log       logCfg           `json:"log"`
	DNS       *dnsConfig       `json:"dns,omitempty"`
	Inbounds  []reverseInbound `json:"inbounds,omitempty"`
	Outbounds []any            `json:"outbounds"`
	Routing   reverseRouting   `json:"routing"`
}

type reverseInbound struct {
	Tag            string         `json:"tag"`
	Listen         string         `json:"listen"`
	Port           int            `json:"port"`
	Protocol       string         `json:"protocol"`
	Settings       any            `json:"settings"`
	StreamSettings *reverseStream `json:"streamSettings,omitempty"`
}

type portalSettings struct {
	Clients    []portalClient `json:"clients"`
	Decryption string         `json:"decryption"`
}

type portalClient struct {
	ID      string     `json:"id"`
	Email   string     `json:"email"`
	Reverse reverseTag `json:"reverse"`
}

type reverseTag struct {
	Tag string `json:"tag"`
}

type portalSocksSettings struct {
	Auth     string         `json:"auth"`
	Accounts []socksAccount `json:"accounts"`
	UDP      bool           `json:"udp"`
	IP       string         `json:"ip"`
}

type socksAccount struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type reverseStream struct {
	Network         string         `json:"network"`
	Security        string         `json:"security"`
	RealitySettings any            `json:"realitySettings"`
	Sockopt         reverseSockopt `json:"sockopt"`
}

type portalReality struct {
	Show        bool     `json:"show"`
	Target      string   `json:"target"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

type reverseSockopt struct {
	Mark                 int `json:"mark,omitempty"`
	TCPKeepAliveIdle     int `json:"tcpKeepAliveIdle,omitempty"`
	TCPKeepAliveInterval int `json:"tcpKeepAliveInterval,omitempty"`
	TCPUserTimeout       int `json:"tcpUserTimeout,omitempty"`
}

type blackholeOutbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
}

type reverseRouting struct {
	Rules []reverseRule `json:"rules"`
}

type reverseRule struct {
	InboundTag  []string `json:"inboundTag"`
	User        []string `json:"user,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

func keepAlive() reverseSockopt {
	return reverseSockopt{
		TCPKeepAliveIdle:     reverseKeepAliveIdle,
		TCPKeepAliveInterval: reverseKeepAliveInterval,
		TCPUserTimeout:       reverseUserTimeoutMs,
	}
}

func ipv4Only(allowIPv6 bool) *dnsConfig {
	if allowIPv6 {
		return nil
	}
	return &dnsConfig{QueryStrategy: "UseIPv4"}
}

// PortalRenderInput is everything the master's portal config needs: the spec,
// the master-local portal private key, the address mihomo reaches the SOCKS
// inbound on, and each exit's SOCKS password (derived on the master).
type PortalRenderInput struct {
	Spec           domain.RealityPortalSpec
	PrivateKey     string
	SocksAddr      string
	SocksPasswords map[string]string // exit → password
}

// RenderPortalConfig renders the master's portal: a VLESS+REALITY inbound
// admitting one bridge per exit, a SOCKS inbound with one user per exit routed to
// that exit's reverse tag, and a blackhole as the only outbound.
func RenderPortalConfig(in PortalRenderInput) (string, error) {
	s := in.Spec
	switch {
	case in.PrivateKey == "":
		return "", fmt.Errorf("xray portal render: REALITY private key is required")
	case in.SocksAddr == "":
		return "", fmt.Errorf("xray portal render: SOCKS address is required")
	}
	if err := s.Validate(); err != nil {
		return "", fmt.Errorf("xray portal render: %w", err)
	}
	clients := make([]portalClient, 0, len(s.Clients))
	accounts := make([]socksAccount, 0, len(s.Clients))
	rules := make([]reverseRule, 0, len(s.Clients))
	shortIDs := make([]string, 0, len(s.Clients))
	for _, c := range s.Clients {
		pass := in.SocksPasswords[c.Exit]
		if pass == "" {
			return "", fmt.Errorf("xray portal render: no SOCKS password for exit %q", c.Exit)
		}
		tag := domain.ReverseTag(c.Exit)
		clients = append(clients, portalClient{ID: c.UUID, Email: "bridge:" + c.Exit, Reverse: reverseTag{Tag: tag}})
		accounts = append(accounts, socksAccount{User: c.Exit, Pass: pass})
		rules = append(rules, reverseRule{InboundTag: []string{PortalSocksTag}, User: []string{c.Exit}, OutboundTag: tag})
		shortIDs = append(shortIDs, c.ShortID)
	}
	if len(shortIDs) == 0 {
		shortIDs = []string{unissuedShortID(in.PrivateKey)}
	}
	cfg := reverseConfig{
		Log: logCfg{Loglevel: "warning"},
		DNS: ipv4Only(s.AllowIPv6),
		Inbounds: []reverseInbound{
			{
				Tag: PortalInboundTag, Listen: "0.0.0.0", Port: s.ListenPort, Protocol: "vless",
				Settings: portalSettings{Clients: clients, Decryption: "none"},
				StreamSettings: &reverseStream{
					Network: "raw", Security: "reality",
					RealitySettings: portalReality{
						Target: s.Dest, ServerNames: []string{s.ServerName},
						PrivateKey: in.PrivateKey, ShortIDs: shortIDs,
					},
					Sockopt: keepAlive(),
				},
			},
			{
				Tag: PortalSocksTag, Listen: in.SocksAddr, Port: s.ResolvedSocksPort(), Protocol: "socks",
				Settings: portalSocksSettings{Auth: "password", Accounts: accounts, UDP: true, IP: in.SocksAddr},
			},
		},
		// First outbound is the default route: whatever no rule claims is dropped.
		Outbounds: []any{blackholeOutbound{Tag: "block", Protocol: "blackhole"}},
		Routing:   reverseRouting{Rules: rules},
	}
	return marshalAny(cfg)
}
