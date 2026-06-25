package domain

// MasterSpec is the master node's data-plane desired state. The master fronts
// clients (client-facing AmneziaWG via WGServerSpec) and routes/load-balances
// their traffic across exit nodes using mihomo. Each exit is a mihomo WireGuard
// proxy carrying an AmneziaWG-obfuscated tunnel (master↔exit); mihomo selects
// among them per the routing rules and the load-balance group.
//
// This is attached to NodeSpec.Master (nil for exit nodes).
type MasterSpec struct {
	// BindAddress is the address mihomo binds for inbound client traffic
	// (the master's own address in the client WG pool, e.g. "10.80.0.1").
	BindAddress string
	// RedirPort is mihomo's redir-port (clients DNAT'd here by nftables).
	RedirPort int
	// ExternalController is the Clash API bind (mgmt/ZT address only).
	ExternalController string
	// ExitTunnels is one mihomo WireGuard proxy per exit.
	ExitTunnels []ExitTunnel
	// Balance selects the wg-best exit-selection kind: a load-balance strategy
	// ("round-robin" | "consistent-hashing" | "sticky-sessions") or a distinct group
	// type ("url-test" | "fallback"). Empty ⇒ round-robin. See mihomo.wgBestGroup.
	Balance string
	// HealthCheckInterval is how often (seconds) mihomo health-checks the exits in
	// wg-best to detect/route around dead ones. 0 ⇒ mihomo.DefaultHealthInterval.
	HealthCheckInterval int
	// DirectCIDRs route via DIRECT (RU/private/own networks), never via an exit.
	// Rendered both into the rules and the included direct-networks file.
	DirectCIDRs []string
	// DirectGeo are geo categories routed DIRECT (e.g. ["RU"]).
	DirectGeo []string
	// SnifferSkip is the sniffer skip-domain list — CDNs/SNI-faking services that
	// break under sniffing.
	SnifferSkip []string
	// DashboardDisabled turns off the mihomo external web dashboard entirely (no
	// external-ui / external-ui-url emitted). Zero value = enabled, preserving the
	// default. Set it where the dashboard download host is blocked so mihomo never
	// attempts the (potentially failing/panic-inducing) startup download.
	DashboardDisabled bool
	// DashboardURL overrides where mihomo fetches the dashboard zip on first run.
	// Empty = the built-in default (zashboard latest on GitHub). Point it at a
	// reachable mirror when the default host is blocked.
	DashboardURL string
	// ClientAdminPorts are TCP ports on the master's mgmt address that the VPN
	// client pool is allowed to reach (opt-in). The admin UIs — the controller Web
	// UI and the mihomo dashboard — bind the mgmt overlay only, and the master input
	// firewall (drop policy) otherwise drops client TCP to them, so clients get
	// pings/DNS/web but cannot open the dashboards. Listing a port here renders an
	// `iifname <client-iface> tcp dport <p> accept` in the master input chain.
	// This deliberately relaxes the "admin on the mgmt overlay only" posture — set
	// it only for ports clients are meant to see. The destination must also bypass
	// the client→mihomo DNAT, which it does whenever the mgmt address falls under
	// DirectCIDRs (e.g. 172.16.0.0/12 covers a 10.20.x mgmt overlay).
	ClientAdminPorts []int
	// Custom holds operator overrides merged into the rendered config plus extra
	// managed files (e.g. additional rule providers). See CustomConfig.
	Custom CustomConfig
	// Compose describes the master's container stack (wg-easy + mihomo). The
	// agent renders a docker-compose.yml from it and keeps the containers up.
	Compose ComposeSpec
}

// ComposeSpec is the master's container-stack desired state, rendered by the
// controller and turned into a docker-compose.yml by the master agent. The data
// plane runs as containers (wg-easy for client AmneziaWG, mihomo for routing).
type ComposeSpec struct {
	WGEasyImage      string   // wg-easy container image (tag pinned by the operator)
	MihomoImage      string   // mihomo container image
	PublicIP         string   // master public IP (wg-easy INIT_HOST, first run)
	WGEasyWebPort    int      // wg-easy web UI port (mgmt overlay)
	ClientDNS        []string // DNS handed to clients (exit blocky addrs)
	ClientAllowedIPs string   // AllowedIPs handed to clients (inverted RFC1918; operator-set)
}

// Enabled reports whether the compose stack should be rendered (images set).
func (c ComposeSpec) Enabled() bool { return c.WGEasyImage != "" || c.MihomoImage != "" }

// ExitTunnel is one master→exit mihomo WireGuard proxy. The master's own private
// key is injected by the agent at render time and is shared across all tunnels
// (the master has a single WG identity that each exit peers); it is not stored
// here. The AmneziaWG params for this tunnel MUST match the exit's interface.
type ExitTunnel struct {
	Name            string // proxy name == exit node name (+ transport suffix when multi)
	Endpoint        string // exit public endpoint "host:port"
	ServerPublicKey string // exit's WG server public key (TransportAWG)
	PresharedKey    string // optional WG preshared key (secret; redacted in plans)
	TunnelIP        string // master's address inside the exit's pool (e.g. "10.81.0.2")
	MTU             int    // computed along the tunnel chain
	AWG             *AWGParams
	// Transport is the master↔exit transport this proxy carries (ADR-0025). Empty
	// == TransportAWG (back-compat). For TransportAWG the ServerPublicKey/TunnelIP/
	// AWG/MTU fields apply (a mihomo wireguard proxy); for TransportRealityXHTTP the
	// Reality field carries the proxy params instead (a mihomo vless proxy).
	Transport MasterTransport
	// Reality is set when Transport == TransportRealityXHTTP, nil otherwise.
	Reality *RealityTunnel
	// Drained keeps the proxy configured (existing connections survive) but
	// excludes it from the load-balance group, so no new traffic routes to it.
	// A standby transport on a dual-transport exit is rendered Drained (ADR-0025).
	Drained bool
}

// CustomConfig is the generic config-customization mechanism: operator-supplied
// overrides deep-merged into a renderer's structured output, plus extra managed
// files written alongside (e.g. mihomo's included rule-provider files). It lets
// operators inject parameters the domain model doesn't promote to first-class
// fields without forking the renderer.
type CustomConfig struct {
	// Overrides is deep-merged into the rendered config tree: maps merge
	// recursively, scalars and lists replace. Keys mirror the target config's
	// structure (e.g. mihomo's "dns", "sniffer", "rules").
	Overrides map[string]any
	// Files are extra files the reconciler writes verbatim alongside the main
	// config (path on the node → content).
	Files []ManagedFile
}

// ManagedFile is an extra file provisioned by a reconciler.
type ManagedFile struct {
	Path    string
	Content string
	// Secret marks content as sensitive so plan output redacts it.
	Secret bool
}

// HasOverrides reports whether any customization is present.
func (c CustomConfig) HasOverrides() bool {
	return len(c.Overrides) > 0 || len(c.Files) > 0
}
