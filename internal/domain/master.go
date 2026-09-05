package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

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
	// NetnsCIDR is the point-to-point link between the host and the namespace
	// mihomo runs in — a /30, host .1, namespace .2. Empty ⇒ NetnsDefaultCIDR.
	//
	// It is CGNAT (RFC 6598) by default rather than anything from 10/8: on this
	// fleet 10/8 is routed into the corporate tunnel, listed in direct_cidrs, and
	// pulled into the tunnel by every client's route_through_cidrs — and each exit
	// already owns a /24 there. RFC 6598 exists for exactly this: provider
	// infrastructure that must not collide with the customer's private space.
	NetnsCIDR string
	// ClientViaNetns decides where client traffic is intercepted (ADR pending):
	//
	//	""      — NetnsDefaultMode
	//	"off"   — stay on the host path
	//	"auto"  — move to the namespace once the preconditions hold
	//
	// There is no per-client mode, and that is a fact about the kernel rather than a
	// missing feature: `tproxy` hands a packet to a socket in the CURRENT network
	// namespace, and there is one mihomo. Moving it serves whoever is routed into
	// the namespace and nobody else — so a rule that moved SOME clients would leave
	// the rest steered at listeners that are no longer there. See NetnsWanted.
	//
	// What makes "auto" defensible is not optimism: the agent checks the namespace
	// can resolve DNS and reach an exit BEFORE touching anything, verifies the
	// client path after the switch, and reverts itself if the verification fails.
	ClientViaNetns string
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
	// MaxFailedTimes is the consecutive-failure threshold after which mihomo forces
	// an out-of-band health check on the exit-selection groups. 0 ⇒ mihomo's default
	// (5). See ADR-0029: a forced re-check re-selects without consulting tolerance.
	MaxFailedTimes int
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
	// ClientVLESS is the client-facing VLESS+REALITY+XHTTP inbound (an alternative
	// to client↔master AmneziaWG for DPI-throttled paths). nil ⇒ the master runs no
	// client VLESS inbound. Its decrypted traffic converges into mihomo over a
	// loopback SOCKS hop, so VLESS clients share the AWG clients' routing.
	ClientVLESS *ClientVLESSServerSpec
	// ClientWG is the client-facing AmneziaWG interface when the agent — rather
	// than wg-easy — owns it. nil ⇒ this master's client leg is still wg-easy's,
	// which is what an un-migrated fleet reports and what the cutover knob
	// (fleet.masters[].client_awg.managed) leaves in place until it is flipped.
	ClientWG *ClientWGSpec
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
	// NetnsHolderImage overrides the image that owns mihomo's network namespace.
	// Worth overriding on a node that cannot pull the default: the holder must be
	// fetchable from behind the filtering this fleet exists to get around, and any
	// image with a shell and a sleep will do — including one the node already has.
	NetnsHolderImage string
}

// Enabled reports whether the compose stack should be rendered (images set).
func (c ComposeSpec) Enabled() bool { return c.WGEasyImage != "" || c.MihomoImage != "" }

// ExitTunnel is one master→exit mihomo WireGuard proxy. The master's own private
// key is injected by the agent at render time and never stored here. Historically
// one shared key served every tunnel; with ADR-0030 the agent instead derives a
// dedicated identity per tunnel when MasterKeyTunnel is set. The AmneziaWG params
// for this tunnel MUST match the exit's interface.
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
	// MasterKeyTunnel selects the master's WireGuard identity for this proxy
	// (ADR-0030). Empty ⇒ the master's single shared key (pre-ADR-0030 behaviour, and
	// what an exit still in phase off/dual gets). Non-empty ⇒ the agent derives a
	// dedicated key from its master key and THIS name, which is always the EXIT NODE
	// NAME — never the proxy Name, which carries a "-reality" suffix on a
	// dual-transport exit and would derive a second, unpublished identity.
	//
	// The controller sets it only once the exit is in a phase where its kernel
	// already accepts the derived pubkey, so the field flipping is exactly the
	// master-side half of the migration.
	MasterKeyTunnel string
	// Reserve places this tunnel in the master's second selection tier: it carries
	// traffic only when every primary tunnel is down (ADR-0029). Orthogonal to
	// Drained — a drained reserve tunnel is excluded from its tier like any other.
	Reserve bool
}

// RealityProxySuffix is what the controller appends to an exit's name to form the
// proxy name of its REALITY transport, so a dual-transport exit contributes two
// proxies under distinct names. It is the ONLY thing tying the two back together
// on the master, which is why it is a constant rather than a literal repeated at
// each site: getting the pairing wrong silently splits one exit into two.
//
// The collision this implies — an exit literally named "<something>-reality" —
// is refused at render time (see mihomo.renderProxies), so the mapping below is
// total rather than best-effort.
const RealityProxySuffix = "-reality"

// ExitNode returns the exit node this tunnel terminates on. For the AWG transport
// the proxy name IS the node name; the REALITY proxy carries the suffix above.
func (t ExitTunnel) ExitNode() string {
	if t.Transport == TransportRealityXHTTP {
		return strings.TrimSuffix(t.Name, RealityProxySuffix)
	}
	return t.Name
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

// Namespace defaults for the master's mihomo. Exported so the renderer, the
// planner and the config validator all name the same thing.
const (
	// NetnsHolder is the container that owns the namespace. A separate container
	// on purpose, the same role Kubernetes gives `pause`: mihomo restarts several
	// times a day, and a namespace owned by mihomo would take the veth and the
	// interception rules with it on every restart.
	NetnsHolder = "wgfleet-netns"
	// NetnsHostIface / NetnsPeerIface are the two ends of the veth.
	NetnsHostIface = "mih-host"
	NetnsPeerIface = "mih0"
	// NetnsDefaultCIDR is the default point-to-point link. Top of RFC 6598, as far
	// as possible from anything a provider would hand out.
	NetnsDefaultCIDR = "100.127.255.0/30"
)

// NetnsLinkCIDR is the link prefix this master uses, spec value or default.
func (m MasterSpec) NetnsLinkCIDR() string {
	if m.NetnsCIDR != "" {
		return m.NetnsCIDR
	}
	return NetnsDefaultCIDR
}

// NetnsDefaultMode is what an unset master.client_via_netns means.
//
// "auto": a switch nobody flips is a fix nobody gets. The failure this migration
// removes — every UDP port the host holds being a silent black hole for client
// traffic to that port — is not something an operator can be expected to know
// they have, so shipping it off by default ships the outage by default.
//
// What makes that defensible is not optimism but a sequence the agent performs on
// its own: it proves the namespace can resolve and reach an exit BEFORE moving
// anything, measures the client path from its own synthetic client after, and
// reverts itself if that path breaks. All of it was exercised end to end on a
// two-VM stand on 2026-09-05, with the client interface on the production port —
// canary, full move, induced failure, automatic revert, reboot in the moved state.
// The rehearsal found eight blockers that review had not; this constant was "off"
// until they were closed.
//
// An operator who wants the old path sets "off"; one who wants to try it on a
// single device sets that device's CIDR.
const NetnsDefaultMode = "auto"

// NetnsWanted reports whether client traffic should be intercepted inside
// mihomo's namespace.
//
// A value that is neither mode is an ERROR, never a guess. The first version
// treated anything unrecognised as a per-client CIDR, so `client_via_netns: "of"`
// — one keystroke short of "off" — silently switched the feature ON.
//
// A CIDR is refused explicitly, and the message says why rather than just "no".
// The mode existed, was implemented, and was measured on the stand 2026-09-05
// doing the opposite of what its name promises: mihomo moves as a whole, so the
// host goes on steering every client OUTSIDE the named prefix at listeners that
// have left, and the blast radius is everyone except the one device that was
// supposed to be the only one at risk. `tproxy` can only reach a socket in its own
// namespace and there is one mihomo — so this is not a bug to fix later.
func (m MasterSpec) NetnsWanted() (wanted bool, err error) {
	v := strings.TrimSpace(m.ClientViaNetns)
	if v == "" {
		v = NetnsDefaultMode
	}
	switch v {
	case "off":
		return false, nil
	case "auto":
		return true, nil
	}
	if _, perr := netip.ParsePrefix(v); perr == nil {
		return false, fmt.Errorf("master.client_via_netns: %q selects clients, and this migration cannot be taken per client: "+
			"mihomo moves as a whole and tproxy only reaches sockets in its own namespace, so everyone outside the prefix "+
			"would be steered at listeners that have moved. Use \"auto\" or \"off\"", v)
	}
	return false, fmt.Errorf("master.client_via_netns: %q is not \"off\" or \"auto\": %w", v, errors.New("unknown mode"))
}
