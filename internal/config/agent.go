package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/logging"
)

// DefaultReconcileInterval is used when agent.reconcile_interval is unset. It sets
// the agent's convergence/self-heal cadence (how fast drift and dead-listener
// repair land), so it is kept tight; override per-fleet via fleet.reconcile_interval
// or per-node via agent.reconcile_interval.
const DefaultReconcileInterval = 30 * time.Second

// DefaultAgentMetricsPort is the port the agent's Prometheus /metrics endpoint
// binds on the node's mgmt/overlay (ZeroTier) address by default. Kept distinct
// from the controller's own /metrics (9300) so a co-located controller+agent
// (master) does not collide. The --metrics flag overrides the full bind address.
const DefaultAgentMetricsPort = 9301

// AgentConfig is the top-level config for a wgfleet-agent process, loaded from
// agent.yaml. The agent is deliberately thin: it only needs to know who it is
// and where the controller lives; the rest of its behavior comes from the
// NodeSpec it pulls.
type AgentConfig struct {
	Agent AgentSection `koanf:"agent"`
}

// AgentSection holds the agent's identity and controller coordinates.
type AgentSection struct {
	Role              string        `koanf:"role"`               // "master" | "exit"
	Controller        string        `koanf:"controller"`         // controller mTLS endpoint
	NodeID            string        `koanf:"node_id"`            // stable node identifier
	ReconcileInterval time.Duration `koanf:"reconcile_interval"` // e.g. "60s"
	// LogLevel is how much the agent says: trace | debug | info | warn | error.
	// Empty means info. The --log-level flag overrides it; SIGUSR1/SIGUSR2 move it
	// on a running process (see internal/logging).
	LogLevel string          `koanf:"log_level"`
	Identity IdentitySection `koanf:"identity"`
	// MgmtAddr is this node's management/overlay (ZeroTier) address. It is the bind
	// address for agent surfaces that must stay off the public interface — today the
	// Prometheus /metrics endpoint, which the agent binds to
	// MgmtAddr:DefaultAgentMetricsPort by default (so metrics come up without an
	// explicit flag). The --metrics flag overrides the full bind; --metrics off
	// disables it. The --mgmt-addr flag overrides this value.
	MgmtAddr string `koanf:"mgmt_addr"`
	// MgmtOverlayMSS, when > 0, clamps TCP MSS on the ZeroTier overlay interface to
	// this value (rendered into the node firewall). Control-plane insurance: keeps
	// the agent↔controller mTLS handshake working even if the ZeroTier MTU is left at
	// its 2800 default while the underlay path is smaller (large TLS records would
	// otherwise be black-holed). Agent-local on purpose — it must not depend on the
	// channel it protects. Recommended 1240 (matches a 1280 overlay MTU); 0 disables.
	MgmtOverlayMSS int `koanf:"mgmt_overlay_mss"`
	// ASBlacklistV4URL / ASBlacklistV6URL override the scanner-ASN feed sources the
	// exit firewall drops (to hide the WG port/SSH from active VPN scanners). Empty
	// falls back to the asnfeed defaults (C24Be/AS_Network_List). The per-exit enable
	// toggle is fleet.yaml exits[].firewall.as_blacklist (wire); these are agent-local
	// operational knobs (like MgmtOverlayMSS), baked fleet-wide at provisioning.
	ASBlacklistV4URL string `koanf:"as_blacklist_v4_url"`
	ASBlacklistV6URL string `koanf:"as_blacklist_v6_url"`
	// ASBlacklistInterval is how often a stale feed cache is refreshed. 0 falls back
	// to the asnfeed default (24h). A failed refresh keeps the last-good list.
	ASBlacklistInterval time.Duration `koanf:"as_blacklist_interval"`
	// MgmtIgnoreCIDRs are the management-overlay scopes fail2ban must never ban
	// (loopback is always added). Baked in at provisioning from fleet.MgmtCIDRs();
	// the agent's host fail2ban planner renders the sshd jail's ignoreip from it.
	// Empty leaves the fail2ban jail unmanaged by reconcile (the bootstrap jail stays),
	// so an un-reprovisioned node is never regressed to a narrower ignoreip.
	MgmtIgnoreCIDRs []string `koanf:"mgmt_ignore_cidrs"`
}

// IdentitySection holds the node's mTLS client certificate material. The key is
// generated on the node during bootstrap and never leaves it.
type IdentitySection struct {
	Cert string `koanf:"cert"` // path to the node client certificate
	Key  string `koanf:"key"`  // path to the node private key (0600, on-node only)
	CA   string `koanf:"ca"`   // path to the CA certificate used to verify the controller
}

// Interval returns the configured reconcile interval, or the default when unset.
func (a AgentConfig) Interval() time.Duration {
	if a.Agent.ReconcileInterval <= 0 {
		return DefaultReconcileInterval
	}
	return a.Agent.ReconcileInterval
}

// Validate checks the agent config for boundary violations before use.
func (a AgentConfig) Validate() error {
	var errs []error
	if _, err := logging.ParseLevel(a.Agent.LogLevel); err != nil {
		errs = append(errs, fmt.Errorf("agent.log_level: %w", err))
	}
	if _, err := domain.ParseRole(a.Agent.Role); err != nil {
		errs = append(errs, fmt.Errorf("agent.role: %w", err))
	}
	if a.Agent.Controller == "" {
		errs = append(errs, errors.New("agent.controller endpoint is required"))
	}
	if a.Agent.NodeID == "" {
		errs = append(errs, errors.New("agent.node_id is required"))
	}
	if a.Agent.Identity.Cert == "" || a.Agent.Identity.Key == "" {
		errs = append(errs, errors.New("agent.identity.cert and .key are required for mTLS"))
	}
	if a.Agent.Identity.CA == "" {
		errs = append(errs, errors.New("agent.identity.ca is required to verify the controller"))
	}
	// A TCP MSS clamp must be a sane segment size. 0 disables; otherwise keep it in a
	// reasonable band (a too-small clamp wrecks throughput, a too-large one fails to
	// fit the overlay path it is meant to protect).
	if m := a.Agent.MgmtOverlayMSS; m != 0 && (m < 536 || m > 1460) {
		errs = append(errs, fmt.Errorf("agent.mgmt_overlay_mss %d out of range (0 to disable, else 536..1460)", m))
	}
	// Scanner-ASN feed refresh cadence: 0 uses the default; otherwise keep it in a
	// sane band so a typo can't pin it to seconds (hammering the source) or months.
	if d := a.Agent.ASBlacklistInterval; d != 0 && (d < time.Minute || d > 7*24*time.Hour) {
		errs = append(errs, fmt.Errorf("agent.as_blacklist_interval %s out of range (0 for default, else 1m..168h)", d))
	}
	for name, u := range map[string]string{
		"agent.as_blacklist_v4_url": a.Agent.ASBlacklistV4URL,
		"agent.as_blacklist_v6_url": a.Agent.ASBlacklistV6URL,
	} {
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			errs = append(errs, fmt.Errorf("%s must be an http(s) URL, got %q", name, u))
		}
	}
	return errors.Join(errs...)
}
