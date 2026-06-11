package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// DefaultReconcileInterval is used when agent.reconcile_interval is unset.
const DefaultReconcileInterval = 60 * time.Second

// AgentConfig is the top-level config for a wgfleet-agent process, loaded from
// agent.yaml. The agent is deliberately thin: it only needs to know who it is
// and where the controller lives; the rest of its behavior comes from the
// NodeSpec it pulls.
type AgentConfig struct {
	Agent AgentSection `koanf:"agent"`
}

// AgentSection holds the agent's identity and controller coordinates.
type AgentSection struct {
	Role              string          `koanf:"role"`               // "master" | "exit"
	Controller        string          `koanf:"controller"`         // controller mTLS endpoint
	NodeID            string          `koanf:"node_id"`            // stable node identifier
	ReconcileInterval time.Duration   `koanf:"reconcile_interval"` // e.g. "60s"
	Identity          IdentitySection `koanf:"identity"`
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
	return errors.Join(errs...)
}
