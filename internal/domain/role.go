// Package domain holds the core types of the wgfleet control plane: the
// declarative desired state (NodeSpec) and the observed inventory (Node).
// These types are storage- and transport-agnostic; controller, agent, store
// and API layers all depend on this package, never the reverse.
package domain

import "fmt"

// Role is the function a managed node performs in the fleet.
type Role string

const (
	// RoleMaster terminates client AmneziaWG, geo-routes and load-balances
	// across exit nodes (the ru-gw gateway in the reference architecture).
	RoleMaster Role = "master"
	// RoleExit accepts traffic from a master and egresses it to the internet
	// (the exit-a/exit-b/exit-c nodes in the reference architecture).
	RoleExit Role = "exit"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleMaster, RoleExit:
		return true
	default:
		return false
	}
}

func (r Role) String() string { return string(r) }

// EgressMethod is how an exit node releases traffic to the internet.
type EgressMethod string

const (
	// EgressWARP routes egress through Cloudflare WARP via wgcf.
	EgressWARP EgressMethod = "warp"
	// EgressDirect releases traffic under the node's datacenter IP.
	EgressDirect EgressMethod = "direct"
	// EgressReality (Phase 3) — Reality/VLESS transport, not yet implemented.
	EgressReality EgressMethod = "reality"
)

// Valid reports whether the egress method is supported on the current MVP.
// EgressReality parses but is rejected here until Phase 3 lands.
func (e EgressMethod) Valid() bool {
	switch e {
	case EgressWARP, EgressDirect:
		return true
	default:
		return false
	}
}

func (e EgressMethod) String() string { return string(e) }

// NodeState is the lifecycle state of a node as observed by the controller.
type NodeState string

const (
	// StatePending — registered in inventory, not yet provisioned.
	StatePending NodeState = "Pending"
	// StateProvisioning — controller is running the SSH bootstrap pipeline.
	StateProvisioning NodeState = "Provisioning"
	// StateReconciling — agent is converging the node toward its NodeSpec.
	StateReconciling NodeState = "Reconciling"
	// StateReady — all self-checks green, node is in the balancer.
	StateReady NodeState = "Ready"
	// StateDegraded — reachable but one or more self-checks are failing.
	StateDegraded NodeState = "Degraded"
	// StateError — reconcile or provisioning failed; needs operator attention.
	StateError NodeState = "Error"
)

// Valid reports whether s is a known node state.
func (s NodeState) Valid() bool {
	switch s {
	case StatePending, StateProvisioning, StateReconciling,
		StateReady, StateDegraded, StateError:
		return true
	default:
		return false
	}
}

func (s NodeState) String() string { return string(s) }

// ParseRole validates and returns a Role, or an error for unknown values.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("unknown role %q (want %q or %q)", s, RoleMaster, RoleExit)
	}
	return r, nil
}
