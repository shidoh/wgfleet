package domain

import "time"

// CredentialKind names the transport a per-master credential belongs to. A device
// holds at most one credential of each kind per master: one AWG key cannot live
// on two devices (the server keeps one endpoint per key), and two of one kind on
// one master would be two profiles competing for one proxy name.
type CredentialKind string

const (
	CredentialAWG   CredentialKind = "awg"
	CredentialVLESS CredentialKind = "vless"
)

// DeviceCredential is one credential attached to a device. Ref is what the
// credential is keyed by in its own table: the ID for AWG, the label for VLESS
// (client_vless_credentials has no ID of its own).
type DeviceCredential struct {
	Kind     CredentialKind
	MasterID string
	Ref      string
	Name     string
}

// ClientDevice is one physical device of one person (ADR-0035). Fleet-wide while
// its credentials are per master: the profile carries a proxy for every master
// the device holds a credential on.
//
// No enabled flag of its own: pausing stays on the credentials, where it already
// removes the AWG peer; a second switch here is a second place to look when
// someone cannot connect.
type ClientDevice struct {
	// ID is internal and stable — what the panel links to. Token is the portal
	// secret and rotates; keeping them apart is what lets a leaked link be cut off
	// without the device changing identity.
	ID    string
	Token string
	Name  string
	// CreatedAt is stamped by the caller, never by the store: a replica applying
	// the same write must record the same time.
	CreatedAt   time.Time
	Credentials []DeviceCredential
}

// Credential returns the device's credential of one kind on one master.
func (d ClientDevice) Credential(kind CredentialKind, masterID string) (DeviceCredential, bool) {
	for _, c := range d.Credentials {
		if c.Kind == kind && c.MasterID == masterID {
			return c, true
		}
	}
	return DeviceCredential{}, false
}

// Legacy reports a device synthesised from a lone AWG credential that belongs to
// no device and whose personal link is still live. It has no row: nothing to
// rename, rotate or delete.
func (d ClientDevice) Legacy() bool { return d.ID == "" }

// ClientMasterMeta is the controller-side routing metadata one master contributes
// to a device profile. None of it is node desired state, so none of it crosses
// the wire.
type ClientMasterMeta struct {
	// RouteThrough is client_awg.route_through_cidrs ∪ client_vless.route_through_cidrs.
	RouteThrough []string
	// Resolvers is what the .conf's DNS line names (one derivation, both renderers).
	Resolvers []string
	// ClientPool is client_awg.address_pool; "" for a master without the AWG leg.
	ClientPool string
	// MgmtCIDRs is the fleet's management overlay (FleetSection.MgmtCIDRs) — where
	// the portal itself lives.
	MgmtCIDRs []string
	// Sites is fleet.client_sites, the same for every master.
	Sites []ClientSite
}

// ClientSite is a network the operator owns that is sometimes the device's own
// LAN and sometimes far away: home, office. The device profile reaches it
// DIRECT when a probe inside it answers directly, through the tunnel when not —
// and hands the person a switch for when the guess is wrong. Fleet-wide, like
// the mgmt overlay; none of it crosses the wire.
type ClientSite struct {
	Name  string
	CIDRs []string
	// ProbeURL is an http:// URL on an address inside CIDRs; "" leaves only the
	// manual switch.
	ProbeURL string
	// ProbeInterval is in seconds; 0 means the default.
	ProbeInterval int
}
