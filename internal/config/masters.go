package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/routing"
)

// reservedNodeNames are the second halves of the tunnel seeds that are not node
// names (wg.TunnelSeed(master, "clients"), wg.TunnelSeed(exit, "lifeline")).
// TunnelSeed sorts its two names, so a node called either — master or exit —
// derives the same obfuscation parameters as that interface.
var reservedNodeNames = map[string]struct{}{"clients": {}, "lifeline": {}}

// IsBase reports whether this master holds slot 0: the one every legacy
// single-master notion attaches to (see FleetSection.BaseMaster).
func (m MasterConfig) IsBase() bool { return m.Slot == 0 }

// BaseMaster is the master in slot 0. Everything that used to mean "the master"
// when there could only be one hangs off it: the exit's single MasterIP, the
// direct_cidrs an exit inherits, the lifeline's client population, the operator's
// master_port pin. A fleet whose slot-0 master is gone has none of those, and
// nothing else moves — which is the point of naming it by slot and not by
// position in the list.
func (f FleetSection) BaseMaster() (MasterConfig, bool) {
	for _, m := range f.Masters {
		if m.IsBase() {
			return m, true
		}
	}
	return MasterConfig{}, false
}

// AnchorLabel seeds everything that belongs to an exit's INTERFACE rather than to
// one peer on it — the AmneziaWG S/H parameters, the REALITY identifiers — so
// every master computes the same values for the one interface they all dial.
//
// It is a label, not a node. It defaults to the base master's name, which is what
// a one-master fleet has always derived from; but once written into the manifest
// it outlives that master, so losing it — the event several masters exist for —
// does not re-key every surviving tunnel.
func (f FleetSection) AnchorLabel() string {
	if f.InterfaceAnchor != "" {
		return f.InterfaceAnchor
	}
	if base, ok := f.BaseMaster(); ok {
		return base.Name
	}
	return ""
}

// validateMasterFanout checks what only a fleet of several masters can get wrong.
func (c ControllerConfig) validateMasterFanout() []error {
	var errs []error
	f := c.Fleet
	bySlot := map[int]string{}
	maxSlot := 0
	for i, m := range f.Masters {
		if _, bad := reservedNodeNames[m.Name]; bad {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: name %q is reserved", i, m.Name))
		}
		if m.Slot < 0 || m.Slot > domain.MaxMasterSlot {
			errs = append(errs, fmt.Errorf("fleet.masters[%d] (%s): slot %d out of range (0-%d)", i, m.Name, m.Slot, domain.MaxMasterSlot))
			continue
		}
		if other, dup := bySlot[m.Slot]; dup {
			errs = append(errs, fmt.Errorf("fleet.masters[%d] (%s): slot %d is taken by %q", i, m.Name, m.Slot, other))
			continue
		}
		bySlot[m.Slot] = m.Name
		if m.Slot > maxSlot {
			maxSlot = m.Slot
		}
	}
	if len(f.Masters) > 0 && f.InterfaceAnchor == "" {
		base, hasBase := f.BaseMaster()
		switch {
		case len(f.Masters) > 1 && hasBase:
			// Unset, the anchor follows the base master — and would move the day it
			// is removed, re-keying every tunnel of the masters that are left.
			errs = append(errs, fmt.Errorf(
				"fleet.interface_anchor is required with several masters; to keep every existing tunnel as it is, set interface_anchor: %q",
				base.Name))
		case !hasBase:
			errs = append(errs, errors.New(
				"fleet.interface_anchor is required when no master holds slot 0: there is no name left to derive it from"))
		}
	}
	if a := f.InterfaceAnchor; a != "" {
		// The label is one half of wg.TunnelSeed(exit, anchor): named like one of
		// the other seeds' halves it derives that interface's parameters, and with
		// the seed's separator in it two different (exit, label) pairs can spell the
		// same seed. Whitespace is never meant.
		if _, bad := reservedNodeNames[a]; bad {
			errs = append(errs, fmt.Errorf("fleet.interface_anchor: %q is reserved", a))
		} else if strings.ContainsFunc(a, unicode.IsSpace) || strings.Contains(a, "|") {
			errs = append(errs, fmt.Errorf("fleet.interface_anchor: %q must not contain whitespace or '|'", a))
		}
	}
	if err := f.validateExitDirectRules(); err != nil {
		errs = append(errs, err)
	}
	_, lastHost := domain.MasterTunnelHostIndex(maxSlot)
	for i, e := range f.Exits {
		if _, bad := reservedNodeNames[e.Name]; bad {
			errs = append(errs, fmt.Errorf("fleet.exits[%d]: name %q is reserved", i, e.Name))
		}
		if maxSlot == 0 || e.AddressPool == "" {
			continue // one master on slot 0: today's rule, unchanged
		}
		prefix, err := netip.ParsePrefix(e.AddressPool)
		if err != nil {
			continue // reported by the check that owns address_pool
		}
		if !poolHoldsHost(prefix, lastHost) {
			errs = append(errs, fmt.Errorf(
				"fleet.exits[%d] (%s): address_pool %s has no host %d, which master slot %d needs",
				i, e.Name, e.AddressPool, lastHost, maxSlot))
		}
	}
	return errs
}

// validateExitDirectRules checks that the direct rules every exit is rendered
// fit under routing.MaxDirectCIDRs. Each takes its own ip-rule priority, and past
// the cap they would walk into the fwmark rule — so routing.Render refuses the
// whole set, on every exit, on every pass, and the fleet runs without policy
// routing while the manifest that caused it loaded clean.
//
// The count mirrors keybroker.renderExitSpec: the base master's direct_cidrs and
// the management CIDRs, de-duplicated, plus one host route for every other
// master. It is the same for every exit, which is why the error is the fleet's.
func (f FleetSection) validateExitDirectRules() error {
	if len(f.Exits) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	count := func(cidrs []string) int {
		n := 0
		for _, c := range cidrs {
			if _, dup := seen[c]; c == "" || dup {
				continue
			}
			seen[c] = struct{}{}
			n++
		}
		return n
	}
	direct, others := 0, len(f.Masters)
	if base, ok := f.BaseMaster(); ok {
		direct, others = count(base.Routing.DirectCIDRs), others-1
	}
	mgmt := count(f.MgmtCIDRs())
	total := direct + mgmt + others
	if total <= routing.MaxDirectCIDRs {
		return nil
	}
	return fmt.Errorf("fleet: every exit would be given %d direct rules, over the max of %d: "+
		"%d from the base master's routing.direct_cidrs, %d management CIDRs (fleet.mgmt_subnet, or one per node's mgmt_addr without it) "+
		"and %d for the other masters — shorten direct_cidrs, or declare fleet.mgmt_subnet",
		total, routing.MaxDirectCIDRs, direct, mgmt, others)
}

// poolHoldsHost reports whether the nth address after the network address is
// inside prefix — the same rule keybroker.nthHost renders by, so a manifest that
// loads is a manifest that renders.
func poolHoldsHost(prefix netip.Prefix, n int) bool {
	addr := prefix.Masked().Addr()
	for i := 0; i < n; i++ {
		addr = addr.Next()
		if !addr.IsValid() || !prefix.Contains(addr) {
			return false
		}
	}
	return true
}
