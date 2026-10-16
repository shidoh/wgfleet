package config

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// masterPortMin keeps a pinned master port out of the privileged range, where it
// would shadow a system service's socket.
const masterPortMin = 1024

// cgnat is RFC 6598 shared address space; netip.Addr.IsPrivate does not cover it,
// and an exit cannot knock on an address behind a carrier NAT either.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// AWGMasterPort is a master's external UDP port for this exit's AWG tunnel when
// the exit starts the flow: a stable per-pair derivation, or — for the base
// master only — the operator's pin. The pin is the recovery lever for one
// poisoned flow; applied to every master it would also move the healthy ones.
func (e ExitConfig) AWGMasterPort(master string, base bool) int {
	if p := e.Transports.AWG.MasterPort; p > 0 && base {
		return p
	}
	return wg.MasterPortFor(master, e.Name)
}

// validateExitInitiated checks every exit that starts its own AWG flow. The master
// answers such an exit only after hearing it, so a shape in which the exit cannot
// be heard is a tunnel that was working and stops — reject it at load instead.
func (c ControllerConfig) validateExitInitiated() []error {
	var errs []error
	anyOn := false
	for i, e := range c.Fleet.Exits {
		a := e.Transports.AWG
		prefix := fmt.Sprintf("fleet.exits[%d] (%s): transports.awg.", i, e.Name)
		if !a.ExitInitiated {
			if a.MasterPort != 0 {
				errs = append(errs, fmt.Errorf("%smaster_port is set but exit_initiated is off", prefix))
			}
			continue
		}
		anyOn = true
		if !slices.Contains(e.EnabledTransports(), domain.TransportAWG) {
			errs = append(errs, fmt.Errorf("%sexit_initiated needs the awg transport enabled", prefix))
		}
		if p := a.MasterPort; p != 0 && (p < masterPortMin || p > 65535) {
			errs = append(errs, fmt.Errorf("%smaster_port %d out of range (%d-65535)", prefix, p, masterPortMin))
		}
	}
	if !anyOn {
		return errs
	}
	if len(c.Fleet.Masters) == 0 {
		errs = append(errs, errors.New("transports.awg.exit_initiated needs a master (fleet has none)"))
	}
	for _, m := range c.Fleet.Masters {
		if err := checkKnockableAddress(m.PublicIP, "transports.awg.exit_initiated"); err != nil {
			errs = append(errs, fmt.Errorf("master %q: %w", m.Name, err))
		}
	}
	return errs
}

// checkKnockableAddress accepts an empty value or a DNS name (the controller
// resolves the master's address from its store and reports if it cannot) and
// rejects a literal the exit could not reach from the internet. flag names the
// manifest key that needs the address.
func checkKnockableAddress(v, flag string) error {
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return nil
	}
	if !IsKnockableIPv4(addr) {
		return fmt.Errorf("public_ip %s is not a public IPv4 address an exit can reach (%s)", v, flag)
	}
	return nil
}

// IsKnockableIPv4 reports whether an exit on the internet can send to addr: a
// public IPv4, not private, loopback, link-local or carrier-NAT space.
func IsKnockableIPv4(addr netip.Addr) bool {
	return addr.Is4() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !cgnat.Contains(addr)
}
