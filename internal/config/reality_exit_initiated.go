package config

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
)

// RealityPortalConfig tunes a master's portal — the VLESS+REALITY inbound the
// exits in the exit-initiated REALITY mode dial (ADR-0038). Everything is
// optional: the portal runs only when some exit uses the mode.
type RealityPortalConfig struct {
	// ListenPort is the world-facing TCP port; 0 derives a stable high port from
	// the master name (see RealityPortalListenPort).
	ListenPort int    `koanf:"listen_port"`
	DestDomain string `koanf:"dest_domain"` // camouflage host; empty ⇒ fleet default / SNI
	DestPort   int    `koanf:"dest_port"`   // camouflage port; 0 ⇒ 443
	SNI        string `koanf:"sni"`         // camouflage SNI; empty ⇒ dest_domain / fleet default
}

// DestHostPort returns the camouflage target as "host:port", or "" when no
// domain is set and the keybroker falls back to the fleet default.
func (r RealityPortalConfig) DestHostPort() string {
	if r.DestDomain == "" {
		return ""
	}
	port := r.DestPort
	if port == 0 {
		port = DefaultRealityDestPort
	}
	return fmt.Sprintf("%s:%d", r.DestDomain, port)
}

// RealityPortalListenPort returns the pinned portal port, or one derived from the
// master name into [40000,60000] that steps past every TCP port the master
// already uses, so it never lands on the client VLESS port derived the same way.
func (m MasterConfig) RealityPortalListenPort() int {
	if m.RealityPortal.ListenPort > 0 {
		return m.RealityPortal.ListenPort
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte("wgfleet-reality-portal-port|" + m.Name))
	span := clientVLESSPortHi - clientVLESSPortLo + 1
	off := int(h.Sum32() % uint32(span))
	taken := m.knownTCPPorts()
	for i := 0; i < span; i++ {
		p := clientVLESSPortLo + (off+i)%span
		if !slices.Contains(taken, p) {
			return p
		}
	}
	return clientVLESSPortLo + off
}

// knownTCPPorts lists the TCP ports the master already listens on or opens, which
// the portal must not take.
func (m MasterConfig) knownTCPPorts() []int {
	redir := m.Mihomo.RedirPort
	if redir == 0 {
		redir = mihomo.DefaultRedirPort
	}
	ports := []int{redir, mihomo.TProxyPortFor(redir), domain.ClientVLESSSocksPort, domain.RealityPortalSocksPort}
	if m.ClientVLESS.Enabled {
		ports = append(ports, m.ClientVLESSListenPort())
	}
	return append(ports, m.PublicTCPPorts...)
}

// validateRealityPortal checks one master's reality_portal block, set or not:
// the derived port is safe by construction, a pinned one is checked here.
func validateRealityPortal(i int, m MasterConfig) []error {
	var errs []error
	prefix := fmt.Sprintf("fleet.masters[%d] (%s): reality_portal.", i, m.Name)
	r := m.RealityPortal
	if p := r.ListenPort; p != 0 {
		if p < masterPortMin || p > 65535 {
			errs = append(errs, fmt.Errorf("%slisten_port %d out of range (%d-65535)", prefix, p, masterPortMin))
		} else if slices.Contains(m.knownTCPPorts(), p) {
			errs = append(errs, fmt.Errorf("%slisten_port %d collides with another TCP port of this master", prefix, p))
		}
	}
	if p := r.DestPort; p != 0 && (p < 1 || p > 65535) {
		errs = append(errs, fmt.Errorf("%sdest_port %d out of range", prefix, p))
	}
	if err := validateRealityCamouflage(r.SNI, r.DestHostPort()); err != nil {
		errs = append(errs, fmt.Errorf("%s %w", prefix, err))
	}
	return errs
}

// validateRealityExitInitiated checks every exit whose REALITY tunnels it dials
// itself. Keys that shape a master-dialled flow (XHTTP, XMUX, empty SNI) have no
// meaning on the reverse link; set on the exit they are refused rather than
// silently dropped. The fleet-wide defaults are not the exit's and pass.
func (c ControllerConfig) validateRealityExitInitiated() []error {
	var errs []error
	anyOn := false
	for i, e := range c.Fleet.Exits {
		r := e.Transports.Reality
		if !r.ExitInitiated {
			continue
		}
		anyOn = true
		prefix := fmt.Sprintf("fleet.exits[%d] (%s): transports.reality.", i, e.Name)
		if !r.Enabled {
			errs = append(errs, fmt.Errorf("%sexit_initiated needs the reality transport enabled", prefix))
		}
		for _, k := range []struct {
			key string
			set bool
		}{
			{"mode", r.Mode != ""},
			{"xhttp_path", r.XHTTPPath != ""},
			{"mux", r.Mux},
			{"empty_sni", r.EmptySNI},
		} {
			if k.set {
				errs = append(errs, fmt.Errorf("%s%s has no effect with exit_initiated (the exit dials raw REALITY); remove it", prefix, k.key))
			}
		}
	}
	if !anyOn {
		return errs
	}
	const flag = "transports.reality.exit_initiated"
	if len(c.Fleet.Masters) == 0 {
		errs = append(errs, errors.New(flag+" needs a master (fleet has none)"))
	}
	for _, m := range c.Fleet.Masters {
		if err := checkKnockableAddress(m.PublicIP, flag); err != nil {
			errs = append(errs, fmt.Errorf("master %q: %w", m.Name, err))
		}
	}
	return errs
}
