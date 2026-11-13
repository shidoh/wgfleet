package config

import (
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"strings"
)

// CamouflageConfig is a node's own-domain camouflage (ADR-0039): the agent runs a
// web server with a certificate for Domain, and every REALITY inbound on the node
// uses it as its target instead of a third-party site. The operator owns the domain
// and points its A record at the node's public_ip; wgfleet never touches DNS.
type CamouflageConfig struct {
	// Domain is the node's own name. Empty ⇒ camouflage off (the fleet default).
	Domain string `koanf:"domain"`
	// PublicHTTPS also serves the site on public TCP/443. Only where nothing else
	// on the node holds TCP/443 (an exit in the exit-initiated REALITY mode, or one
	// whose inbound sits on another port).
	PublicHTTPS bool `koanf:"public_https"`
}

// Enabled reports whether the node runs camouflage.
func (c CamouflageConfig) Enabled() bool { return c.Domain != "" }

// CamouflageFleet is the fleet-wide part of camouflage.
type CamouflageFleet struct {
	// ACMEEmail is the contact address for the certificate authority; optional.
	ACMEEmail string `koanf:"acme_email"`
	// ACMECA selects the certificate authority: empty ⇒ Caddy's public defaults;
	// CamouflageCAInternal ⇒ Caddy's own local CA, trusted by the agent's switch
	// gate — for stands without public DNS; otherwise an ACME directory URL.
	ACMECA string `koanf:"acme_ca"`
	// Image is the web server image (repo:tag); empty ⇒ the pinned default.
	Image string `koanf:"image"`
}

// CamouflageCAInternal makes Caddy issue from its local CA (stands only).
const CamouflageCAInternal = "internal"

// camouflageNode is the slice of a master or an exit that camouflage validation reads.
type camouflageNode struct {
	where    string // "fleet.masters[0] (master-1)"
	camo     CamouflageConfig
	publicIP string
	sshHost  string
	explicit []string // set sni/dest_domain keys on the node's REALITY inbounds
	holds443 bool     // a REALITY inbound on the node listens on TCP/443
}

func (c ControllerConfig) camouflageNodes() []camouflageNode {
	var out []camouflageNode
	for i, m := range c.Fleet.Masters {
		n := camouflageNode{
			where: fmt.Sprintf("fleet.masters[%d] (%s)", i, m.Name), camo: m.Camouflage,
			publicIP: m.PublicIP, sshHost: m.SSH.Host,
		}
		if m.ClientVLESS.SNI != "" || m.ClientVLESS.DestDomain != "" {
			n.explicit = append(n.explicit, "client_vless.sni/dest_domain")
		}
		if m.RealityPortal.SNI != "" || m.RealityPortal.DestDomain != "" {
			n.explicit = append(n.explicit, "reality_portal.sni/dest_domain")
		}
		n.holds443 = (m.ClientVLESS.Enabled && m.ClientVLESSListenPort() == 443) || m.RealityPortal.ListenPort == 443
		out = append(out, n)
	}
	for i, e := range c.Fleet.Exits {
		r := e.Transports.Reality
		listening := r.Enabled && !r.ExitInitiated
		n := camouflageNode{
			where: fmt.Sprintf("fleet.exits[%d] (%s)", i, e.Name), camo: e.Camouflage,
			publicIP: e.PublicIP, sshHost: e.SSH.Host,
		}
		if r.SNI != "" || r.DestDomain != "" {
			n.explicit = append(n.explicit, "transports.reality.sni/dest_domain")
		}
		n.holds443 = listening && (r.ListenPort == 0 || r.ListenPort == 443)
		out = append(out, n)
	}
	return out
}

// validateCamouflage checks every node's camouflage block and the fleet-wide one.
func (c ControllerConfig) validateCamouflage() []error {
	var errs []error
	seen := map[string]string{}
	for _, n := range c.camouflageNodes() {
		if !n.camo.Enabled() {
			if n.camo.PublicHTTPS {
				errs = append(errs, fmt.Errorf("%s: camouflage.public_https needs camouflage.domain", n.where))
			}
			continue
		}
		d := n.camo.Domain
		if err := validateCamouflageDomain(d); err != nil {
			errs = append(errs, fmt.Errorf("%s: camouflage.domain: %w", n.where, err))
		}
		if prev, dup := seen[strings.ToLower(d)]; dup {
			errs = append(errs, fmt.Errorf("%s: camouflage.domain %q is already used by %s", n.where, d, prev))
		}
		seen[strings.ToLower(d)] = n.where
		if CamouflagePublicIP(n.publicIP, n.sshHost) == "" {
			errs = append(errs, fmt.Errorf("%s: camouflage needs a public address in public_ip (or ssh.host): "+
				"the switch gate checks that the domain resolves to it; a private or overlay address never matches", n.where))
		}
		for _, k := range n.explicit {
			errs = append(errs, fmt.Errorf("%s: camouflage replaces %s; remove one of the two", n.where, k))
		}
		if n.camo.PublicHTTPS && n.holds443 {
			errs = append(errs, fmt.Errorf("%s: camouflage.public_https: TCP/443 is held by a REALITY inbound "+
				"(which already shows the site to probes)", n.where))
		}
	}
	f := c.Fleet.Camouflage
	if f.ACMEEmail != "" {
		if _, err := mail.ParseAddress(f.ACMEEmail); err != nil {
			errs = append(errs, fmt.Errorf("fleet.camouflage.acme_email %q: %w", f.ACMEEmail, err))
		}
	}
	if ca := f.ACMECA; ca != "" && ca != CamouflageCAInternal {
		u, err := url.Parse(ca)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("fleet.camouflage.acme_ca %q: want %q or an https ACME directory URL",
				ca, CamouflageCAInternal))
		}
	}
	return errs
}

// validateCamouflageDomain accepts a lowercase-insensitive DNS name with at least
// two labels: no scheme, port, path or wildcard.
func validateCamouflageDomain(d string) error {
	if len(d) > 253 {
		return fmt.Errorf("%q is longer than 253 characters", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q is not a fully qualified name", d)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q is not a valid DNS name", d)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("%q is not a valid DNS name", d)
			}
		}
	}
	if isIPLiteral(d) {
		return fmt.Errorf("%q is an IP address, not a name", d)
	}
	return nil
}

// CamouflagePublicIP is the address the node's domain must resolve to: the first
// candidate that is a public unicast IP. A private, overlay (ZeroTier) or CGNAT
// address in ssh.host is skipped — public DNS never points there.
func CamouflagePublicIP(candidates ...string) string {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	for _, c := range candidates {
		a, err := netip.ParseAddr(c)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a) {
			return a.String()
		}
	}
	return ""
}

func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}
