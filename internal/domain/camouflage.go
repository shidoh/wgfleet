package domain

import (
	"fmt"
	"net/netip"
	"strings"
)

// CamouflageSpec is a node's own-domain camouflage (ADR-0039): the agent runs a
// web server with a certificate for Domain, and every REALITY inbound on the node
// takes it as its target once the switch gate opens. The inbound specs keep their
// fleet-default ServerName/Dest — that is the fallback the gate returns to.
type CamouflageSpec struct {
	// Domain is the node's own name; its A record points at PublicIP.
	Domain string
	// PublicHTTPS also serves the site on public TCP/443.
	PublicHTTPS bool
	// PublicIP is the address the domain must resolve to before the gate opens.
	PublicIP string
	// ACMEEmail is the certificate authority contact; optional.
	ACMEEmail string
	// ACMECA is "" (public defaults), CamouflageCAInternal (local CA, stands) or an
	// ACME directory URL.
	ACMECA string
	// Image is the web server image (pinned repo:tag); empty ⇒ the agent default.
	Image string
	// LocalPort is the loopback TLS port the inbounds use as target; 0 ⇒
	// CamouflageLocalPort.
	LocalPort int
}

// CamouflageLocalPort is the default loopback port of the camouflage site.
const CamouflageLocalPort = 8444

// CamouflageCAInternal makes the web server issue from its own local CA (stands).
const CamouflageCAInternal = "internal"

// ResolvedLocalPort returns LocalPort or its default.
func (c CamouflageSpec) ResolvedLocalPort() int {
	if c.LocalPort == 0 {
		return CamouflageLocalPort
	}
	return c.LocalPort
}

// LocalTarget is the REALITY target "127.0.0.1:<port>" of the camouflage site.
func (c CamouflageSpec) LocalTarget() string {
	return fmt.Sprintf("127.0.0.1:%d", c.ResolvedLocalPort())
}

// Validate rejects a spec the agent cannot render safely. The controller has
// validated the manifest already; this guards the wire.
func (c CamouflageSpec) Validate() error {
	if c.Domain == "" || strings.ContainsAny(c.Domain, "/: *{}\n\t") || !strings.Contains(c.Domain, ".") {
		return fmt.Errorf("camouflage: domain %q is not a hostname", c.Domain)
	}
	if _, err := netip.ParseAddr(c.PublicIP); err != nil {
		return fmt.Errorf("camouflage: public ip %q: %w", c.PublicIP, err)
	}
	if p := c.LocalPort; p != 0 && (p < 1024 || p > 65535) {
		return fmt.Errorf("camouflage: local port %d out of range", p)
	}
	if strings.ContainsAny(c.ACMEEmail, " \n\t{}") {
		return fmt.Errorf("camouflage: acme email %q is not an address", c.ACMEEmail)
	}
	if ca := c.ACMECA; ca != "" && ca != CamouflageCAInternal && !strings.HasPrefix(ca, "https://") {
		return fmt.Errorf("camouflage: acme ca %q", ca)
	}
	if strings.ContainsAny(c.ACMECA, " \n\t{}") {
		return fmt.Errorf("camouflage: acme ca %q", c.ACMECA)
	}
	return nil
}
