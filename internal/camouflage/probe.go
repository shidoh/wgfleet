package camouflage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Result is one probe of the site.
type Result struct {
	// TLSOK: the loopback site completed a TLS 1.3 handshake for the domain with a
	// certificate that chains to a trusted root and has not expired.
	TLSOK bool
	// DNSOK: the domain resolves to the node's public IP.
	DNSOK bool
	// NotAfter is the certificate's expiry; zero when no certificate was read.
	NotAfter time.Time
	// Reason explains the first failure; empty when both checks passed.
	Reason string
}

// OK reports whether the site may become the REALITY target.
func (r Result) OK() bool { return r.TLSOK && r.DNSOK }

// Prober checks the site. The zero value checks the real network.
type Prober struct {
	// Resolve returns the addresses of a name; nil ⇒ the system resolver (which
	// honours /etc/hosts — how a stand points the domain at the node).
	Resolve func(ctx context.Context, host string) ([]string, error)
	// RootsFile is a PEM bundle trusted instead of the system roots — the local CA
	// of Caddy's internal issuer on a stand. Empty ⇒ the system roots.
	RootsFile string
	// Now is the clock; nil ⇒ time.Now.
	Now func() time.Time
}

// probeTimeout bounds each check; the site is on the loopback.
const probeTimeout = 5 * time.Second

// Probe runs both checks against the spec's site. Both always run, so the
// result carries the certificate's expiry even when DNS is wrong.
func (p Prober) Probe(ctx context.Context, s domain.CamouflageSpec) Result {
	var r Result
	tlsErr := p.checkTLS(ctx, s, &r)
	dnsErr := p.checkDNS(ctx, s)
	r.TLSOK, r.DNSOK = tlsErr == nil, dnsErr == nil
	switch {
	case tlsErr != nil:
		r.Reason = tlsErr.Error()
	case dnsErr != nil:
		r.Reason = dnsErr.Error()
	}
	return r
}

func (p Prober) now() time.Time {
	if p.Now == nil {
		return time.Now()
	}
	return p.Now()
}

func (p Prober) checkTLS(ctx context.Context, s domain.CamouflageSpec, r *Result) error {
	roots, err := p.roots()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		ServerName: s.Domain,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		Time:       p.now,
	}}
	conn, err := d.DialContext(ctx, "tcp", s.LocalTarget())
	if err != nil {
		return fmt.Errorf("site %s does not answer TLS for %s: %w", s.LocalTarget(), s.Domain, err)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) > 0 {
		r.NotAfter = state.PeerCertificates[0].NotAfter
	}
	return nil
}

func (p Prober) roots() (*x509.CertPool, error) {
	if p.RootsFile == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("system roots: %w", err)
		}
		return pool, nil
	}
	pem, err := os.ReadFile(p.RootsFile)
	if err != nil {
		return nil, fmt.Errorf("local CA not issued yet: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("local CA %s holds no certificate", p.RootsFile)
	}
	return pool, nil
}

func (p Prober) checkDNS(ctx context.Context, s domain.CamouflageSpec) error {
	want, err := netip.ParseAddr(s.PublicIP)
	if err != nil {
		return fmt.Errorf("public ip %q: %w", s.PublicIP, err)
	}
	resolve := p.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	addrs, err := resolve(ctx, s.Domain)
	if err != nil {
		return fmt.Errorf("%s does not resolve: %w", s.Domain, err)
	}
	for _, a := range addrs {
		if got, err := netip.ParseAddr(a); err == nil && got.Unmap() == want.Unmap() {
			return nil
		}
	}
	return fmt.Errorf("%s resolves to %v, not to this node's %s", s.Domain, addrs, s.PublicIP)
}

// LocalCARoot is where Caddy's internal issuer keeps its root, under the data dir.
func LocalCARoot(dataDir string) string {
	return dataDir + "/caddy/pki/authorities/local/root.crt"
}
