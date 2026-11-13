// Package camouflage renders and checks a node's own-domain site (ADR-0039): a
// Caddy instance with a certificate for the node's domain that every REALITY
// inbound on the node uses as its target.
package camouflage

import (
	"fmt"
	"html"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// CaddyInput is what the Caddyfile depends on beyond the spec.
type CaddyInput struct {
	Spec domain.CamouflageSpec
	// HTTPSOn443 says the node answers TLS on public TCP/443 with the site —
	// through Caddy itself (public_https) or through a REALITY inbound on 443,
	// whose probes reach the site. Port 80 then redirects; otherwise it serves the
	// page itself, since a redirect would lead nowhere.
	HTTPSOn443 bool
}

// RenderCaddyfile renders the site's Caddyfile.
//
// The loopback site is the REALITY target. default_sni and fallback_sni make it
// answer a ClientHello without SNI or with any other name (a peer still on the
// fleet-default name) with the domain's certificate — REALITY completes every
// handshake through the target, so a refusal here would refuse the peer.
func RenderCaddyfile(in CaddyInput) (string, error) {
	s := in.Spec
	if err := s.Validate(); err != nil {
		return "", err
	}
	d := s.Domain
	var b strings.Builder
	b.WriteString("{\n\tadmin off\n")
	fmt.Fprintf(&b, "\tdefault_sni %s\n\tfallback_sni %s\n", d, d)
	if s.ACMEEmail != "" {
		fmt.Fprintf(&b, "\temail %s\n", s.ACMEEmail)
	}
	switch s.ACMECA {
	case "":
	case domain.CamouflageCAInternal:
		b.WriteString("\tlocal_certs\n")
	default:
		fmt.Fprintf(&b, "\tacme_ca %s\n", s.ACMECA)
	}
	// No HTTP/3: a UDP listener nobody can reach behind the node firewall.
	b.WriteString("\tauto_https disable_redirects\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n\n")
	b.WriteString("(site) {\n\troot * /srv\n\tfile_server\n}\n\n")
	port := s.ResolvedLocalPort()
	fmt.Fprintf(&b, "https://%s:%d, https://:%d {\n\tbind 127.0.0.1\n\timport site\n}\n\n", d, port, port)
	if s.PublicHTTPS {
		fmt.Fprintf(&b, "https://%s:443, https://:443 {\n\timport site\n}\n\n", d)
	}
	// Port 80 serves the ACME HTTP-01 challenge (Caddy answers it on any HTTP
	// server it runs) and whatever an ordinary site would.
	if in.HTTPSOn443 || s.PublicHTTPS {
		fmt.Fprintf(&b, "http://:80 {\n\tredir https://%s{uri} 308\n}\n", d)
	} else {
		b.WriteString("http://:80 {\n\timport site\n}\n")
	}
	return b.String(), nil
}

// IndexHTML is the site's only page: a plain placeholder under the domain's name.
func IndexHTML(domainName string) string {
	n := html.EscapeString(domainName)
	return "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
		"<title>" + n + "</title>\n" +
		"<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}</style>\n" +
		"</head>\n<body>\n<h1>" + n + "</h1>\n<p>This server is operated by the owner of " + n + ".</p>\n</body>\n</html>\n"
}
