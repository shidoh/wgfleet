package camouflage

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func spec() domain.CamouflageSpec {
	return domain.CamouflageSpec{Domain: "e1.example.net", PublicIP: "198.51.100.20"}
}

func TestCaddyfileServesTheLoopbackTargetForAnyName(t *testing.T) {
	out, err := RenderCaddyfile(CaddyInput{Spec: spec()})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"admin off",
		"default_sni e1.example.net",
		"fallback_sni e1.example.net",
		"protocols h1 h2",
		"https://e1.example.net:8444, https://:8444 {\n\tbind 127.0.0.1",
		"http://:80 {\n\timport site\n}",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Caddyfile lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{":443", "local_certs", "acme_ca", "email"} {
		if strings.Contains(out, not) {
			t.Errorf("Caddyfile has %q without being asked:\n%s", not, out)
		}
	}
}

func TestCaddyfilePublicHTTPSAndRedirect(t *testing.T) {
	s := spec()
	s.PublicHTTPS = true
	s.ACMEEmail = "ops@example.net"
	s.ACMECA = "https://ca.example.net/directory"
	s.LocalPort = 9443
	out, err := RenderCaddyfile(CaddyInput{Spec: s})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"email ops@example.net", "acme_ca https://ca.example.net/directory",
		"https://e1.example.net:9443, https://:9443 {",
		"https://e1.example.net:443, https://:443 {\n\timport site",
		"redir https://e1.example.net{uri} 308",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Caddyfile lacks %q:\n%s", want, out)
		}
	}
	// A REALITY inbound on 443 shows the site too, so port 80 redirects to it.
	out, _ = RenderCaddyfile(CaddyInput{Spec: spec(), HTTPSOn443: true})
	if !strings.Contains(out, "redir https://e1.example.net{uri} 308") || strings.Contains(out, "https://:443") {
		t.Errorf("inbound on 443: want a redirect and no own 443 listener:\n%s", out)
	}
	s = spec()
	s.ACMECA = domain.CamouflageCAInternal
	if out, _ = RenderCaddyfile(CaddyInput{Spec: s}); !strings.Contains(out, "local_certs") {
		t.Errorf("internal CA: want local_certs:\n%s", out)
	}
}

func TestCaddyfileRefusesAnInvalidSpec(t *testing.T) {
	s := spec()
	s.Domain = "e1.example.net {\n}"
	if _, err := RenderCaddyfile(CaddyInput{Spec: s}); err == nil {
		t.Fatal("rendered a Caddyfile for a domain that would inject a block")
	}
}

func TestIndexHTMLEscapes(t *testing.T) {
	if out := IndexHTML("a<b>.example.net"); strings.Contains(out, "<b>") {
		t.Errorf("unescaped: %s", out)
	}
}

// site starts a TLS server on the loopback with a certificate for the spec's
// domain, writes its CA to a roots file, and returns the spec pointed at it.
func site(t *testing.T) (domain.CamouflageSpec, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// httptest's certificate covers example.com; the probe dials the loopback
	// with the domain as SNI, so the spec's domain is example.com here.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	roots := filepath.Join(t.TempDir(), "root.crt")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(roots, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return domain.CamouflageSpec{Domain: "example.com", PublicIP: "198.51.100.20", LocalPort: p}, roots
}

func resolveTo(addrs ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return addrs, nil }
}

func TestProbePassesForTheSiteAndTheRightAddress(t *testing.T) {
	s, roots := site(t)
	r := Prober{RootsFile: roots, Resolve: resolveTo("203.0.113.9", "198.51.100.20")}.Probe(context.Background(), s)
	if !r.OK() || r.Reason != "" {
		t.Fatalf("result = %+v, want ok", r)
	}
	if r.NotAfter.IsZero() {
		t.Error("certificate expiry not read")
	}
}

func TestProbeFailures(t *testing.T) {
	s, roots := site(t)
	ctx := context.Background()

	r := Prober{RootsFile: roots, Resolve: resolveTo("203.0.113.9")}.Probe(ctx, s)
	if !r.TLSOK || r.DNSOK || !strings.Contains(r.Reason, "not to this node's 198.51.100.20") {
		t.Errorf("wrong address: %+v", r)
	}
	r = Prober{RootsFile: roots, Resolve: func(context.Context, string) ([]string, error) {
		return nil, errors.New("no such host")
	}}.Probe(ctx, s)
	if r.DNSOK || !strings.Contains(r.Reason, "does not resolve") {
		t.Errorf("no address: %+v", r)
	}
	// An untrusted certificate is a failed site, not a working one.
	r = Prober{RootsFile: filepath.Join(t.TempDir(), "missing.crt"), Resolve: resolveTo("198.51.100.20")}.Probe(ctx, s)
	if r.TLSOK || !strings.Contains(r.Reason, "local CA not issued yet") {
		t.Errorf("missing roots: %+v", r)
	}
	other := s
	other.Domain = "e1.example.net"
	r = Prober{RootsFile: roots, Resolve: resolveTo("198.51.100.20")}.Probe(ctx, other)
	if r.TLSOK {
		t.Errorf("certificate for another name accepted: %+v", r)
	}
	// An expired certificate fails the handshake too.
	r = Prober{RootsFile: roots, Resolve: resolveTo("198.51.100.20"),
		Now: func() time.Time { return time.Now().Add(100 * 365 * 24 * time.Hour) }}.Probe(ctx, s)
	if r.TLSOK {
		t.Errorf("expired certificate accepted: %+v", r)
	}
	closed := s
	closed.LocalPort = 1
	if r = (Prober{RootsFile: roots, Resolve: resolveTo("198.51.100.20")}).Probe(ctx, closed); r.TLSOK {
		t.Errorf("nothing listening, yet TLS ok: %+v", r)
	}
}

var (
	ok      = Result{TLSOK: true, DNSOK: true, NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	down    = Result{Reason: "connection refused"}
	wrongNS = Result{TLSOK: true, Reason: "resolves elsewhere", NotAfter: ok.NotAfter}
)

func TestGateOpensOnlyOnAFullPass(t *testing.T) {
	s := spec()
	g := NewGate("")
	for _, r := range []Result{down, wrongNS} {
		if _, err := g.Observe(&s, r); err != nil {
			t.Fatal(err)
		}
		if g.ActiveDomain() != "" {
			t.Fatalf("opened on %+v", r)
		}
	}
	if changed, _ := g.Observe(&s, ok); !changed || g.ActiveDomain() != s.Domain {
		t.Fatal("did not open on a full pass")
	}
	if d, target := g.Target(&s); d != s.Domain || target != "127.0.0.1:8444" {
		t.Errorf("Target = %q %q", d, target)
	}
}

func TestGateClosesAfterTwoFailedPassesNotOne(t *testing.T) {
	s := spec()
	g := NewGate("")
	g.Observe(&s, ok)
	g.Observe(&s, down)
	if g.ActiveDomain() != s.Domain {
		t.Fatal("closed on a single failed pass")
	}
	g.Observe(&s, ok)
	g.Observe(&s, down)
	if g.ActiveDomain() != s.Domain {
		t.Fatal("a pass in between must reset the count")
	}
	g.Observe(&s, down)
	if g.ActiveDomain() != "" {
		t.Fatal("still open after two failed passes in a row")
	}
	if d, target := g.Target(&s); d != s.Domain || target != "" {
		t.Errorf("closed Target = %q %q, want the domain without a target", d, target)
	}
}

// A wrong DNS answer stops the gate from opening but never closes it: every peer
// still connects through the local target.
func TestGateStaysOpenOnADNSChange(t *testing.T) {
	s := spec()
	g := NewGate("")
	g.Observe(&s, ok)
	g.Observe(&s, wrongNS)
	g.Observe(&s, wrongNS)
	if g.ActiveDomain() != s.Domain {
		t.Fatal("closed on DNS alone")
	}
	if hc := g.Check(s, time.Now()); hc.OK {
		t.Errorf("check green with DNS wrong: %+v", hc)
	}
}

func TestGateClosesWhenTheDomainChangesOrCamouflageGoes(t *testing.T) {
	s := spec()
	g := NewGate("")
	g.Observe(&s, ok)
	other := s
	other.Domain = "e2.example.net"
	g.Observe(&other, down)
	if g.ActiveDomain() != "" {
		t.Fatalf("still serving %q for a spec that names another domain", g.ActiveDomain())
	}
	g.Observe(&other, ok)
	g.Observe(nil, Result{})
	if g.ActiveDomain() != "" {
		t.Fatal("open with no camouflage in the spec")
	}
	if d, target := g.Target(nil); d != "" || target != "" {
		t.Errorf("Target(nil) = %q %q", d, target)
	}
}

func TestGatePersistsItsDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "camouflage.active")
	s := spec()
	g := NewGate(path)
	g.Observe(&s, ok)
	if got := NewGate(path).ActiveDomain(); got != s.Domain {
		t.Fatalf("restarted gate serves %q, want %q", got, s.Domain)
	}
	g.Observe(&s, down)
	g.Observe(&s, down)
	if got := NewGate(path).ActiveDomain(); got != "" {
		t.Fatalf("restarted gate serves %q after closing", got)
	}
}

func TestGateCheck(t *testing.T) {
	s := spec()
	now := time.Now()
	g := NewGate("")
	if hc := g.Check(s, now); hc.OK || hc.Name != "camouflage" || !strings.Contains(hc.Detail, "not checked") {
		t.Errorf("unchecked: %+v", hc)
	}
	g.Observe(&s, ok)
	if hc := g.Check(s, now); !hc.OK || !strings.Contains(hc.Detail, "serving e1.example.net") {
		t.Errorf("serving: %+v", hc)
	}
	soon := ok
	soon.NotAfter = now.Add(3 * 24 * time.Hour)
	g.Observe(&s, soon)
	if hc := g.Check(s, now); hc.OK || !strings.Contains(hc.Detail, "expires in") {
		t.Errorf("expiring: %+v", hc)
	}
	g.Observe(&s, down)
	if hc := g.Check(s, now); hc.OK || !strings.Contains(hc.Detail, "still the target") {
		t.Errorf("one failure: %+v", hc)
	}
}
