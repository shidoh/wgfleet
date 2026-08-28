package metrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Node certificates last a year, and until this collector existed nothing published
// the date — so the first sign of a lapse was a node that had stopped reporting, one
// node per provisioning anniversary.
func TestCertExpiryGaugePublishesNotAfter(t *testing.T) {
	want := time.Now().Add(300 * 24 * time.Hour).Truncate(time.Second)
	path := writeTestCert(t, want)

	reg := prometheus.NewRegistry()
	if err := NewCertExpiryCollector(reg, "master-xa-1", "master", path); err != nil {
		t.Fatalf("NewCertExpiryCollector: %v", err)
	}
	got := gatherValue(t, reg, "wgfleet_agent_cert_expiry_timestamp_seconds", nil)
	if int64(got) != want.Unix() {
		t.Errorf("expiry = %d, want %d", int64(got), want.Unix())
	}
}

func TestCertExpiryGaugeRefusesRubbish(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(bad, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewCertExpiryCollector(prometheus.NewRegistry(), "n", "master", bad); err == nil {
		t.Error("a file with no certificate in it was accepted")
	}
	if err := NewCertExpiryCollector(prometheus.NewRegistry(), "n", "master", filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func writeTestCert(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "master-xa-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The agent renews its certificate in place, with no restart. A gauge read once at
// boot reports the pre-renewal expiry forever, which makes a healthy node and a node
// whose renewal has been failing for months publish the identical series — and trips
// the 30-day alert fleet-wide on the original anniversary.
func TestCertExpiryFollowsTheFileAcrossRenewal(t *testing.T) {
	first := time.Now().Add(40 * 24 * time.Hour).Truncate(time.Second)
	path := writeTestCert(t, first)

	reg := prometheus.NewRegistry()
	if err := NewCertExpiryCollector(reg, "master-xa-1", "master", path); err != nil {
		t.Fatalf("NewCertExpiryCollector: %v", err)
	}
	if got := gatherValue(t, reg, "wgfleet_agent_cert_expiry_timestamp_seconds", nil); int64(got) != first.Unix() {
		t.Fatalf("before renewal: expiry = %d, want %d", int64(got), first.Unix())
	}

	renewed := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	replaceTestCert(t, path, renewed)

	if got := gatherValue(t, reg, "wgfleet_agent_cert_expiry_timestamp_seconds", nil); int64(got) != renewed.Unix() {
		t.Errorf("after renewal: expiry = %d, want %d", int64(got), renewed.Unix())
	}
}

// A certificate that has become unreadable must not keep publishing the last value
// it had: an operator reading a moving-forward expiry off a file the agent can no
// longer open is worse off than one reading nothing.
func TestCertExpiryDropsTheSeriesWhenTheFileGoesBad(t *testing.T) {
	path := writeTestCert(t, time.Now().Add(90*24*time.Hour))
	reg := prometheus.NewRegistry()
	if err := NewCertExpiryCollector(reg, "n", "master", path); err != nil {
		t.Fatalf("NewCertExpiryCollector: %v", err)
	}
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	errs := -1.0
	for _, mf := range mfs {
		switch mf.GetName() {
		case "wgfleet_agent_cert_expiry_timestamp_seconds":
			t.Errorf("a stale expiry was still published from an unparsable file")
		case "wgfleet_agent_cert_expiry_read_errors_total":
			errs = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	if errs != 1 {
		t.Errorf("read errors = %v, want 1", errs)
	}
}

// replaceTestCert overwrites an existing certificate file in place, the way the
// agent's own rotation does.
func replaceTestCert(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	fresh := writeTestCert(t, notAfter)
	raw, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
