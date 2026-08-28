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

// Node certificates last a year, nothing renews them, and until this gauge existed
// nothing published the date either — so the first sign of a lapse was a node that
// had stopped reporting, one node per provisioning anniversary.
func TestCertExpiryGaugePublishesNotAfter(t *testing.T) {
	want := time.Now().Add(300 * 24 * time.Hour).Truncate(time.Second)
	path := writeTestCert(t, want)

	reg := prometheus.NewRegistry()
	if err := NewCertExpiryGauge(reg, "master-xa-1", "master", path); err != nil {
		t.Fatalf("NewCertExpiryGauge: %v", err)
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
	if err := NewCertExpiryGauge(prometheus.NewRegistry(), "n", "master", bad); err == nil {
		t.Error("a file with no certificate in it was accepted")
	}
	if err := NewCertExpiryGauge(prometheus.NewRegistry(), "n", "master", filepath.Join(dir, "absent")); err == nil {
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
