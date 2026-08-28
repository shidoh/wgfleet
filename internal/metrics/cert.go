package metrics

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// NewCertExpiryGauge publishes when this node's mTLS client certificate expires.
//
// Node certificates are issued for a year and there is no renewal path anywhere in
// this system: no RPC renews one, no code reads NotAfter after issuance, and no
// document mentions it. The controller's own server certificate is re-minted on
// every start, so the server half self-heals and the node half does not — meaning a
// fleet provisioned across one month falls off the control plane across one month,
// one node per anniversary, and the first symptom is a node that stopped reporting.
//
// Renewal is the real fix and is a larger change. This is the part that must not
// wait for it: an expiry a year out is only invisible if nobody is looking, and
// until something publishes the date nobody can.
func NewCertExpiryGauge(reg *prometheus.Registry, node, role, certPath string) error {
	notAfter, err := certNotAfter(certPath)
	if err != nil {
		return err
	}
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   namespace,
		Subsystem:   "agent",
		Name:        "cert_expiry_timestamp_seconds",
		Help:        "Unix time at which this node's mTLS client certificate expires. There is no automatic renewal; a node whose certificate lapses is refused by the controller.",
		ConstLabels: prometheus.Labels{"node": node, "role": role},
	}, nil)
	reg.MustRegister(g)
	g.WithLabelValues().Set(float64(notAfter.Unix()))
	return nil
}

// certNotAfter reads the leaf certificate's expiry from a PEM file.
func certNotAfter(path string) (time.Time, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("read certificate %q: %w", path, err)
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return time.Time{}, fmt.Errorf("no CERTIFICATE block in %q", path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse certificate %q: %w", path, err)
		}
		return c.NotAfter, nil
	}
}
