package metrics

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CertExpiryCollector publishes when this node's mTLS client certificate expires.
//
// It re-reads the file at every scrape, and that is the whole design. The first
// version parsed the certificate once at process start and Set a plain gauge — which
// was correct on the day it was written and became wrong hours later, when agents
// learned to renew their own certificates IN PROCESS, with no restart. A gauge
// frozen at the boot-time NotAfter says the same thing about a node that renewed
// cleanly on day 300 and a node whose renewal has been failing since day 256: both
// keep publishing the original expiry and both trip the 30-day alert on the original
// anniversary. The one series that exists to tell those two apart must not be a
// snapshot of a file that changes underneath it.
//
// A read failure yields no series rather than a stale one, and raises
// wgfleet_agent_cert_expiry_read_errors_total so the absence is itself visible: an
// unreadable certificate is a node heading for the control plane's door, and
// silence about it is exactly what this collector exists to prevent.
type CertExpiryCollector struct {
	path     string
	desc     *prometheus.Desc
	errDesc  *prometheus.Desc
	notAfter func(string) (time.Time, error)

	// The error count is emitted from this collector's own Collect rather than
	// registered as a standalone Counter: a separate Counter is gathered
	// independently of us, so a scrape can report the failure count from BEFORE the
	// read that just failed — the one scrape where the number matters.
	mu   sync.Mutex
	errs float64
}

var _ prometheus.Collector = (*CertExpiryCollector)(nil)

// NewCertExpiryCollector registers the collector. It parses the certificate once
// up front so a misconfigured path is an error the caller can log at startup rather
// than a series that is quietly never emitted.
func NewCertExpiryCollector(reg *prometheus.Registry, node, role, certPath string) error {
	if _, err := certNotAfter(certPath); err != nil {
		return err
	}
	labels := prometheus.Labels{"node": node, "role": role}
	c := &CertExpiryCollector{
		path: certPath,
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "agent", "cert_expiry_timestamp_seconds"),
			"Unix time at which this node's mTLS client certificate expires. The agent renews it in place between 70% and 90% of its lifetime; a value that stops moving forward means renewal is failing and the node is heading for refusal by the controller.",
			nil, labels,
		),
		errDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "agent", "cert_expiry_read_errors_total"),
			"Scrapes at which this node's mTLS client certificate could not be read or parsed.",
			nil, labels,
		),
		notAfter: certNotAfter,
	}
	reg.MustRegister(c)
	return nil
}

// Describe implements prometheus.Collector.
func (c *CertExpiryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
	ch <- c.errDesc
}

// Collect implements prometheus.Collector.
func (c *CertExpiryCollector) Collect(ch chan<- prometheus.Metric) {
	notAfter, err := c.notAfter(c.path)

	c.mu.Lock()
	if err != nil {
		c.errs++
	}
	errs := c.errs
	c.mu.Unlock()

	ch <- prometheus.MustNewConstMetric(c.errDesc, prometheus.CounterValue, errs)
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(notAfter.Unix()))
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
