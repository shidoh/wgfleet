package metrics

import (
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Probe locates one scheduled probe's persisted outcome markers. SuccessPath is
// the probe's cache file — written ONLY on a successful run, so its mtime is the
// last-success time. AttemptPath is the marker touched on EVERY run (see
// exit.AttemptMarkerPath), so its mtime is the last-attempt time.
type Probe struct {
	Name        string
	SuccessPath string
	AttemptPath string
}

// ProbeCollector exports when each scheduled probe last ATTEMPTED to run and when
// it last SUCCEEDED, at scrape time (like the other collectors: no goroutine, and
// the numbers are current as of the scrape).
//
// Why this exists: scheduled probes degrade gracefully by design — a failure is
// non-fatal, logged at WARN, and the last-good/default value stays in force. That
// is correct, but it makes total failure indistinguishable from normal operation
// from the outside. The WARP path-MTU probe failed on 100% of runs on every node
// for an unknown length of time (an unforced tracepath following an AAAA answer
// into a v6 black hole on an IPv4-only data plane) while the whole fleet reported
// Ready: auto-MTU discovery was dead, and a real PMTU regression — the one thing
// the probe exists to catch — would have gone unnoticed. See an earlier finding.
//
// The two timestamps make "attempting regularly, never succeeding" a first-class
// signal: attempts advance while last-success stays put (or stays 0, meaning the
// probe has NEVER produced a result). Deriving them from the marker files the
// planners already maintain, rather than counting failures in memory, is
// deliberate on two counts: planners are rebuilt from scratch on every reconcile
// pass, so in-process counters silently reset (the bug that once killed tier
// failover), and the probe intervals are hours-to-daily, so a counter would also
// be wiped by any agent restart. File mtimes survive both.
type ProbeCollector struct {
	probes []Probe

	lastSuccess *prometheus.Desc
	lastAttempt *prometheus.Desc
}

var _ prometheus.Collector = (*ProbeCollector)(nil)

// NewProbeCollector builds the scheduled-probe collector and registers it on reg.
// node + role are constant labels (mirrors NewAgentMetrics). Probes with an empty
// name or success path are ignored.
func NewProbeCollector(reg *prometheus.Registry, node, role string, probes []Probe) *ProbeCollector {
	cl := prometheus.Labels{"node": node, "role": role}
	kept := make([]Probe, 0, len(probes))
	for _, p := range probes {
		if p.Name == "" || p.SuccessPath == "" {
			continue
		}
		kept = append(kept, p)
	}
	c := &ProbeCollector{
		probes: kept,
		lastSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "probe", "last_success_timestamp_seconds"),
			"Unix time of a scheduled probe's last SUCCESSFUL run; 0 means it has never succeeded.",
			[]string{"probe"}, cl),
		lastAttempt: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "probe", "last_attempt_timestamp_seconds"),
			"Unix time of a scheduled probe's last run attempt, successful or not; 0 means it has never run.",
			[]string{"probe"}, cl),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *ProbeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lastSuccess
	ch <- c.lastAttempt
}

// Collect implements prometheus.Collector. A probe that has neither succeeded nor
// been attempted yields NO series at all: on a node where it does not apply (the
// AS-blacklist feed with the feature off, the WARP MTU probe on a non-WARP egress
// or with warp_mtu pinned) an all-zero series would read as a broken probe. Once
// it has run even once, both series are emitted — 0 on the side that never
// happened, which is precisely the "attempting but never succeeding" signature.
func (c *ProbeCollector) Collect(ch chan<- prometheus.Metric) {
	for _, p := range c.probes {
		success, okSuccess := fileMTime(p.SuccessPath)
		attempt, okAttempt := fileMTime(p.AttemptPath)
		if !okSuccess && !okAttempt {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.lastSuccess, prometheus.GaugeValue, unixOrZero(success, okSuccess), p.Name)
		ch <- prometheus.MustNewConstMetric(c.lastAttempt, prometheus.GaugeValue, unixOrZero(attempt, okAttempt), p.Name)
	}
}

// fileMTime returns a file's modification time. A missing or unreadable file is
// reported as absent rather than as an error: for a probe marker, "not there" is
// the meaningful state (never ran / never succeeded), not a failure to scrape.
func fileMTime(path string) (time.Time, bool) {
	if path == "" {
		return time.Time{}, false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

func unixOrZero(t time.Time, ok bool) float64 {
	if !ok {
		return 0
	}
	return float64(t.Unix())
}
