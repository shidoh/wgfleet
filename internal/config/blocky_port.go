package config

import "github.com/shidoh/wgfleet/internal/dnsfilter"

// BlockyMetricsPort is the port a node's blocky serves /metrics on, or 0 when the
// node runs no blocky (dns_filter off) or has its metrics turned off. It reads the
// same blocks the renderer does, so service discovery lists exactly what runs.
func (f FleetSection) BlockyMetricsPort(node string) int {
	for _, m := range f.Masters {
		if m.Name == node {
			if !m.DNSFilter {
				return 0
			}
			return blockyHTTPPort(f.MasterDNSFor(m))
		}
	}
	for _, e := range f.Exits {
		if e.Name == node {
			if !e.DNSFilter {
				return 0
			}
			return blockyHTTPPort(e.DNS)
		}
	}
	return 0
}

func blockyHTTPPort(d DNSConfig) int {
	if d.Prometheus != nil && !*d.Prometheus {
		return 0
	}
	if d.Ports.HTTP > 0 {
		return d.Ports.HTTP
	}
	return dnsfilter.DefaultHTTPPort
}
