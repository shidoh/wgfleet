package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/domain"
)

// ProfileFetchSource is the slice of the store this collector reads.
type ProfileFetchSource interface {
	ListDevices(ctx context.Context) ([]domain.ClientDevice, error)
	ListProfileFetches(ctx context.Context) ([]domain.ProfileFetch, error)
}

// ProfileFetchCollector reports when each device last downloaded its profile and
// what software did it. A change a stale profile cannot follow waits until every
// device shows a download newer than the change, from a core new enough to
// follow it.
type ProfileFetchCollector struct {
	src  ProfileFetchSource
	now  func() time.Time
	age  *prometheus.Desc
	info *prometheus.Desc
}

var _ prometheus.Collector = (*ProfileFetchCollector)(nil)

// NewProfileFetchCollector builds the collector and registers it on reg.
func NewProfileFetchCollector(reg *prometheus.Registry, src ProfileFetchSource) *ProfileFetchCollector {
	c := &ProfileFetchCollector{
		src: src,
		now: time.Now,
		age: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "client_profile", "fetch_age_seconds"),
			"Seconds since the device last downloaded this kind from the portal (absent if never).",
			[]string{"device", "kind"}, nil),
		info: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "client_profile", "fetch_info"),
			"Software behind the device's latest download, read from its User-Agent; value is always 1.",
			[]string{"device", "kind", "app", "app_version", "core_version"}, nil),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *ProfileFetchCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.age
	ch <- c.info
}

// Collect implements prometheus.Collector. A store read error emits nothing:
// store_up on the store collector already says the store could not be read.
func (c *ProfileFetchCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	devs, err := c.src.ListDevices(ctx)
	if err != nil {
		return
	}
	fetches, err := c.src.ListProfileFetches(ctx)
	if err != nil {
		return
	}
	names := make(map[string]string, len(devs))
	for _, d := range devs {
		names[d.ID] = d.Name
	}
	for _, f := range fetches {
		name, ok := names[f.DeviceID]
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.age, prometheus.GaugeValue,
			c.now().Sub(f.At).Seconds(), name, string(f.Kind))
		a := clientcfg.ParseUserAgent(f.UserAgent)
		ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1,
			name, string(f.Kind), a.App, a.AppVersion, a.CoreVersion)
	}
}
