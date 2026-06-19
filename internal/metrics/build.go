package metrics

import "github.com/prometheus/client_golang/prometheus"

// RegisterBuildInfo registers a wgfleet_build_info gauge (value always 1) carrying
// the component's build version and commit as labels, the conventional way to
// surface "what is running" on a dashboard. component is "controller" or "agent".
func RegisterBuildInfo(reg *prometheus.Registry, component, version, commit string) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Build version and commit of the running component; value is always 1.",
	}, []string{"component", "version", "commit"})
	g.WithLabelValues(component, version, commit).Set(1)
	reg.MustRegister(g)
}
