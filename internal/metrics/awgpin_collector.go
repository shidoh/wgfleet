package metrics

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Names rendered by internal/netfw for the exit-initiated AWG flow. Repeated here
// rather than imported: metrics must not depend on the renderer, and the
// collector test reads a ruleset captured from a real kernel, so a rename on
// either side fails it.
const (
	awgPinTable   = "wgfleet_master"
	awgHeardSet   = "awg_exit_heard"
	awgGatePrefix = "awg_exit_gate_"
)

// ExitNameFunc maps an exit's IP to its node name for the `exit` label; "" or a
// nil func falls back to the IP.
type ExitNameFunc func(ip string) string

// AWGPinCollector reads the master's gate for exit-initiated AWG flows at scrape
// time: which exits are armed, which have been heard and how recently, and how
// many packets the gate held back. The questions an operator asks when such a
// tunnel is down are "is the exit knocking" and "is the master waiting", and
// both answers live only in the kernel.
type AWGPinCollector struct {
	list  NFTFunc
	names ExitNameFunc

	armed    *prometheus.Desc
	heard    *prometheus.Desc
	heardAge *prometheus.Desc
	drops    *prometheus.Desc
}

var _ prometheus.Collector = (*AWGPinCollector)(nil)

// NewAWGPinCollector registers the collector. list defaults to
// `nft -j list table ip wgfleet_master`.
func NewAWGPinCollector(reg *prometheus.Registry, node, role string, list NFTFunc, names ExitNameFunc) *AWGPinCollector {
	if list == nil {
		list = func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "nft", "-j", "list", "table", "ip", awgPinTable).Output()
		}
	}
	cl := prometheus.Labels{"node": node, "role": role}
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(namespace, "agent", name), help, []string{"exit"}, cl)
	}
	c := &AWGPinCollector{
		list:  list,
		names: names,
		armed: desc("awg_pin_armed",
			"1 when the master answers this exit's AWG tunnel only from its pinned port and only after hearing the exit (exit-initiated flow). Master nodes only."),
		heard: desc("awg_exit_heard",
			"1 while the exit's knocks on its pinned master port keep it in the gate's heard set, else 0. Master nodes only."),
		heardAge: desc("awg_exit_heard_age_seconds",
			"Seconds since the exit's last knock on its pinned master port. Absent while the exit is not heard. Master nodes only."),
		drops: desc("awg_gate_drops_total",
			"Packets the master's gate held back from a new flow to the exit because the exit had not knocked yet. Master nodes only."),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *AWGPinCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.armed
	ch <- c.heard
	ch <- c.heardAge
	ch <- c.drops
}

// Collect implements prometheus.Collector. No table, no series: a master with no
// armed tunnel has nothing to say, and must not look like one whose exits went quiet.
func (c *AWGPinCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), nftListTimeout)
	defer cancel()
	out, err := c.list(ctx)
	if err != nil {
		return
	}
	st, ok := parseAWGPin(out)
	if !ok {
		return
	}
	for ip, dropped := range st.armed {
		exit := c.label(ip)
		ch <- prometheus.MustNewConstMetric(c.armed, prometheus.GaugeValue, 1, exit)
		ch <- prometheus.MustNewConstMetric(c.drops, prometheus.CounterValue, dropped, exit)
		age, heard := st.heardAge[ip]
		if !heard {
			ch <- prometheus.MustNewConstMetric(c.heard, prometheus.GaugeValue, 0, exit)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.heard, prometheus.GaugeValue, 1, exit)
		ch <- prometheus.MustNewConstMetric(c.heardAge, prometheus.GaugeValue, age, exit)
	}
}

func (c *AWGPinCollector) label(ip string) string {
	if c.names != nil {
		if n := c.names(ip); n != "" {
			return n
		}
	}
	return ip
}

type awgPinStats struct {
	armed    map[string]float64 // exit IP → packets held back, summed over both gates
	heardAge map[string]float64 // exit IP → seconds since the last knock
}

type nftPinDoc struct {
	Nftables []struct {
		Set  *nftPinSet  `json:"set"`
		Rule *nftPinRule `json:"rule"`
	} `json:"nftables"`
}

type nftPinSet struct {
	Name    string  `json:"name"`
	Timeout float64 `json:"timeout"`
	Elem    []struct {
		Elem struct {
			Val     string  `json:"val"`
			Expires float64 `json:"expires"`
		} `json:"elem"`
	} `json:"elem"`
}

type nftPinRule struct {
	Chain string            `json:"chain"`
	Expr  []json.RawMessage `json:"expr"`
}

type nftPinExpr struct {
	Match *struct {
		Op   string `json:"op"`
		Left struct {
			Payload *struct {
				Field string `json:"field"`
			} `json:"payload"`
		} `json:"left"`
		Right json.RawMessage `json:"right"`
	} `json:"match"`
	Counter *struct {
		Packets float64 `json:"packets"`
	} `json:"counter"`
}

// parseAWGPin reads the gate chains and the heard set out of the master's NAT
// table. ok is false when the JSON is unreadable.
func parseAWGPin(out []byte) (awgPinStats, bool) {
	var doc nftPinDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return awgPinStats{}, false
	}
	st := awgPinStats{armed: map[string]float64{}, heardAge: map[string]float64{}}
	for _, o := range doc.Nftables {
		switch {
		case o.Set != nil && o.Set.Name == awgHeardSet:
			for _, e := range o.Set.Elem {
				st.heardAge[e.Elem.Val] = o.Set.Timeout - e.Elem.Expires
			}
		case o.Rule != nil && strings.HasPrefix(o.Rule.Chain, awgGatePrefix):
			ip, packets := gateRule(o.Rule.Expr)
			if ip != "" {
				st.armed[ip] += packets
			}
		}
	}
	return st, true
}

// gateRule returns the exit a gate rule guards (its `ip daddr == X` match) and
// the rule's counter.
func gateRule(exprs []json.RawMessage) (ip string, packets float64) {
	for _, raw := range exprs {
		var e nftPinExpr
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		if e.Counter != nil {
			packets = e.Counter.Packets
		}
		m := e.Match
		if m == nil || m.Op != "==" || m.Left.Payload == nil || m.Left.Payload.Field != "daddr" || ip != "" {
			continue
		}
		var s string
		if json.Unmarshal(m.Right, &s) == nil {
			ip = s
		}
	}
	return ip, packets
}
