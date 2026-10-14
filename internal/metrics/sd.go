package metrics

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
)

// SDGroup is one Prometheus HTTP service-discovery target group.
type SDGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// SDConfig is what the discovery endpoint needs beyond the store.
type SDConfig struct {
	// ControllerAddr is the controller's own /metrics address, listed in the
	// wgfleet job beside the agents.
	ControllerAddr string
	// BlockyPort returns the blocky HTTP (metrics) port of a node, or 0 when that
	// node runs no blocky or does not export its metrics.
	BlockyPort func(node string) int
}

// SDHandler serves Prometheus HTTP service discovery for the fleet's scrape jobs:
//
//	GET /sd/wgfleet        the controller and every agent
//	GET /sd/node-exporter  every node's node_exporter
//	GET /sd/blocky         every node's blocky
//
// The controller already knows every node and its mgmt address, so a scraper
// pointed here picks up a new node by itself. A hand-kept target list is what
// left a second master's DNS unscraped: it was added to two jobs and not the third.
func SDHandler(st store.Store, cfg SDConfig) http.Handler {
	mux := http.NewServeMux()
	jobs := map[string]func([]domain.Node) []SDGroup{
		"wgfleet":       func(ns []domain.Node) []SDGroup { return wgfleetGroups(ns, cfg.ControllerAddr) },
		"node-exporter": nodeExporterGroups,
		"blocky":        func(ns []domain.Node) []SDGroup { return blockyGroups(ns, cfg.BlockyPort) },
	}
	for name, build := range jobs {
		mux.HandleFunc("GET /sd/"+name, func(w http.ResponseWriter, r *http.Request) {
			serveSD(w, r, st, build)
		})
	}
	return mux
}

func serveSD(w http.ResponseWriter, r *http.Request, st store.Store, build func([]domain.Node) []SDGroup) {
	ctx, cancel := context.WithTimeout(r.Context(), scrapeTimeout)
	defer cancel()
	nodes, err := st.ListNodes(ctx)
	if err != nil {
		// Never answer an empty list here: the scraper would take it as "no
		// targets" and drop every one it has. A failed refresh keeps the last good
		// list instead.
		slog.Warn("metrics: service discovery: list nodes", "error", err)
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := json.Marshal(build(dialable(nodes)))
	if err != nil {
		http.Error(w, "encode targets", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// dialable keeps the nodes that have a mgmt address, sorted by name so the
// answer is stable between refreshes.
func dialable(nodes []domain.Node) []domain.Node {
	out := make([]domain.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.MgmtAddr != "" {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func target(addr string, port int) string {
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

func wgfleetGroups(nodes []domain.Node, controllerAddr string) []SDGroup {
	var out []SDGroup
	if controllerAddr != "" {
		out = append(out, SDGroup{Targets: []string{controllerAddr}, Labels: map[string]string{"component": "controller"}})
	}
	for _, n := range nodes {
		// node/role only as __meta_ labels: the agent stamps both on its own series,
		// and a target label of the same name would rename them to exported_node.
		out = append(out, SDGroup{
			Targets: []string{target(n.MgmtAddr, config.DefaultAgentMetricsPort)},
			Labels: map[string]string{
				"component":           "agent",
				"__meta_wgfleet_node": n.Name,
				"__meta_wgfleet_role": string(n.Role),
			},
		})
	}
	return out
}

func nodeExporterGroups(nodes []domain.Node) []SDGroup {
	out := make([]SDGroup, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, SDGroup{
			Targets: []string{target(n.MgmtAddr, nodeexporter.Port)},
			Labels:  map[string]string{"node": n.Name, "role": string(n.Role)},
		})
	}
	return out
}

func blockyGroups(nodes []domain.Node, port func(string) int) []SDGroup {
	out := []SDGroup{}
	for _, n := range nodes {
		p := 0
		if port != nil {
			p = port(n.Name)
		}
		if p == 0 {
			continue
		}
		out = append(out, SDGroup{
			Targets: []string{target(n.MgmtAddr, p)},
			Labels:  map[string]string{"node": n.Name, "role": string(n.Role)},
		})
	}
	return out
}
