package exit

import (
	"context"
	"os/exec"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// endpointLinePrefix is how wg.RenderInterface writes a peer endpoint.
const endpointLinePrefix = "Endpoint = "

// onlyEndpointsDiffer reports whether two rendered interface configs are the
// same once every Endpoint line is dropped — the case `awg set` can apply to a
// running interface without the `awg-quick down/up` that drops the tunnel.
func onlyEndpointsDiffer(current, desired string) bool {
	return current != "" && withoutEndpoints(current) == withoutEndpoints(desired)
}

func withoutEndpoints(cfg string) string {
	var b strings.Builder
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), endpointLinePrefix) {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// setMasterEndpoints sets the endpoint of every peer the controller gave one
// (exit-initiated AWG flow) whose live endpoint differs. live == nil sets them all.
// A peer without a spec endpoint is the master-dials case and is left alone: its
// endpoint is wherever the master last sent from.
func setMasterEndpoints(iface string, peers []domain.PeerSpec, live map[string]string, summary string) []reconcile.Action {
	var actions []reconcile.Action
	for _, p := range peers {
		if p.Endpoint == "" || (live != nil && live[p.PublicKey] == p.Endpoint) {
			continue
		}
		actions = append(actions, reconcile.ExecAction(summary,
			"awg", "set", iface, "peer", p.PublicKey, "endpoint", p.Endpoint))
	}
	return actions
}

// readLiveEndpoints asks the kernel which endpoint each awg0 peer holds now.
func readLiveEndpoints(iface string) (map[string]string, bool) {
	out, err := exec.CommandContext(context.Background(), "awg", "show", iface, "endpoints").Output()
	if err != nil {
		return nil, false
	}
	return wg.ParseShowEndpoints(string(out)), true
}

// reportedMasterEndpoint is the endpoint the kernel holds for the first peer the
// controller gave an endpoint to, or "" when none has one.
func reportedMasterEndpoint(peers []domain.PeerSpec, live map[string]string) string {
	for _, p := range peers {
		if p.Endpoint != "" {
			return live[p.PublicKey]
		}
	}
	return ""
}

// MasterEndpoint is what an exit reports as StatusReport.awg_master_endpoint: the
// endpoint awg0 holds right now for the master peer given one. Empty when no
// peer has a spec endpoint or the interface cannot be read. confPath is the
// interface's config (Paths.WGConf), which names the interface.
func MasterEndpoint(confPath string, peers []domain.PeerSpec) string {
	for _, p := range peers {
		if p.Endpoint != "" {
			live, ok := readLiveEndpoints(ifaceName(confPath))
			if !ok {
				return ""
			}
			return reportedMasterEndpoint(peers, live)
		}
	}
	return ""
}
