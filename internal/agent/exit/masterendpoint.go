package exit

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"time"

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
		if p.Endpoint == "" || (live != nil && sameEndpoint(live[p.PublicKey], p.Endpoint)) {
			continue
		}
		actions = append(actions, reconcile.ExecAction(summary,
			"awg", "set", iface, "peer", p.PublicKey, "endpoint", p.Endpoint))
	}
	return actions
}

// sameEndpoint compares two "ip:port" endpoints by value, so a formatting
// difference in `awg show` output never reads as a roamed endpoint.
func sameEndpoint(a, b string) bool {
	pa, errA := netip.ParseAddrPort(a)
	pb, errB := netip.ParseAddrPort(b)
	if errA != nil || errB != nil {
		return a == b && a != ""
	}
	return pa.Addr().Unmap() == pb.Addr().Unmap() && pa.Port() == pb.Port()
}

// awgShowTimeout bounds one `awg show` so a wedged netlink call cannot hold the
// reconcile pass.
const awgShowTimeout = 5 * time.Second

// readLiveEndpoints asks the kernel which endpoint each awg0 peer holds now.
func readLiveEndpoints(iface string) (map[string]string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), awgShowTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "awg", "show", iface, "endpoints").Output()
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
// endpoint awg0 holds right now for the master peer given one, "" when no peer
// has a spec endpoint. ok=false means the interface could not be read — the
// caller keeps the value it reported last rather than sending an empty one,
// because the master's gate is armed from it. confPath is the interface's
// config (Paths.WGConf), which names the interface.
func MasterEndpoint(confPath string, peers []domain.PeerSpec) (string, bool) {
	return masterEndpointFrom(peers, readLiveEndpoints, ifaceName(confPath))
}

func masterEndpointFrom(peers []domain.PeerSpec, read func(string) (map[string]string, bool), iface string) (string, bool) {
	for _, p := range peers {
		if p.Endpoint != "" {
			live, ok := read(iface)
			if !ok {
				return "", false
			}
			return reportedMasterEndpoint(peers, live), true
		}
	}
	return "", true
}
