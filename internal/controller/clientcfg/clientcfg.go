// Package clientcfg builds one end user's WireGuard configuration from the
// controller's own state.
//
// It exists so the operator UI and the self-service portal cannot drift apart.
// Two code paths rendering "the same" config is exactly how a client ends up with
// a working QR and a broken download, and the difference would only surface on
// someone else's phone.
package clientcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Source is what building a config needs: the node record (for the endpoint and
// the published interface key), the rendered spec (for the interface itself) and
// the issued credentials.
type Source interface {
	GetNode(ctx context.Context, id string) (domain.Node, error)
	RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error)
	ListWGClients(ctx context.Context, masterID string) ([]domain.WGClient, error)
}

// ErrNotManaged reports that the master's client interface still belongs to
// wg-easy, so there is no config for the controller to render yet.
var ErrNotManaged = errors.New("this master's client interface is not managed by the agent yet")

// Result is a rendered config and the credential it belongs to.
type Result struct {
	Config string
	Client domain.WGClient
	Master domain.Node
}

// Build renders the config for one credential on one master. Lookup is by
// credential ID, which is also what the portal uses as its token — the ID is
// random and stable, so a link keeps working across renames.
func Build(ctx context.Context, src Source, masterID, clientID string) (Result, error) {
	node, err := src.GetNode(ctx, masterID)
	if err != nil {
		return Result{}, err
	}
	spec, err := src.RenderNodeSpec(ctx, masterID)
	if err != nil {
		return Result{}, err
	}
	if spec.Master == nil || spec.Master.ClientWG == nil {
		return Result{}, ErrNotManaged
	}
	if node.ClientWGPublicKey == "" {
		return Result{}, errors.New("the master has not published its client interface key yet")
	}
	host := EndpointHost(node, spec)
	if host == "" {
		return Result{}, errors.New("no public endpoint known for this master")
	}

	clients, err := src.ListWGClients(ctx, masterID)
	if err != nil {
		return Result{}, err
	}
	for _, c := range clients {
		if c.ID != clientID {
			continue
		}
		cfg, rerr := wg.RenderClientConfig(wg.ClientConfigInput{
			Spec:            *spec.Master.ClientWG,
			Client:          c,
			ServerPublicKey: node.ClientWGPublicKey,
			Endpoint:        net.JoinHostPort(host, strconv.Itoa(spec.Master.ClientWG.ListenPort)),
		})
		if rerr != nil {
			return Result{}, rerr
		}
		return Result{Config: cfg, Client: c, Master: node}, nil
	}
	return Result{}, store.ErrNotFound
}

// FindByID locates a credential across every master, returning the master it
// belongs to. The portal needs it because a client's link carries only the
// credential token — asking someone to also know which gateway issued it would
// defeat the point of a self-service link.
// A store failure is reported, not swallowed. Skipping the master that failed
// and carrying on ends in ErrNotFound — which the portal renders as "this link is
// no longer working, your profile may have been replaced or switched off" AND
// charges the caller a rate-limit failure. During a store hiccup that tells every
// legitimate user their access was revoked, and locks out the ones who reload.
func FindByID(ctx context.Context, src Source, masters []string, clientID string) (string, error) {
	for _, m := range masters {
		clients, err := src.ListWGClients(ctx, m)
		if err != nil {
			return "", fmt.Errorf("clientcfg: list credentials of %q: %w", m, err)
		}
		for _, c := range clients {
			if c.ID == clientID {
				return m, nil
			}
		}
	}
	return "", store.ErrNotFound
}

// EndpointHost resolves the address clients dial: the spec's public IP — which
// the controller already resolved as manifest-then-store, and which may be a DNS
// name — else the node's registered one. The fallback covers both a spec with no
// master section and, the case that actually happens, a master section whose own
// resolution came up empty.
//
// The spec comes first because the manifest is where this address is DECLARED and
// the store row is a copy taken at provisioning time that only another provisioning
// run refreshes. Reading the store first meant a master that changed address kept
// handing out profiles pointing at the old one.
//
// It deliberately does NOT fall back to the SSH host. That address is often the
// management overlay (the documented workaround when direct SSH is black-holed),
// and shipping it in a client profile would send end users at an overlay address.
// It also has to agree with the operator page's own readiness check, which uses
// the same two sources — a third fallback here meant the page said "no endpoint"
// while the download quietly produced one.
func EndpointHost(node domain.Node, spec domain.NodeSpec) string {
	if spec.Master != nil && spec.Master.Compose.PublicIP != "" {
		return spec.Master.Compose.PublicIP
	}
	return node.PublicIP
}

// ConfigFileName is the filename a downloaded config is offered under.
func ConfigFileName(c domain.WGClient) string { return fmt.Sprintf("%s.conf", c.Name) }
