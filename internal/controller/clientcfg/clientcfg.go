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
	"net/netip"
	"slices"
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
	// LifelineExits names the exits the manifest gives a reserve client-facing
	// interface, in manifest order. The order is the operator's own and is what the
	// console lists, so a reserve door does not move around the page between loads.
	LifelineExits(ctx context.Context) ([]string, error)
	// ExitEndpointHost is the address a client dials for one exit's lifeline: the
	// same resolution the master↔exit tunnel uses, and "" when the fleet knows no
	// dialable address for it.
	ExitEndpointHost(ctx context.Context, exitID string) (string, error)
}

// ErrNotManaged reports that the master's client interface still belongs to
// wg-easy, so there is no config for the controller to render yet.
var ErrNotManaged = errors.New("this master's client interface is not managed by the agent yet")

// Result is a rendered config and the credential it belongs to.
type Result struct {
	Config string
	Client domain.WGClient
	Master domain.Node
	// Exit is the exit whose lifeline this config points at, and is set only by
	// BuildLifeline. Master stays filled in either way: a reserve config is still
	// one master's credential, and the caller reports it under that master.
	Exit domain.Node
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

// The reserve door.
//
// A lifeline is a second client-facing interface, carrying the same credentials
// on an EXIT instead of the master (see domain.LifelineSpec). It exists because
// the master is the fleet's one publicly-dialed address and therefore the most
// blockable thing we run: when it goes, every client goes with it, however
// healthy the exits are. So a reserve config is built here, beside the ordinary
// one, and from the same credential — a second builder would drift, and the day
// it drifted is the day nobody could reach the master to notice.
//
// What differs from Build is exactly what has to: the exit's own lifeline
// identity and endpoint, the address shifted into the lifeline pool, and a
// per-exit preshared key derived from the client's. Taking any of those from the
// master would render a config that looks right and never handshakes — or, for
// the PSK, would hand every exit the key that authenticates against the master's
// real client interface.

// Reasons a lifeline cannot hand out a config. They are the operator-facing text
// of a STANDING condition — something to go and fix — so they are named here once
// and shown on the page rather than only surfacing as a failed download.
const (
	// reasonNoLifeline also covers an agent too old to own one (wire < 11): the
	// controller drops the block in that case, so the spec simply has no lifeline
	// and there is nothing here to tell the two apart.
	reasonNoLifeline = "no lifeline on this exit"
	reasonNoKey      = "the exit has not published its lifeline key yet"
	reasonNoEndpoint = "no public endpoint known for this exit"
)

// LifelineExit is one exit's reserve door as the console sees it: whether a
// config can be handed out from it and, when it cannot, the single thing that is
// missing.
type LifelineExit struct {
	ID       string
	Name     string
	Endpoint string
	Ready    bool
	Reason   string
}

// ListLifelineExits reports every exit that carries a reserve interface, in
// manifest order, with its readiness.
//
// masterID names the master whose credentials these lifelines carry; it is
// deliberately NOT consulted. Readiness is a property of the exit alone, and it
// has to be: this listing is what an operator reaches for when the master is
// exactly the thing that is broken, and a check against the master would make the
// reserve path unavailable in precisely that case.
func ListLifelineExits(ctx context.Context, src Source, masterID string) ([]LifelineExit, error) {
	names, err := src.LifelineExits(ctx)
	if err != nil {
		return nil, fmt.Errorf("clientcfg: list the fleet's lifeline exits: %w", err)
	}
	out := make([]LifelineExit, 0, len(names))
	for _, name := range names {
		state, _, _, err := lifelineState(ctx, src, name)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	return out, nil
}

// lifelineState resolves one exit's reserve door once, returning both the
// console's view of it and the two pieces a build needs (the rendered lifeline
// spec and the exit's node record). Listing and building must agree on what
// "ready" means — a page saying "ready" over a download that refuses is the bug
// this single resolution exists to prevent.
//
// A node the store does not know is NOT an error: an exit declared in the
// manifest but never registered is an ordinary state (the console shows it as
// Pending), and failing the whole listing over one such exit would hide every
// other exit's reserve door.
func lifelineState(ctx context.Context, src Source, exitID string) (LifelineExit, *domain.LifelineSpec, domain.Node, error) {
	state := LifelineExit{ID: exitID, Name: exitID}
	spec, err := src.RenderNodeSpec(ctx, exitID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			state.Reason = reasonNoLifeline
			return state, nil, domain.Node{}, nil
		}
		return state, nil, domain.Node{}, fmt.Errorf("clientcfg: render the spec of exit %q: %w", exitID, err)
	}
	node, err := src.GetNode(ctx, exitID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return state, nil, domain.Node{}, fmt.Errorf("clientcfg: read exit %q: %w", exitID, err)
	}
	if node.Name != "" {
		state.Name = node.Name
	}
	if spec.Lifeline == nil {
		state.Reason = reasonNoLifeline
		return state, nil, node, nil
	}
	host, err := src.ExitEndpointHost(ctx, exitID)
	if err != nil {
		return state, nil, node, fmt.Errorf("clientcfg: resolve the endpoint of exit %q: %w", exitID, err)
	}
	if host != "" {
		state.Endpoint = net.JoinHostPort(host, strconv.Itoa(spec.Lifeline.ListenPort))
	}
	switch {
	case node.LifelinePublicKey == "":
		state.Reason = reasonNoKey
	case host == "":
		state.Reason = reasonNoEndpoint
	default:
		state.Ready = true
	}
	return state, spec.Lifeline, node, nil
}

// BuildLifeline renders one credential's RESERVE config: the same client, the
// same private key, pointed at one exit's lifeline instead of the master.
//
// The master is still read — its client pool is the base the lifeline address is
// shifted from, and its credentials are the population the lifeline carries — but
// its endpoint and its published interface key are deliberately not required. A
// master that has lost its public address, or never published a key, is a master
// whose clients need this config most.
func BuildLifeline(ctx context.Context, src Source, masterID, clientID, exitID string) (Result, error) {
	master, err := src.GetNode(ctx, masterID)
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

	// An exit that carries no lifeline at all is ErrNotFound, not a bespoke error:
	// the caller is a URL, and a stale link must land on the same 404 an unknown
	// credential gets rather than on a page explaining a feature this exit lacks.
	exits, err := src.LifelineExits(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("clientcfg: list the fleet's lifeline exits: %w", err)
	}
	if !slices.Contains(exits, exitID) {
		return Result{}, store.ErrNotFound
	}
	state, lifeline, exitNode, err := lifelineState(ctx, src, exitID)
	if err != nil {
		return Result{}, err
	}
	if !state.Ready {
		return Result{}, fmt.Errorf("clientcfg: no reserve config from exit %q: %s", exitID, state.Reason)
	}

	masterPool, err := netip.ParsePrefix(spec.Master.ClientWG.AddressPool)
	if err != nil {
		return Result{}, fmt.Errorf("clientcfg: master client pool %q: %w", spec.Master.ClientWG.AddressPool, err)
	}
	lifelinePool, err := netip.ParsePrefix(lifeline.AddressPool)
	if err != nil {
		return Result{}, fmt.Errorf("clientcfg: lifeline pool %q on exit %q: %w", lifeline.AddressPool, exitID, err)
	}

	clients, err := src.ListWGClients(ctx, masterID)
	if err != nil {
		return Result{}, err
	}
	for _, c := range clients {
		if c.ID != clientID {
			continue
		}
		// c is the range's own copy, so shifting it here cannot reach the store's
		// record — the master-side address and PSK must survive untouched.
		addr, aerr := domain.LifelineAddress(c.Address, masterPool, lifelinePool)
		if aerr != nil {
			return Result{}, fmt.Errorf("clientcfg: reserve address for %q: %w", c.Name, aerr)
		}
		psk, perr := domain.LifelinePSK(c.PresharedKey, exitID)
		if perr != nil {
			return Result{}, fmt.Errorf("clientcfg: reserve preshared key for %q: %w", c.Name, perr)
		}
		c.Address, c.PresharedKey = addr, psk
		cfg, rerr := wg.RenderClientConfig(wg.ClientConfigInput{
			Spec:            lifeline.ClientWGSpec,
			Client:          c,
			ServerPublicKey: exitNode.LifelinePublicKey,
			Endpoint:        state.Endpoint,
		})
		if rerr != nil {
			return Result{}, rerr
		}
		return Result{Config: cfg, Client: c, Master: master, Exit: exitNode}, nil
	}
	return Result{}, store.ErrNotFound
}

// LifelineFileName is the filename a downloaded RESERVE config is offered under.
// It carries the exit's name because a person may hold several — one per reserve
// door — and "laptop.conf" twice in a Downloads folder is how the wrong one gets
// imported on the day it matters.
func LifelineFileName(c domain.WGClient, exit string) string {
	return fmt.Sprintf("%s-%s.conf", c.Name, exit)
}
