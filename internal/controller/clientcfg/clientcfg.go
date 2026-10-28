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
	// LifelineMaster names the one master whose credentials the fleet's reserve
	// interfaces carry; "" when there is none. A reserve config is only ever built
	// for that master's credentials.
	LifelineMaster(ctx context.Context) (string, error)
	// ExitEndpointHost is the address a client dials for one exit's lifeline: the
	// same resolution the master↔exit tunnel uses, and "" when the fleet knows no
	// dialable address for it.
	ExitEndpointHost(ctx context.Context, exitID string) (string, error)
	// NodeChecks returns what the NODE last said about itself. A door is offered on
	// the strength of two controller-side facts — a published key and a known
	// address — and both of them are one-way: the key is published once at the first
	// successful render and never withdrawn. So without this, an exit whose agent has
	// been refusing to apply its reserve spec for a week still shows a download and a
	// QR, and the person walks away with a profile that cannot connect. It is nil,
	// not an error, for a node that has never reported.
	NodeChecks(ctx context.Context, nodeID string) ([]domain.HealthCheck, error)
}

// ErrNotReady marks a master that cannot hand out a config YET — no published
// interface key, no known endpoint, no client interface spec. It is ours, not the
// caller's: the portal answers "try later" (503), never "your link is dead", and
// a device profile skips that master instead of failing whole.
var ErrNotReady = errors.New("clientcfg: master not ready")

// notReady keeps each operator-facing sentence as it was while making it match
// ErrNotReady under errors.Is.
type notReady string

func (e notReady) Error() string        { return string(e) }
func (e notReady) Is(target error) bool { return target == ErrNotReady }

// ErrNotManaged reports that the master's spec carries no client interface yet
// (nil MasterSpec.ClientWG), so there is no config for the controller to render.
var ErrNotManaged error = notReady("this master has no client interface (client_awg.address_pool is not set)")

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

// BuildInput resolves everything one credential's config is rendered FROM, without
// rendering it: the .conf and the mihomo profile both consume this, so neither
// renders the other's format just to throw it away.
func BuildInput(ctx context.Context, src Source, masterID, clientID string) (wg.ClientConfigInput, domain.Node, error) {
	node, err := src.GetNode(ctx, masterID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// A master missing from the store is not-ready, not absent: node deletion
		// cascades a device's credentials, so a credential can only ever name a
		// master that once existed here — this is a store race or a not-yet-applied
		// registration, not evidence the credential itself is gone. wgFor still asks
		// whether THIS credential is enabled before settling on not-ready vs. paused.
		return wg.ClientConfigInput{}, domain.Node{}, notReady("this master was not found in the store yet")
	case err != nil:
		return wg.ClientConfigInput{}, domain.Node{}, err
	}
	spec, err := src.RenderNodeSpec(ctx, masterID)
	if err != nil {
		return wg.ClientConfigInput{}, domain.Node{}, err
	}
	if spec.Master == nil || spec.Master.ClientWG == nil {
		return wg.ClientConfigInput{}, domain.Node{}, ErrNotManaged
	}
	if node.ClientWGPublicKey == "" {
		return wg.ClientConfigInput{}, domain.Node{}, notReady("the master has not published its client interface key yet")
	}
	host := EndpointHost(node, spec)
	if host == "" {
		return wg.ClientConfigInput{}, domain.Node{}, notReady("no public endpoint known for this master")
	}
	c, err := findClient(ctx, src, masterID, clientID)
	if err != nil {
		return wg.ClientConfigInput{}, domain.Node{}, err
	}
	return wg.ClientConfigInput{
		Spec:            *spec.Master.ClientWG,
		Client:          c,
		ServerPublicKey: node.ClientWGPublicKey,
		Endpoint:        net.JoinHostPort(host, strconv.Itoa(spec.Master.ClientWG.ListenPort)),
	}, node, nil
}

// Build renders the config for one credential on one master. Lookup is by
// credential ID, which is also what the portal uses as its token — the ID is
// random and stable, so a link keeps working across renames.
func Build(ctx context.Context, src Source, masterID, clientID string) (Result, error) {
	in, node, err := BuildInput(ctx, src, masterID, clientID)
	if err != nil {
		return Result{}, err
	}
	cfg, err := wg.RenderClientConfig(in)
	if err != nil {
		return Result{}, err
	}
	return Result{Config: cfg, Client: in.Client, Master: node}, nil
}

// findClient resolves one credential on one master, or store.ErrNotFound.
//
// Both builders go through here so "which credential is this token" has exactly
// one answer. The two used to carry their own copy of the loop, and the copies
// would have had to be corrected together — a lookup that started, say, matching
// on name in one of them is how a reserve link would quietly resolve to a
// different person's credential than the main link with the same token.
//
// A store failure is returned as-is, not folded into ErrNotFound: the portal
// renders ErrNotFound as "this link no longer works" AND charges a rate-limit
// failure, so a busy SQLite must not tell every legitimate user their access was
// revoked (see FindByID).
func findClient(ctx context.Context, src Source, masterID, clientID string) (domain.WGClient, error) {
	clients, err := src.ListWGClients(ctx, masterID)
	if err != nil {
		return domain.WGClient{}, err
	}
	for _, c := range clients {
		if c.ID == clientID {
			return c, nil
		}
	}
	return domain.WGClient{}, store.ErrNotFound
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
	// reasonUnhealthy is the fallback wording when the exit reports its reserve
	// interface is not up but says nothing about why.
	reasonUnhealthy = "the exit reports its reserve interface is not up"
)

// lifelineCheck is the name of the node-side health check that watches the reserve
// interface. It reads the planner's own recorded reason first and the state of the
// world second, which is the only thing that can tell "up and current" apart from
// "up on a week-old config" — see the agent's lifeline probe.
const lifelineCheck = "lifeline"

// lifelineUnhealthy returns the exit's own complaint about its reserve interface,
// or "" when it is not complaining.
//
// A node that has never reported, or a store that cannot be read, is NOT a
// complaint: readiness must not collapse because a status row is missing. The
// check is a veto on a door we would otherwise offer, not the thing that opens it.
func lifelineUnhealthy(ctx context.Context, src Source, exitID string) string {
	checks, err := src.NodeChecks(ctx, exitID)
	if err != nil {
		return ""
	}
	for _, c := range checks {
		if c.Name != lifelineCheck || c.OK {
			continue
		}
		if c.Detail != "" {
			return c.Detail
		}
		return reasonUnhealthy
	}
	return ""
}

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

// LifelineCarries reports whether masterID's clients are on the fleet's reserve
// interfaces at all. It is a fact about the manifest, not about any exit's
// health: a caller uses it to tell "the fleet has no reserve for you" from "you
// asked for an exit that does not exist".
func LifelineCarries(ctx context.Context, src Source, masterID string) (bool, error) {
	carried, err := src.LifelineMaster(ctx)
	if err != nil {
		return false, fmt.Errorf("clientcfg: resolve the lifeline's master: %w", err)
	}
	return carried != "" && carried == masterID, nil
}

// ListLifelineExits reports every exit that carries a reserve interface, in
// manifest order, with its readiness.
//
// masterID is consulted for one thing only: whether the reserve interfaces carry
// its clients at all (LifelineCarries) — for any other master the list is empty.
// Readiness is a property of the exit alone, and it has to be: this listing is
// what an operator reaches for when the master is exactly the thing that is
// broken, and a check against the master's health would make the reserve path
// unavailable in precisely that case.
func ListLifelineExits(ctx context.Context, src Source, masterID string) ([]LifelineExit, error) {
	if ok, err := LifelineCarries(ctx, src, masterID); err != nil || !ok {
		return nil, err
	}
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
	switch unhealthy := lifelineUnhealthy(ctx, src, exitID); {
	case node.LifelinePublicKey == "":
		state.Reason = reasonNoKey
	case host == "":
		state.Reason = reasonNoEndpoint
	case unhealthy != "":
		// Last, because the two above are "this door was never built" and this one is
		// "it was, and it is stuck" — which is the more useful thing to read when both
		// could be said.
		state.Reason = unhealthy
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
	if ok, err := LifelineCarries(ctx, src, masterID); err != nil {
		return Result{}, err
	} else if !ok {
		// Same answer an unknown credential gets: the caller is a URL.
		return Result{}, store.ErrNotFound
	}
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

	c, err := findClient(ctx, src, masterID, clientID)
	if err != nil {
		return Result{}, err
	}
	// c is this function's own copy, so shifting it here cannot reach the store's
	// record — the master-side address and PSK must survive untouched.
	addr, err := domain.LifelineAddress(c.Address, masterPool, lifelinePool)
	if err != nil {
		return Result{}, fmt.Errorf("clientcfg: reserve address for %q: %w", c.Name, err)
	}
	psk, err := domain.LifelinePSK(c.PresharedKey, exitID)
	if err != nil {
		return Result{}, fmt.Errorf("clientcfg: reserve preshared key for %q: %w", c.Name, err)
	}
	c.Address, c.PresharedKey = addr, psk
	cfg, err := wg.RenderClientConfig(wg.ClientConfigInput{
		Spec:            lifeline.ClientWGSpec,
		Client:          c,
		ServerPublicKey: exitNode.LifelinePublicKey,
		Endpoint:        state.Endpoint,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Config: cfg, Client: c, Master: master, Exit: exitNode}, nil
}

// LifelineFileName is the filename a downloaded RESERVE config is offered under.
// It carries the exit's name because a person may hold several — one per reserve
// door — and "laptop.conf" twice in a Downloads folder is how the wrong one gets
// imported on the day it matters.
func LifelineFileName(c domain.WGClient, exit string) string {
	return fmt.Sprintf("%s-%s.conf", c.Name, exit)
}
