package clientcfg

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

type stubSource struct {
	nodes map[string]domain.Node
	spec  domain.NodeSpec
	// specs overrides spec per node, so a fixture can hold a master AND the exit
	// whose lifeline carries the master's clients.
	specs     map[string]domain.NodeSpec
	clients   map[string][]domain.WGClient
	listErr   error
	lifelines []string
	hosts     map[string]string
	// lifelineMaster is the one master whose clients the reserve interfaces carry.
	lifelineMaster string
	// checks is what each node last reported about itself; absent ⇒ never reported.
	checks map[string][]domain.HealthCheck
}

func (s stubSource) NodeChecks(_ context.Context, id string) ([]domain.HealthCheck, error) {
	return s.checks[id], nil
}

func (s stubSource) GetNode(_ context.Context, id string) (domain.Node, error) {
	n, ok := s.nodes[id]
	if !ok {
		return domain.Node{}, store.ErrNotFound
	}
	return n, nil
}

func (s stubSource) RenderNodeSpec(_ context.Context, id string) (domain.NodeSpec, error) {
	if sp, ok := s.specs[id]; ok {
		return sp, nil
	}
	return s.spec, nil
}

func (s stubSource) ListWGClients(_ context.Context, id string) ([]domain.WGClient, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.clients[id], nil
}

func (s stubSource) LifelineExits(context.Context) ([]string, error) {
	return s.lifelines, nil
}

func (s stubSource) LifelineMaster(context.Context) (string, error) {
	return s.lifelineMaster, nil
}

func (s stubSource) ExitEndpointHost(_ context.Context, exitID string) (string, error) {
	return s.hosts[exitID], nil
}

func managedSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{ClientWG: &domain.ClientWGSpec{
			ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1",
			MTU: 1360, DNS: []string{"10.80.0.1"}, AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
}

// testPSK is a valid base64 preshared key; the lifeline derives its own from it.
var testPSK = base64.StdEncoding.EncodeToString([]byte("preshared-key-00000000000000000."))

// lifelineKey is the exit's published lifeline interface key — a different
// identity from the master's, which is the whole point of the reserve door.
const lifelineKey = "ZXhpdC1saWZlbGluZS1rZXktMDAwMDAwMDAwMDAwMDA="

// lifelineSpec is an exit carrying a reserve client-facing interface for m1's
// clients: the same population, a shifted pool, its own port.
//
// Its DNS and AllowedIPs deliberately DIFFER from the master's: every
// interface-level line in a reserve config must come from the EXIT's spec, and
// identical fixtures would let a builder that rendered the master's spec pass this
// test unnoticed. The AllowedIPs here is the plain default route, which is what
// keybroker.lifelineSpec renders — a split list is the one shape wg-quick cannot
// install correctly, and the reserve profile is the one people import on an
// unfamiliar machine on a bad day.
func lifelineSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleExit,
		Lifeline: &domain.LifelineSpec{
			ClientWGSpec: domain.ClientWGSpec{
				ListenPort: 41827, AddressPool: "10.98.77.0/24", ServerAddress: "10.98.77.1",
				MTU: 1360, DNS: []string{"10.98.77.1"},
				AllowedIPs: []string{"0.0.0.0/0"},
			},
			Egress: domain.EgressDirect,
		},
	}
}

func source() stubSource {
	return stubSource{
		nodes: map[string]domain.Node{
			"m1": {
				ID: "m1", Name: "m1", Role: domain.RoleMaster, PublicIP: "203.0.113.1",
				ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
			},
			"e1": {
				ID: "e1", Name: "e1", Role: domain.RoleExit, PublicIP: "203.0.113.9",
				LifelinePublicKey: lifelineKey,
			},
		},
		spec:  managedSpec(),
		specs: map[string]domain.NodeSpec{"e1": lifelineSpec()},
		clients: map[string][]domain.WGClient{"m1": {
			{ID: "abc", Name: "laptop", Address: "10.80.0.2/32",
				PublicKey: "pub", PrivateKey: "Y2xpZW50LWtleQ==", PresharedKey: testPSK, Enabled: true},
		}},
		lifelines:      []string{"e1"},
		lifelineMaster: "m1",
		hosts:          map[string]string{"e1": "203.0.113.9"},
	}
}

func TestBuild(t *testing.T) {
	res, err := Build(context.Background(), source(), "m1", "abc")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if res.Client.Name != "laptop" || res.Master.ID != "m1" {
		t.Fatalf("result = %+v", res)
	}
	// PersistentKeepalive is asserted by presence, not value: it is derived per
	// credential rather than fixed at 25, so the fleet no longer shares one beacon.
	for _, want := range []string{"PrivateKey = Y2xpZW50LWtleQ==", "Endpoint = 203.0.113.1:443", "PersistentKeepalive = "} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("config missing %q:\n%s", want, res.Config)
		}
	}
	if got := ConfigFileName(res.Client); got != "laptop.conf" {
		t.Errorf("ConfigFileName() = %q", got)
	}
}

func TestBuildFailures(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*stubSource)
		master  string
		client  string
		wantErr string
	}{
		"unknown master": {master: "nope", client: "abc", wantErr: "not found"},
		"unknown client": {master: "m1", client: "zzz", wantErr: "not found"},
		"master has no client interface": {
			mutate:  func(s *stubSource) { s.spec = domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}} },
			master:  "m1",
			client:  "abc",
			wantErr: "has no client interface",
		},
		"key not published yet": {
			mutate: func(s *stubSource) {
				n := s.nodes["m1"]
				n.ClientWGPublicKey = ""
				s.nodes["m1"] = n
			},
			master: "m1", client: "abc", wantErr: "has not published",
		},
		"no endpoint": {
			mutate: func(s *stubSource) {
				n := s.nodes["m1"]
				n.PublicIP = ""
				s.nodes["m1"] = n
			},
			master: "m1", client: "abc", wantErr: "no public endpoint",
		},
		"store unavailable": {
			mutate: func(s *stubSource) { s.listErr = errors.New("store is down") },
			master: "m1", client: "abc", wantErr: "store is down",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			src := source()
			if tc.mutate != nil {
				tc.mutate(&src)
			}
			_, err := Build(context.Background(), src, tc.master, tc.client)
			if err == nil {
				t.Fatalf("Build() = nil error, want one mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Build() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestFindByID(t *testing.T) {
	src := source()
	src.clients["m2"] = []domain.WGClient{{ID: "def", Name: "phone"}}

	got, err := FindByID(context.Background(), src, []string{"m2", "m1"}, "abc")
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if got != "m1" {
		t.Fatalf("FindByID() = %q, want m1", got)
	}
	if _, err := FindByID(context.Background(), src, []string{"m1", "m2"}, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByID() for an unknown token = %v, want ErrNotFound", err)
	}
}

// The endpoint falls back through the sources in the order an operator would
// expect: the address the manifest declares (carried in the spec) first, then
// whatever the store registered, and never the address we provisioned through.
// The declared address wins because a master that moves is an ordinary event and
// the store row is never refreshed — see EndpointHost.
func TestEndpointHostFallback(t *testing.T) {
	spec := managedSpec()
	spec.Master.Compose.PublicIP = "198.51.100.4"
	node := domain.Node{PublicIP: "203.0.113.1", SSH: domain.SSHTarget{Host: "192.0.2.9"}}

	if got := EndpointHost(node, spec); got != "198.51.100.4" {
		t.Errorf("EndpointHost() = %q, want the declared public IP", got)
	}
	spec.Master.Compose.PublicIP = ""
	if got := EndpointHost(node, spec); got != "203.0.113.1" {
		t.Errorf("EndpointHost() = %q, want the registered public IP", got)
	}
	spec.Master.Compose.PublicIP = "198.51.100.4"
	node.PublicIP = ""
	if got := EndpointHost(node, spec); got != "198.51.100.4" {
		t.Errorf("EndpointHost() = %q, want the manifest's public IP", got)
	}
	// The SSH host is deliberately NOT a fallback: it is often the management
	// overlay, and a client profile must never point end users there.
	spec.Master.Compose.PublicIP = ""
	node.PublicIP = ""
	if got := EndpointHost(node, spec); got != "" {
		t.Errorf("EndpointHost() = %q, want empty — the SSH host must not reach a client config", got)
	}
}

// A reserve config is the master's credential rendered against a different door:
// the client's own private key, but the exit's lifeline identity, the shifted
// address, the per-exit preshared key and the exit's endpoint. Getting any one of
// those from the master would produce a config that looks right and never
// completes a handshake — or, worse, hands the exit the master's real PSK.
func TestBuildLifeline(t *testing.T) {
	res, err := BuildLifeline(context.Background(), source(), "m1", "abc", "e1")
	if err != nil {
		t.Fatalf("BuildLifeline() error = %v", err)
	}
	wantPSK, err := domain.LifelinePSK(testPSK, "e1")
	if err != nil {
		t.Fatalf("LifelinePSK() error = %v", err)
	}
	for _, want := range []string{
		"PrivateKey = Y2xpZW50LWtleQ==",
		"Address = 10.98.77.2/32",
		"PublicKey = " + lifelineKey,
		"PresharedKey = " + wantPSK,
		"Endpoint = 203.0.113.9:41827",
		"DNS = 10.98.77.1",
		// Everything into the tunnel, whatever the master's own configs route. A split
		// list is the one shape wg-quick cannot install correctly, and a reserve
		// profile is the one people import on an unfamiliar machine on a bad day.
		"AllowedIPs = 0.0.0.0/0",
	} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("config missing %q:\n%s", want, res.Config)
		}
	}
	// Nothing of the master's own door may leak into the reserve config — not its
	// endpoint, its pool address, its real preshared key or its interface key, and
	// not its interface-level settings either (resolver, routed prefixes).
	for _, unwanted := range []string{"203.0.113.1:443", "10.80.0.2/32", testPSK,
		"c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=", "10.80.0.1", "AllowedIPs = 0.0.0.0/1"} {
		if strings.Contains(res.Config, unwanted) {
			t.Errorf("config carries the master's %q:\n%s", unwanted, res.Config)
		}
	}
	if res.Master.ID != "m1" || res.Exit.ID != "e1" {
		t.Errorf("result master = %q, exit = %q; want m1 / e1", res.Master.ID, res.Exit.ID)
	}
	if res.Client.Address != "10.98.77.2/32" {
		t.Errorf("result client address = %q, want the lifeline one", res.Client.Address)
	}
	if got := LifelineFileName(res.Client, "e1"); got != "laptop-e1.conf" {
		t.Errorf("LifelineFileName() = %q, want laptop-e1.conf", got)
	}
}

// A switched-off credential still renders. Gating on Enabled is the caller's job
// (the console does it), and it is the same rule Build already follows — a person
// whose profile is muted must not get a download that silently differs.
func TestBuildLifelineDisabledClientStillRenders(t *testing.T) {
	src := source()
	c := src.clients["m1"][0]
	c.Enabled = false
	src.clients["m1"] = []domain.WGClient{c}

	if _, err := BuildLifeline(context.Background(), src, "m1", "abc", "e1"); err != nil {
		t.Fatalf("BuildLifeline() for a disabled credential = %v, want a config", err)
	}
}

func TestBuildLifelineFailures(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*stubSource)
		exit    string
		client  string
		wantErr string
	}{
		"unknown exit":   {exit: "nope", client: "abc", wantErr: "not found"},
		"unknown client": {exit: "e1", client: "zzz", wantErr: "not found"},
		"master has no client interface": {
			mutate:  func(s *stubSource) { s.spec = domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}} },
			exit:    "e1",
			client:  "abc",
			wantErr: "has no client interface",
		},
		"exit carries no lifeline": {
			mutate:  func(s *stubSource) { s.specs["e1"] = domain.NodeSpec{Role: domain.RoleExit} },
			exit:    "e1",
			client:  "abc",
			wantErr: "no lifeline on this exit",
		},
		"lifeline key not published yet": {
			mutate: func(s *stubSource) {
				n := s.nodes["e1"]
				n.LifelinePublicKey = ""
				s.nodes["e1"] = n
			},
			exit: "e1", client: "abc", wantErr: "has not published its lifeline key yet",
		},
		"no endpoint for the exit": {
			mutate:  func(s *stubSource) { s.hosts = map[string]string{} },
			exit:    "e1",
			client:  "abc",
			wantErr: "no public endpoint known for this exit",
		},
		"credential outside the master pool": {
			mutate: func(s *stubSource) {
				c := s.clients["m1"][0]
				c.Address = "10.81.0.2/32"
				s.clients["m1"] = []domain.WGClient{c}
			},
			exit: "e1", client: "abc", wantErr: "outside the master pool",
		},
		"store unavailable": {
			mutate: func(s *stubSource) { s.listErr = errors.New("store is down") },
			exit:   "e1", client: "abc", wantErr: "store is down",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			src := source()
			if tc.mutate != nil {
				tc.mutate(&src)
			}
			_, err := BuildLifeline(context.Background(), src, "m1", tc.client, tc.exit)
			if err == nil {
				t.Fatalf("BuildLifeline() = nil error, want one mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildLifeline() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// An exit that is not a lifeline exit at all is ErrNotFound, not a bespoke error:
// the caller (a URL someone typed or an old link) must get the same 404 an unknown
// credential gets.
func TestBuildLifelineUnknownExitIsNotFound(t *testing.T) {
	_, err := BuildLifeline(context.Background(), source(), "m1", "abc", "e9")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BuildLifeline() for an unknown exit = %v, want ErrNotFound", err)
	}
}

// The listing says, per exit, whether a reserve config can be handed out and — when
// it cannot — the one thing the operator has to fix. Every not-ready reason is a
// standing condition, so it belongs on the page rather than behind a failed download.
func TestListLifelineExits(t *testing.T) {
	src := source()
	src.lifelines = []string{"e1", "e2", "e3", "e4"}
	src.hosts["e2"] = "203.0.113.10"
	src.hosts["e3"] = "203.0.113.11"
	src.specs["e2"] = domain.NodeSpec{Role: domain.RoleExit} // no lifeline rendered
	src.specs["e3"] = lifelineSpec()
	src.specs["e4"] = lifelineSpec()
	src.nodes["e2"] = domain.Node{ID: "e2", Name: "e2", Role: domain.RoleExit}
	src.nodes["e3"] = domain.Node{ID: "e3", Name: "e3", Role: domain.RoleExit} // no key published
	src.nodes["e4"] = domain.Node{ID: "e4", Name: "e4", Role: domain.RoleExit, LifelinePublicKey: lifelineKey}

	got, err := ListLifelineExits(context.Background(), src, "m1")
	if err != nil {
		t.Fatalf("ListLifelineExits() error = %v", err)
	}
	want := []LifelineExit{
		{ID: "e1", Name: "e1", Endpoint: "203.0.113.9:41827", Ready: true},
		{ID: "e2", Name: "e2", Reason: "no lifeline on this exit"},
		{ID: "e3", Name: "e3", Endpoint: "203.0.113.11:41827", Reason: "the exit has not published its lifeline key yet"},
		{ID: "e4", Name: "e4", Reason: "no public endpoint known for this exit"},
	}
	if len(got) != len(want) {
		t.Fatalf("ListLifelineExits() = %+v, want %d entries", got, len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("exit %d = %+v, want %+v", i, got[i], w)
		}
	}
}

// A door the exit itself says is broken must not be offered. The two facts the
// listing used to rely on are both one-way — a lifeline key is published once at
// the first successful render and never withdrawn — so an exit whose agent has
// been refusing to apply its reserve spec for a week went on showing a download
// and a QR, and the person walked away with a profile that cannot connect.
func TestListLifelineExitsHidesAnExitThatReportsItsReserveInterfaceDown(t *testing.T) {
	src := source()
	src.checks = map[string][]domain.HealthCheck{
		"e1": {{Name: "lifeline", OK: false, Detail: "the agent is not applying the lifeline spec: AmneziaWG 3.x refused"}},
	}
	exits, err := ListLifelineExits(context.Background(), src, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if len(exits) != 1 {
		t.Fatalf("got %d exits, want 1: %+v", len(exits), exits)
	}
	if exits[0].Ready {
		t.Fatalf("an exit reporting its reserve interface down must not be offered: %+v", exits[0])
	}
	if !strings.Contains(exits[0].Reason, "AmneziaWG 3.x refused") {
		t.Errorf("the exit's own reason must reach the page, got %q", exits[0].Reason)
	}
}

// And the download must refuse for the same reason, rather than handing out a
// config the page has just declined to advertise.
func TestBuildLifelineRefusesAnExitThatReportsItsReserveInterfaceDown(t *testing.T) {
	src := source()
	src.checks = map[string][]domain.HealthCheck{
		"e1": {{Name: "lifeline", OK: false}},
	}
	if _, err := BuildLifeline(context.Background(), src, "m1", "abc", "e1"); err == nil {
		t.Fatal("a reserve config was handed out for an exit whose interface is reported down")
	}
}

// A passing check changes nothing, and neither does a node that has never
// reported: readiness must not collapse because a status row is missing.
func TestListLifelineExitsIgnoresAHealthyOrSilentNode(t *testing.T) {
	for name, checks := range map[string][]domain.HealthCheck{
		"healthy":             {{Name: "lifeline", OK: true}},
		"never reported":      nil,
		"other check failing": {{Name: "warp-egress", OK: false, Detail: "warp is down"}},
	} {
		src := source()
		if checks != nil {
			src.checks = map[string][]domain.HealthCheck{"e1": checks}
		}
		exits, err := ListLifelineExits(context.Background(), src, "m1")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !exits[0].Ready {
			t.Errorf("%s: the door must stay open, got reason %q", name, exits[0].Reason)
		}
	}
}

// sourceWithSecondMaster is source() plus a second master m2 with its own client.
func sourceWithSecondMaster(t *testing.T) stubSource {
	t.Helper()
	src := source()
	nodes := map[string]domain.Node{}
	for id, n := range src.nodes {
		nodes[id] = n
	}
	nodes["m2"] = domain.Node{
		ID: "m2", Name: "m2", Role: domain.RoleMaster, PublicIP: "203.0.113.2",
		ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
	}
	clients := map[string][]domain.WGClient{}
	for id, cs := range src.clients {
		clients[id] = cs
	}
	clients["m2"] = []domain.WGClient{
		{ID: "xyz", Name: "tablet", Address: "10.80.0.2/32",
			PublicKey: "pub2", PrivateKey: "Y2xpZW50LWtleQ==", PresharedKey: testPSK, Enabled: true},
	}
	src.nodes, src.clients = nodes, clients
	return src
}

// Review Focus 6. A reserve interface carries the base master's clients. A
// device whose credential lives on another master must not be offered — or
// handed — a config the exit has no peer for: it would import cleanly and never
// connect.
func TestLifelineIsNotOfferedForANonBaseMaster(t *testing.T) {
	src := sourceWithSecondMaster(t)
	ctx := context.Background()

	if ok, err := LifelineCarries(ctx, src, "m2"); err != nil || ok {
		t.Errorf("LifelineCarries(m2) = %v, %v; want false", ok, err)
	}
	if exits, err := ListLifelineExits(ctx, src, "m2"); err != nil || len(exits) != 0 {
		t.Errorf("reserve exits for a non-base master = %v, %v; want none", exits, err)
	}
	if _, err := BuildLifeline(ctx, src, "m2", "xyz", "e1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reserve config for a non-base master's credential: err = %v, want ErrNotFound", err)
	}
	if exits, err := ListLifelineExits(ctx, src, "m1"); err != nil || len(exits) == 0 {
		t.Errorf("the base master's reserve exits disappeared: %v, %v", exits, err)
	}
}

// With no base master there is nobody the lifeline carries.
func TestLifelineCarriesNobodyWithoutABaseMaster(t *testing.T) {
	src := source()
	src.lifelineMaster = ""
	if ok, err := LifelineCarries(context.Background(), src, "m1"); err != nil || ok {
		t.Errorf("LifelineCarries = %v, %v; want false", ok, err)
	}
}
