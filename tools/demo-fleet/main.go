// Command demo-fleet seeds a controller work directory with a FICTIONAL fleet so
// the web console can be screenshotted for documentation without any real
// infrastructure. It writes a manifest, creates the fleet CA, and fills the
// controller's SQLite store with nodes, status reports, keys, client credentials
// and an admin login — everything an agent would otherwise report over gRPC.
//
// Every name and address is invented: mgmt addresses are in 10.20.0.0/16 and
// public/egress addresses come from the RFC 5737 documentation blocks.
//
// Usage:
//
//	go run ./tools/demo-fleet -dir /tmp/demo-fleet [-agent-bin bin/wgfleet-agent] [-keep]
//	bin/wgfleet-controller --config /tmp/demo-fleet/controller.yaml
//
// The console then serves at http://127.0.0.1:9000 (login demo / demo). With
// -keep the seeder stays up and re-records every status every -interval so
// "seen"/"handshake" ages on the pages stay seconds old while you screenshot.
// Development tool only: it is not part of the release archive.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/keybroker"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/controller/web/auth"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

const (
	agentVersion  = "v0.2.4"
	adminUser     = "demo"
	adminPassword = "demo"
	masterName    = "master-1"
	masterMgmt    = "10.20.0.1"
	masterPublic  = "198.51.100.10"
	clientPool    = "10.80.0.0/24"
	portalURL     = "https://vpn.example.org"
)

// devices are the client devices the console lists: every AWG credential becomes
// one on adoption, exactly as on a real upgrade; vless names the VLESS credential
// attached to it, and a device with no AWG credential is created from scratch.
var devices = []struct{ name, vless string }{
	{name: "alice-phone", vless: "alice-phone"},
	{name: "erin-macbook", vless: "erin-macbook"},
}

// exit is one fictional exit node and the way it should look on the console.
type exit struct {
	name, region, mgmt, public, warpIP string
	pool                               string
	delay                              time.Duration
	carrying                           bool // Selected in the master's mihomo view
	lowThroughput                      bool // egress-throughput check failing → Degraded, auto-suspended
	drained                            bool // console drain flag
	// heldFor, reachable and probed are the MASTER's verdict on the tunnel to this
	// exit: how long its multi-destination probe has been holding the exit out of
	// the load balancer, and what the last pass reached. Zero heldFor with probed
	// > 0 is the other case the console renders — a reserve-tier member the warm
	// probe sampled — and zero probed is "never sampled", which draws no badge.
	heldFor           time.Duration
	reachable, probed int
}

var exits = []exit{
	{name: "exit-de-1", region: "de", mgmt: "10.20.0.11", public: "203.0.113.11", warpIP: "192.0.2.41", pool: "10.81.1.0/24", delay: 48 * time.Millisecond, carrying: true},
	{name: "exit-nl-1", region: "nl", mgmt: "10.20.0.12", public: "203.0.113.12", warpIP: "192.0.2.57", pool: "10.81.2.0/24", delay: 52 * time.Millisecond, carrying: true},
	{name: "exit-fi-1", region: "fi", mgmt: "10.20.0.13", public: "203.0.113.13", warpIP: "192.0.2.73", pool: "10.81.3.0/24", delay: 31 * time.Millisecond, carrying: true},
	{name: "exit-fr-1", region: "fr", mgmt: "10.20.0.14", public: "203.0.113.14", warpIP: "192.0.2.88", pool: "10.81.4.0/24", delay: 61 * time.Millisecond, lowThroughput: true, heldFor: 12 * time.Minute, probed: 3},
	{name: "exit-se-1", region: "se", mgmt: "10.20.0.15", public: "203.0.113.15", warpIP: "192.0.2.102", pool: "10.81.5.0/24", delay: 44 * time.Millisecond, drained: true},
	{name: "exit-us-1", region: "us", mgmt: "10.20.0.16", public: "203.0.113.16", warpIP: "192.0.2.119", pool: "10.81.6.0/24", delay: 118 * time.Millisecond, reachable: 3, probed: 3}, // reserve tier, warm-probed and usable
}

// client is one end user on the master's client interface, with how recently it
// handshook (0 = never connected).
type client struct {
	name         string
	handshakeAgo time.Duration
	rx, tx       int64
}

// vlessClients are the master's client-facing VLESS+REALITY credentials.
var vlessClients = []string{"alice-phone", "erin-macbook"}

var clients = []client{
	{name: "alice-phone", handshakeAgo: 24 * time.Second, rx: 1_842_000_000, tx: 96_000_000},
	{name: "bob-laptop", handshakeAgo: 71 * time.Second, rx: 9_310_000_000, tx: 412_000_000},
	{name: "carol-tablet", handshakeAgo: 3*time.Hour + 12*time.Minute, rx: 226_000_000, tx: 18_000_000},
	{name: "dave-desktop"},
}

func main() {
	dir := flag.String("dir", "", "work directory to create the demo fleet in (required)")
	agentBin := flag.String("agent-bin", "", "optional path to a wgfleet-agent binary; sets controller.agent_bin so the rollout panel can compare versions")
	keep := flag.Bool("keep", false, "stay running and re-record fresh status reports every -interval")
	interval := flag.Duration("interval", 10*time.Second, "re-record cadence with -keep")
	var b binds
	flag.StringVar(&b.listen, "listen", "127.0.0.1:8443", "controller.listen (gRPC) bind to write into the manifest")
	flag.StringVar(&b.webui, "webui", "127.0.0.1:9000", "controller.webui bind to write into the manifest")
	flag.StringVar(&b.metrics, "metrics", "127.0.0.1:9300", "controller.metrics bind to write into the manifest")
	flag.StringVar(&b.portal, "portal", "127.0.0.1:9001", "controller.client_portal bind to write into the manifest")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "demo-fleet: -dir is required")
		os.Exit(2)
	}
	if err := run(*dir, *agentBin, b, *keep, *interval); err != nil {
		fmt.Fprintln(os.Stderr, "demo-fleet:", err)
		os.Exit(1)
	}
}

// binds are the three listeners the manifest declares; flags so a host that
// already uses the defaults can still run the demo.
type binds struct{ listen, webui, metrics, portal string }

func run(dir, agentBin string, b binds, keep bool, interval time.Duration) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	manifest := filepath.Join(abs, "controller.yaml")
	if err := os.WriteFile(manifest, []byte(renderManifest(abs, agentBin, b)), 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	// Load it back through the real loader: this validates the manifest exactly
	// as the controller will, and gives the key broker the fleet it needs.
	cfg, err := config.Load(manifest, &config.ControllerConfig{})
	if err != nil {
		return fmt.Errorf("manifest does not load: %w", err)
	}
	if err := ensureCA(filepath.Join(abs, "ca.crt"), filepath.Join(abs, "ca.key")); err != nil {
		return err
	}
	st, err := store.Open(cfg.Controller.Store)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	ctx := context.Background()
	if err := seedAuth(ctx, st); err != nil {
		return err
	}
	if err := seedNodes(ctx, st); err != nil {
		return err
	}
	broker := keybroker.New(st, cfg.Fleet, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	clientKeys, err := seedClients(ctx, st, broker)
	if err != nil {
		return err
	}
	if err := seedDevices(ctx, st); err != nil {
		return err
	}
	if err := recordStatuses(ctx, st, clientKeys); err != nil {
		return err
	}

	fmt.Printf("demo fleet seeded in %s\n\n", abs)
	fmt.Printf("  bin/wgfleet-controller --config %s\n", manifest)
	fmt.Printf("  open http://%s   (login %s / %s)\n", b.webui, adminUser, adminPassword)
	fmt.Printf("  portal http://%s/c/<token>   (links in the console show %s)\n\n", b.portal, portalURL)
	if !keep {
		return nil
	}
	fmt.Printf("re-recording status every %s; Ctrl-C to stop\n", interval)
	for range time.Tick(interval) {
		if err := recordStatuses(ctx, st, clientKeys); err != nil {
			return err
		}
	}
	return nil
}

// renderManifest is the fleet the console will show. It mirrors the shape of the
// README's "Try it locally" manifest with a co-located master and six exits.
func renderManifest(dir, agentBin string, b binds) string {
	m := fmt.Sprintf(`# Fictional demo fleet written by tools/demo-fleet. Nothing here is real.
controller:
  listen:  %q
  webui:   %q
  metrics: %q
  store:   %q
  # Nothing reports over gRPC here, so the staleness sweep would demote every
  # node within minutes; the seeder's -keep loop stands in for the agents.
  staleness_after: -1s
  client_portal: %q
  client_portal_url: %q
  pki:
    ca_cert: %q
    ca_key:  "file://%s"
`, b.listen, b.webui, b.metrics, filepath.Join(dir, "state.db"), b.portal, portalURL, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if agentBin != "" {
		m += fmt.Sprintf("  agent_bin: %q\n", agentBin)
	}
	m += fmt.Sprintf(`fleet:
  mgmt_subnet: 10.20.0.0/16
  masters:
    - name: %s
      mgmt_addr: %s
      public_ip: %s
      client_awg: { listen_port: 443, address_pool: %s, managed: true }
      client_vless: { enabled: true, listen_port: 8443 }
      client_admin_ports: [9001]
      routing:
        direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
        direct_geo:   [RU]
        balance:      consistent-hashing
        reserve_exits: [exit-us-1]
      dns_filter: true
  exits:
`, masterName, masterMgmt, masterPublic, clientPool)
	for _, e := range exits {
		m += fmt.Sprintf(`    - name: %s
      region: %s
      egress: warp
      address_pool: %s
      mgmt_addr: %s
      public_ip: %s
      dns_filter: true
      firewall: { as_blacklist: true, whitelist: [10.20.0.0/16] }
`, e.name, e.region, e.pool, e.mgmt, e.public)
	}
	return m
}

func ensureCA(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}
	ca, err := pki.NewCA("wgfleet-demo-ca")
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	return pki.SaveCA(ca, certPath, keyPath)
}

// seedAuth installs the admin login once. The store is written directly, so the
// console's 12-character minimum does not apply — this is a demo password. A
// re-run leaves an existing credential alone: writing it again would rotate the
// session secret and log out whoever is screenshotting.
func seedAuth(ctx context.Context, st store.Store) error {
	if ok, err := st.AuthConfigured(ctx); err != nil || ok {
		return err
	}
	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return err
	}
	secret, err := auth.NewSecret()
	if err != nil {
		return err
	}
	return st.SetAuthCredential(ctx, adminUser, hash, secret)
}

// seedNodes writes the inventory rows the agents would have created by
// registering: role, addresses, version, a real WireGuard public key each, and
// the master's client-facing key.
func seedNodes(ctx context.Context, st store.Store) error {
	created := time.Now().Add(-37 * 24 * time.Hour)
	upsert := func(n domain.Node) error {
		kp, err := wg.GenerateKeyPair()
		if err != nil {
			return err
		}
		n.ID, n.PublicKey, n.CreatedAt = n.Name, kp.PublicKey, created
		n.AgentVersion, n.WireVersion = agentVersion, api.WireContractVersion
		return st.UpsertNode(ctx, n)
	}
	if err := upsert(domain.Node{Name: masterName, Role: domain.RoleMaster, Region: "ru",
		MgmtAddr: masterMgmt, PublicIP: masterPublic, State: domain.StateReady}); err != nil {
		return err
	}
	clientKP, err := wg.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := st.SetNodeClientWGKey(ctx, masterName, clientKP.PublicKey); err != nil {
		return err
	}
	// The client VLESS inbound's REALITY key is x25519 too, so a WireGuard keypair
	// is a valid stand-in for the one xray would generate on the node.
	vlessKP, err := wg.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := st.SetNodeClientVlessKey(ctx, masterName, vlessKP.PublicKey); err != nil {
		return err
	}
	for _, e := range exits {
		state := domain.StateReady
		if e.lowThroughput {
			state = domain.StateDegraded
		}
		if err := upsert(domain.Node{Name: e.name, Role: domain.RoleExit, Region: e.region,
			MgmtAddr: e.mgmt, PublicIP: e.public, State: state, Drain: e.drained}); err != nil {
			return err
		}
	}
	return nil
}

// seedClients issues the end-user credentials through the real broker so the
// addresses and ids are minted exactly as the console does. Returns each
// client's public key so the master's status report can list it as a live peer.
func seedClients(ctx context.Context, st store.Store, broker *keybroker.Broker) (map[string]string, error) {
	existing, err := st.ListWGClients(ctx, masterName)
	if err != nil {
		return nil, err
	}
	keys := map[string]string{}
	for _, c := range existing {
		keys[c.Name] = c.PublicKey
	}
	for _, c := range clients {
		if _, ok := keys[c.name]; ok {
			continue // re-run against an existing store
		}
		issued, err := broker.IssueWGClient(ctx, masterName, c.name)
		if err != nil {
			return nil, fmt.Errorf("issue %s: %w", c.name, err)
		}
		keys[c.name] = issued.PublicKey
	}
	vless, err := st.ListVLESSClients(ctx, masterName)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, c := range vless {
		have[c.Name] = true
	}
	for _, name := range vlessClients {
		if have[name] {
			continue
		}
		if _, err := broker.IssueVLESSClient(ctx, masterName, name); err != nil {
			return nil, fmt.Errorf("issue vless %s: %w", name, err)
		}
	}
	return keys, nil
}

// seedDevices runs the one-shot adoption the controller runs on its first start —
// so the device pages exist before the console opens — then attaches the VLESS
// credentials. IDs and tokens of created devices are fixed so a re-run finds them.
func seedDevices(ctx context.Context, st store.Store) error {
	if _, err := st.AdoptWGCredentialsAsDevices(ctx, time.Now()); err != nil {
		return fmt.Errorf("adopt: %w", err)
	}
	wgs, err := st.ListWGClients(ctx, masterName)
	if err != nil {
		return err
	}
	wgID := map[string]string{}
	for _, c := range wgs {
		wgID[c.Name] = c.ID
	}
	for i, d := range devices {
		id := store.AdoptedDeviceID(masterName, wgID[d.name])
		if _, ok := wgID[d.name]; !ok {
			id = fmt.Sprintf("d0000000000000000000000000000%03d", i)
			if _, err := st.GetDevice(ctx, id); errors.Is(err, store.ErrNotFound) {
				dev := domain.ClientDevice{ID: id, Token: fmt.Sprintf("7e57%028d", i), Name: d.name, CreatedAt: time.Now()}
				if err := st.CreateDevice(ctx, dev); err != nil {
					return fmt.Errorf("create device %s: %w", d.name, err)
				}
			}
		}
		err := st.AttachCredential(ctx, domain.CredentialVLESS, masterName, d.vless, id)
		if err != nil && !errors.Is(err, store.ErrDeviceSlotTaken) && !errors.Is(err, store.ErrCredentialAttached) {
			return fmt.Errorf("attach vless %s: %w", d.vless, err)
		}
	}
	return nil
}

// recordStatuses writes one fresh status report per node, as the agents would
// every reconcile pass: state, handshake age, self-checks, and for the master
// mihomo's view of every exit tunnel plus the live client peers.
func recordStatuses(ctx context.Context, st store.Store, clientKeys map[string]string) error {
	now := time.Now()
	ok := func(name, detail string, lat time.Duration) domain.HealthCheck {
		return domain.HealthCheck{Name: name, OK: true, Detail: detail, Latency: lat}
	}

	var health []domain.ExitTunnelHealth
	for _, e := range exits {
		h := domain.ExitTunnelHealth{
			Name: e.name, Alive: true, Delay: e.delay, LastTest: now.Add(-14 * time.Second), Selected: e.carrying,
			Reachable: e.reachable, Probed: e.probed,
		}
		if e.heldFor > 0 {
			h.Alive, h.HeldOut, h.HeldSince = false, true, now.Add(-e.heldFor)
		}
		health = append(health, h)
	}
	var peers []domain.ClientPeerStatus
	for _, c := range clients {
		p := domain.ClientPeerStatus{PublicKey: clientKeys[c.name], ReceivedBytes: c.rx, SentBytes: c.tx}
		if c.handshakeAgo > 0 {
			p.LastHandshake = now.Add(-c.handshakeAgo)
		}
		peers = append(peers, p)
	}
	master := domain.NodeStatus{
		NodeID: masterName, State: domain.StateReady, ReportedAt: now,
		LastHandshake: now.Add(-24 * time.Second),
		Checks: []domain.HealthCheck{
			ok("client-wg", "listening on :443", 3*time.Millisecond),
			ok("mihomo-api", "6 proxies, 3 selected", 4*time.Millisecond),
			ok("dns-filter", "resolved via 10.20.0.1:53", 9*time.Millisecond),
			ok("client-vless", "listening on :8443", 2*time.Millisecond),
			ok("client-wg-owned", "wg0 claimed by wgfleet-agent", 1*time.Millisecond),
			ok("udp-return-path", "reply sockets bindable on 443, 9993", 2*time.Millisecond),
		},
		ExitHealth:  health,
		ClientPeers: peers,
	}
	if err := writeStatus(ctx, st, master); err != nil {
		return err
	}

	for _, e := range exits {
		checks := []domain.HealthCheck{
			ok("wg-handshake", "19s ago", 6*time.Millisecond),
			ok("warp-egress", "WARP handshake 41s ago", 210*time.Millisecond),
			ok("dns-filter", "resolved via "+e.mgmt+":53", 7*time.Millisecond),
			ok(domain.CheckEgressReachability, "ok: egress via WARP", 0),
			ok(domain.CheckEgressActive, "warp", 0),
			ok(domain.CheckEgressThroughput, "live 1840 KiB/s (min 250 KiB/s)", 0),
		}
		state := domain.StateReady
		if e.lowThroughput {
			state = domain.StateDegraded
			checks[len(checks)-1] = domain.HealthCheck{Name: domain.CheckEgressThroughput,
				Detail: "below floor (5/5): live 87 KiB/s, probe 112 KiB/s (min 250 KiB/s)"}
		}
		s := domain.NodeStatus{
			NodeID: e.name, State: state, ReportedAt: now,
			LastHandshake: now.Add(-19 * time.Second), EgressIP: e.warpIP, Checks: checks,
		}
		if err := writeStatus(ctx, st, s); err != nil {
			return err
		}
	}
	return nil
}

// writeStatus persists a report the way the gRPC service does: the status row,
// then the node's lifecycle state reflected from it.
func writeStatus(ctx context.Context, st store.Store, s domain.NodeStatus) error {
	if err := st.RecordStatus(ctx, s); err != nil {
		return err
	}
	return st.SetNodeState(ctx, s.NodeID, s.State, s.ReconcileError)
}
