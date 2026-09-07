// Package compose renders the master node's container stack as a
// docker-compose.yml from the desired state. The master data plane runs as two
// containers: wg-easy (client-facing AmneziaWG server + UI) and mihomo (proxy
// router + load balancer). The agent writes this file and keeps the stack up
// with `docker compose up -d`; restarts of individual services happen when their
// mounted config changes (see the master reconcilers).
//
// The output is a structured map marshaled deterministically (yaml.v3 sorts map
// keys), which keeps dry-run diffs honest.
package compose

import (
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Host directories the stack mounts. They hold the agent-rendered configs.
const (
	wgEasyDir = "/etc/wireguard" // wg-easy db + generated wg configs (an earlier finding: per-node)
	mihomoDir = "/etc/mihomo"    // mihomo config.yaml + rule providers
)

// Default container images (repository:tag) when the spec leaves them unset.
// Exported so the controller can resolve operator image/tag overrides against
// the same canonical defaults the renderer falls back to.
const (
	// Pinned by DIGEST, not by the `:15` major tag. `:15` is a MOVING tag — the same
	// trap the mihomo `Alpha` override fell into below — and here it is materially
	// worse: wg-easy ships schema migrations that run automatically on container
	// start (7 as of v15.3.0, five of them after v15.0.0, two in June 2026), and we
	// write that SQLite schema DIRECTLY for the AWG params, because wg-easy exposes
	// no env or API for them (ADR-0008). A moving tag therefore lets an unattended
	// `docker pull` migrate the schema out from under our writes.
	//
	// Digest resolved 2026-07-20 from the image the fleet was actually running
	// (v15.3.0, built 2026-05-18). Bumping this is an operator decision: re-check
	// internal/wgeasy/awg.go ColumnsFromSpec against the new schema first.
	DefaultWGEasyImage = "ghcr.io/wg-easy/wg-easy:15@sha256:93bbd593e07bab98d02807a28770ac87ab6c48818e319e68c1f66561feb99876"
	// DefaultWGEasyImageAWG3 is the wg-easy the stack runs once the host's AmneziaWG
	// kernel module is generation 3. wg-easy drives the interface with the
	// amneziawg-tools it bundles, and AmneziaWG 3.0 changed the netlink attribute
	// layout between tools and module, so the two must be of one generation:
	// v15.3.0 above bundles generation-1 tools, v15.4.0 pins AWGTOOLS_BRANCH to
	// v3.0.20260805. A 15.3 container on a 3.x module fails `awg setconf` with
	// "Invalid argument" on its own defaults and never raises the interface — a
	// tester's master lost every client that way on 2026-09-07 after a routine
	// module upgrade. Both digests were exercised against the same module and the
	// agent's exact AWG columns on a stand that day; see WGEasyImageFor.
	//
	// Multi-arch index digest of ghcr.io/wg-easy/wg-easy:15 as resolved 2026-09-07
	// (v15.4.0). The interfaces_table AWG columns are identical to 15.3's
	// (j_c/j_min/j_max, s1-s4, h1-h4 text, i1-i5 text); 15.4 adds routing_table
	// with a default, which is why the agent's UPDATE keeps working unchanged.
	DefaultWGEasyImageAWG3 = "ghcr.io/wg-easy/wg-easy:15@sha256:0e7bc9d34e86ddcaa92bc700d4d7dc9b33291dbc07ac8d13382f7c2095f949ec"
	// wgEasyAWG3MinGeneration is the module generation from which the stack runs
	// DefaultWGEasyImageAWG3 (mirrors awgmod's gate).
	wgEasyAWG3MinGeneration = 3
	// Pinned, NOT :latest and NOT :Alpha (docs/DESIGN.md #8) — reproducible/auditable
	// deploys. (The AWG-param safety that keeps mihomo's amneziawg-go from panicking is
	// handled in the derivation: Jmin is floored ≥ S4, so no junk packet underflows its
	// S4-strip — see internal/wg junkS4Margin. So this pin is for reproducibility, not a
	// kernel↔mihomo version-match requirement.)
	//
	// Bumped 1.19.27 → 1.19.29 to retire the fleet's `mihomo_tag: "Alpha"` override. That
	// override existed because AWG 2.0 landed in Alpha before any release; it shipped in
	// v1.19.14 (2025-09-24), so the rationale is long obsolete — and `Alpha` is a MOVING
	// tag, which silently defeats the pin.
	//
	// Bumped 1.19.29 → 1.19.30 (2026-08-17): CVE-2026-56862 in crypto/tls, an xhttp fix
	// that touches our transport (default uplink chunk size), and a batch of sniffer work
	// we lean on. It also adds AmneziaWG v3.0/v3.1 support behind a new `version:` key —
	// unset (our case) keeps the legacy device_v1 code path, so this bump does NOT change
	// how the fleet's AWG 2.0 tunnels are built. Enabling `version: 3` is a separate
	// decision gated by tools/check-awg3-status.sh.
	DefaultMihomoImage = "metacubex/mihomo:v1.19.30"
	// NetnsHolderSleep is what the namespace holder runs. A shell loop rather than
	// `sleep infinity`, because the holder now runs the mihomo image (see
	// netnsHolderImage) and BusyBox's sleep in some builds takes only an integer.
	// PID 1 in a container gets no default signal handlers, so the loop is what
	// keeps `docker stop` working: the shell traps and exits.
	NetnsHolderSleep = "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"
	// DefaultWGEasyWebPort is the wg-easy admin UI port when the spec leaves it
	// unset. Exported so the controller UI can build a link to it.
	DefaultWGEasyWebPort = 44423
	// defaultAdminUsername is the wg-easy admin account name used for unattended
	// setup when the input leaves the username empty (matches wgeasy.AdminUsername).
	defaultAdminUsername = "admin"
)

// RenderInput is everything needed to render the master compose file.
type RenderInput struct {
	Compose domain.ComposeSpec
	// ClientListenPort / ClientPool come from the master's client-facing AWG
	// server spec (WGServerSpec): the UDP port clients dial and their subnet.
	ClientListenPort int
	ClientPool       string
	// MgmtAddr is the master's ZeroTier address; admin endpoints bind it only.
	MgmtAddr string
	// AdminUsername / AdminPassword drive wg-easy's unattended setup. They are
	// resolved agent-locally (the password is generated and persisted on-node,
	// never sent by the controller — ADR-0008). When the password is empty no
	// admin is seeded and wg-easy falls back to its interactive setup wizard.
	AdminUsername string
	AdminPassword string
	// ClientWGManaged drops wg-easy from the stack: the agent owns the client-facing
	// interface and raises it directly, so the container would only fight it for the
	// same UDP port and the same /etc/wireguard directory.
	ClientWGManaged bool
	// NetnsAttachMihomo moves mihomo INTO the holder's namespace. Separate from
	// NetnsHolderImage on purpose, and the separation is the whole safety property
	// of phase A: the holder and its veth can be created, inspected and repaired on
	// a live master while mihomo keeps serving clients from the host namespace.
	// Attaching is the irreversible-feeling half — mihomo's listeners bind an
	// address that only exists inside the namespace — and it belongs with the
	// interception rules that move at the same moment, not before them.
	NetnsAttachMihomo bool
	// NetnsHolderImage, when set, adds the container that OWNS mihomo's network
	// namespace. It does nothing but hold the namespace open — the role Kubernetes
	// gives `pause` — and it exists as a separate container precisely because
	// mihomo does not stay up: a proxy definition changes, the duplicate-device
	// self-heal fires, and each restart would otherwise take the veth and the
	// interception rules with it, leaving clients with no path until the next
	// reconcile pass noticed. Empty ⇒ no holder, mihomo stays on host networking.
	NetnsHolderImage string
	// AWGModuleGeneration is the MAJOR version of the AmneziaWG kernel module on
	// this node — 1 for the 1.x line, 3 for 3.x, 0 when it could not be read. The
	// agent supplies it (awgmod.ModuleGeneration) because only the node knows which
	// module it runs; the controller resolves the image knob without that
	// knowledge. It selects the wg-easy image when the operator left it at the
	// default: see WGEasyImageFor.
	AWGModuleGeneration int
}

// WGEasyImageFor picks the wg-easy image for a node whose AmneziaWG module is
// generation gen. An operator override is returned untouched — pinning is theirs
// to get right and theirs to be told about. The default follows the module: the
// generation-1 pin until the module is 3.x, DefaultWGEasyImageAWG3 from then on.
// An unreadable generation (0) keeps the pin, which is the image the node was
// running before this decision existed.
//
// The controller sends the resolved default rather than an empty string, so
// "left at the default" is recognised by value. That is deliberate: the wire
// contract does not change, and an older controller's spec still gets the right
// image on a node whose module moved.
func WGEasyImageFor(image string, gen int) string {
	switch {
	case image != "" && image != DefaultWGEasyImage:
		return image
	case gen >= wgEasyAWG3MinGeneration:
		return DefaultWGEasyImageAWG3
	default:
		return DefaultWGEasyImage
	}
}

// RenderMasterCompose renders docker-compose.yml for the master stack. The
// INIT_* environment variables seed wg-easy on first run only (it ignores them
// once set up); AmneziaWG obfuscation is configured separately by writing
// wg-easy's SQLite DB (ADR-0008), since INIT_* cannot set it.
func RenderMasterCompose(in RenderInput) (string, error) {
	if in.MgmtAddr == "" {
		return "", fmt.Errorf("compose render: master mgmt address is required")
	}
	c := in.Compose

	wgEasyImage := WGEasyImageFor(c.WGEasyImage, in.AWGModuleGeneration)
	mihomoImage := orDefault(c.MihomoImage, DefaultMihomoImage)
	webPort := c.WGEasyWebPort
	if webPort == 0 {
		webPort = DefaultWGEasyWebPort
	}

	wgEasyEnv := []any{
		fmt.Sprintf("PORT=%d", webPort),
		"HOST=" + in.MgmtAddr,
		"INSECURE=true",
		"EXPERIMENTAL_AWG=true",
		"OVERRIDE_AUTO_AWG=awg",
	}
	// First-run seeding. wg-easy applies INIT_* ONLY at first DB creation (it
	// ignores them once set up), and v15 gates them precisely (verified against
	// wg-easy 15.3.0 src/server/database/sqlite.ts initialSetup):
	//   - INIT_IPV4_CIDR applies only when INIT_IPV6_CIDR is ALSO set;
	//   - INIT_DNS / INIT_ALLOWED_IPS apply on their own (client-config defaults);
	//   - the setup WIZARD is skipped (setSetupStep(0)) ONLY when ALL of
	//     INIT_USERNAME + INIT_PASSWORD + INIT_HOST + INIT_PORT are present.
	// So to bring a fresh master up non-interactively we MUST supply the admin
	// credentials together with host+port — otherwise wg-easy stops at its setup
	// wizard asking for password/host/port (ADR-0008). The admin password is
	// resolved agent-locally and never crosses the wire. The interface columns
	// (port/pool/MTU + AmneziaWG obfuscation) are still enforced authoritatively by
	// the agent's direct DB write afterwards (internal/wgeasy ColumnsFromSpec).
	if in.ClientPool != "" || in.AdminPassword != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_ENABLED=true")
	}
	if in.ClientPool != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_IPV4_CIDR="+in.ClientPool)
	}
	if c.PublicIP != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_HOST="+c.PublicIP)
	}
	if in.ClientListenPort > 0 {
		wgEasyEnv = append(wgEasyEnv, fmt.Sprintf("INIT_PORT=%d", in.ClientListenPort))
	}
	if in.AdminPassword != "" {
		user := in.AdminUsername
		if user == "" {
			user = defaultAdminUsername
		}
		wgEasyEnv = append(wgEasyEnv,
			"INIT_USERNAME="+user,
			"INIT_PASSWORD="+in.AdminPassword,
		)
	}
	if len(c.ClientDNS) > 0 {
		wgEasyEnv = append(wgEasyEnv, "INIT_DNS="+strings.Join(c.ClientDNS, ","))
	}
	if c.ClientAllowedIPs != "" {
		wgEasyEnv = append(wgEasyEnv, "INIT_ALLOWED_IPS="+c.ClientAllowedIPs)
	}

	mihomo := map[string]any{
		"image":          mihomoImage,
		"container_name": "mihomo",
		"restart":        "always",
		"network_mode":   "host",
		"cap_add":        []any{"NET_ADMIN", "SYS_PTRACE"},
		"volumes":        []any{mihomoDir + ":/etc/mihomo"},
		"command":        "-d /etc/mihomo",
		// Bound the log. Docker's default json-file driver has NO rotation, and this
		// container is the noisiest thing on the master: measured 2026-09-04 it had
		// written 97787 error lines in 18 days, all of one kind, into a file nothing
		// ever truncates. That is a disk leak on a 2 vCPU box, and it also makes
		// `docker logs --since` expensive — json-file has no index, so every read
		// scans from the beginning of the file.
		"logging": map[string]any{
			"driver":  "json-file",
			"options": map[string]any{"max-size": "10m", "max-file": "3"},
		},
	}
	services := map[string]any{"mihomo": mihomo}

	// wg-easy is in the stack only while it still owns the client leg. Once the
	// agent does, the container is dropped entirely rather than merely stopped: a
	// `docker compose up -d` on a file that still lists it would bring it straight
	// back, and it would then race the agent's interface for the same UDP port and
	// the same /etc/wireguard directory. Removing the service makes `up -d` itself
	// the thing that retires it.
	//
	// mihomo's depends_on goes with it — a dependency on a service the file no
	// longer defines is a compose error, and the ordering it bought (wg0 exists
	// before mihomo binds) is now the interface planner's job.
	if !in.ClientWGManaged {
		services["wg-easy"] = map[string]any{
			"image":          wgEasyImage,
			"container_name": "wg-easy",
			"restart":        "unless-stopped",
			"network_mode":   "host",
			"cap_add":        []any{"NET_ADMIN", "SYS_MODULE"},
			"volumes": []any{
				wgEasyDir + ":/etc/wireguard",
				"/lib/modules:/lib/modules:ro",
			},
			"environment": wgEasyEnv,
		}
		mihomo["depends_on"] = []any{"wg-easy"}
	}

	// The namespace holder, and mihomo joining it. `network_mode: "container:X"` is
	// the same kernel operation Kubernetes performs for a pod — setns(CLONE_NEWNET)
	// onto a namespace someone else owns — so mihomo's transparent reply sockets no
	// longer compete with whatever the HOST happens to bind. That competition is the
	// whole bug: on the live master the client AmneziaWG interface holds
	// 0.0.0.0:443 without SO_REUSEADDR, so every reply socket mihomo opened for a
	// client's QUIC flow failed with EADDRINUSE and the packet was dropped in
	// silence.
	//
	// Placed after the wg-easy block so the dependency is APPENDED: while wg-easy
	// still owns the client leg mihomo waits for both, and overwriting would drop
	// the ordering that keeps wg0 present before mihomo binds it.
	if in.NetnsHolderImage != "" {
		services[domain.NetnsHolder] = map[string]any{
			"image":          in.NetnsHolderImage,
			"container_name": domain.NetnsHolder,
			// The image is the master's own mihomo unless the operator overrode it, so
			// the entrypoint has to be replaced: mihomo's own would start a second proxy
			// inside the namespace and fight the first one for the listeners.
			"entrypoint":   []any{"/bin/sh", "-c"},
			"command":      []any{NetnsHolderSleep},
			"network_mode": "none",
			"restart":      "unless-stopped",
			"logging": map[string]any{
				"driver":  "json-file",
				"options": map[string]any{"max-size": "1m", "max-file": "1"},
			},
		}
		if in.NetnsAttachMihomo {
			mihomo["network_mode"] = "container:" + domain.NetnsHolder
			deps, _ := mihomo["depends_on"].([]any)
			mihomo["depends_on"] = append(deps, domain.NetnsHolder)
		}
	}

	doc := map[string]any{"services": services}

	out, err := marshalYAML(doc)
	if err != nil {
		return "", fmt.Errorf("compose render: %w", err)
	}
	return out, nil
}

// MihomoDir / WGEasyDir expose the mounted host directories so the agent renders
// configs into the same place the containers read them.
func MihomoDir() string { return mihomoDir }
func WGEasyDir() string { return wgEasyDir }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// redactedEnvKeys are the wg-easy env entries whose values are secret and must be
// masked in dry-run plan output / Web UI previews. The value still lands verbatim
// in the on-disk compose file (root-only).
var redactedEnvKeys = []string{"INIT_PASSWORD="}

// RedactComposeEnv masks secret env values (e.g. INIT_PASSWORD) in a rendered
// compose document so plan output and the Web UI never display them. It is the
// reconcile.Redactor for the master compose FileAction.
func RedactComposeEnv(yamlText string) string {
	lines := strings.Split(yamlText, "\n")
	for i, line := range lines {
		for _, key := range redactedEnvKeys {
			if idx := strings.Index(line, key); idx != -1 {
				lines[i] = line[:idx+len(key)] + "<redacted>"
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func marshalYAML(v any) (string, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		// Close flushes the final node; a truncated flush would write a corrupt
		// config to disk. Surface it instead of shipping invalid YAML.
		return "", fmt.Errorf("flush yaml: %w", err)
	}
	return b.String(), nil
}
