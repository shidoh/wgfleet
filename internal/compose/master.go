// Package compose renders the master node's container stack as a
// docker-compose.yml from the desired state. The stack is mihomo (proxy router +
// load balancer) and, when the master wants it, the container that owns mihomo's
// network namespace. The agent writes this file and keeps the stack up
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
	mihomoDir = "/etc/mihomo" // mihomo config.yaml + rule providers
)

// Default container images (repository:tag) when the spec leaves them unset.
// Exported so the controller can resolve operator image/tag overrides against
// the same canonical defaults the renderer falls back to.
const (
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
	//
	// Bumped 1.19.30 → 1.19.32 (2026-10-14): 1.19.31 fixes RandomPaddingAddition and
	// DisableCookies for AmneziaWG v3 (what a `version: 3` master↔exit tunnel runs on),
	// a nil dereference in WireGuard initialization, and 1.19.32 sizes the effective
	// MSS with TCP options counted. The image change recreates the namespace holder
	// too (it runs this image, see netnsHolderImage); on the stand that cost one
	// pass: the agent re-plumbs the namespace and restarts mihomo to rebind the
	// listeners it started before the namespace had its address — one ~6 s gap for
	// clients, the same as any mihomo restart.
	//
	// Bumped 1.19.32 → 1.19.33 (2026-10-28): a sub-millisecond URL test is no longer
	// reported as a failure (our delay probes and wg-best), the fake-ip pool keeps its
	// allocations across a hot reload, DoH dials the query gave up on no longer pile
	// up, WireGuard devices are initialised lazily, and the crypto/tls CVE-2026-97031
	// fix.
	DefaultMihomoImage = "metacubex/mihomo:v1.19.33"
	// NetnsHolderSleep is what the namespace holder runs. A shell loop rather than
	// `sleep infinity`, because the holder now runs the mihomo image (see
	// netnsHolderImage) and BusyBox's sleep in some builds takes only an integer.
	// PID 1 in a container gets no default signal handlers, so the loop is what
	// keeps `docker stop` working: the shell traps and exits.
	NetnsHolderSleep = "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"
)

// RenderInput is everything needed to render the master compose file.
type RenderInput struct {
	Compose domain.ComposeSpec
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
}

// RenderMasterCompose renders docker-compose.yml for the master stack.
func RenderMasterCompose(in RenderInput) (string, error) {
	mihomoImage := orDefault(in.Compose.MihomoImage, DefaultMihomoImage)

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

	// The namespace holder, and mihomo joining it. `network_mode: "container:X"` is
	// the same kernel operation Kubernetes performs for a pod — setns(CLONE_NEWNET)
	// onto a namespace someone else owns — so mihomo's transparent reply sockets no
	// longer compete with whatever the HOST happens to bind. That competition is the
	// whole bug: on the live master the client AmneziaWG interface holds
	// 0.0.0.0:443 without SO_REUSEADDR, so every reply socket mihomo opened for a
	// client's QUIC flow failed with EADDRINUSE and the packet was dropped in
	// silence.
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
			mihomo["depends_on"] = []any{domain.NetnsHolder}
		}
	}

	doc := map[string]any{"services": services}

	out, err := marshalYAML(doc)
	if err != nil {
		return "", fmt.Errorf("compose render: %w", err)
	}
	return out, nil
}

// MihomoDir exposes the mounted host directory so the agent renders configs into
// the same place the container reads them.
func MihomoDir() string { return mihomoDir }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
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
