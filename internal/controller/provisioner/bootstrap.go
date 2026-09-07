package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/hardening"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
	"github.com/shidoh/wgfleet/internal/version"
)

// BootstrapInput is everything needed to render a node's bootstrap plan.
type BootstrapInput struct {
	Node   domain.Node // inventory entry (role, mgmt addr, ...)
	Facts  Facts       // discovered in Phase 0
	Bundle pki.KeyPair // node mTLS cert (CertPEM) — see also CABundle/Key below
	// CACert / NodeKey are the rest of the node's mTLS identity. They are written
	// to the node with 0600 (key) / 0644 (cert).
	CACert  []byte
	NodeKey []byte // SECRET — redacted in plan output

	// AgentBinary is the wgfleet-agent binary to install. May be nil in plan mode
	// or when the agent is fetched on-node by other means; then the upload step is
	// rendered as a placeholder.
	AgentBinary []byte

	// ControllerEndpoint is the mTLS address the agent will dial.
	ControllerEndpoint string
	// ZeroTierNetwork is the mgmt overlay network to join (empty ⇒ skip).
	ZeroTierNetwork string
	// MgmtOverlayMSS, when > 0, is baked into the node's agent.yaml as
	// agent.mgmt_overlay_mss (TCP MSS clamp on the overlay; control-plane insurance).
	MgmtOverlayMSS int
	// ReconcileInterval, when > 0, is baked into agent.yaml as
	// agent.reconcile_interval (the agent's reconcile/self-heal cadence). 0 ⇒ omit
	// the key and let the agent use its built-in default. The controller resolves
	// this from fleet.reconcile_interval (config.FleetSection.AgentReconcileInterval).
	ReconcileInterval time.Duration
	// ASBlacklistV4URL / ASBlacklistV6URL / ASBlacklistInterval are baked into
	// agent.yaml when set, configuring the scanner-ASN blacklist feed the exit
	// firewall drops (hides the WG port/SSH from VPN scanners). Empty/0 ⇒ omit the
	// key so the agent uses the asnfeed defaults. From fleet.as_blacklist_*.
	ASBlacklistV4URL    string
	ASBlacklistV6URL    string
	ASBlacklistInterval time.Duration
	// MgmtIgnoreCIDRs are management-overlay scopes fail2ban must never ban (added
	// to the sshd jail's ignoreip alongside loopback). From fleet.MgmtCIDRs() so the
	// operator/control plane reaching nodes over the overlay is never locked out.
	MgmtIgnoreCIDRs []string
}

// Remote paths the bootstrap writes to. Kept here so plan and apply agree.
const (
	remoteAgentBin = "/usr/local/bin/wgfleet-agent"
	// remoteAgentBinPrev holds the binary an upgrade replaced, so a node that comes
	// back broken can be restored over SSH — a channel independent of the agent
	// being upgraded, so a dead agent never blocks its own recovery.
	remoteAgentBinPrev = remoteAgentBin + ".prev"
	remoteUnit         = "/etc/systemd/system/wgfleet-agent.service"
	remoteAgentYAML    = "/etc/wgfleet/agent.yaml"
	remoteNodeCert     = "/etc/wgfleet/node.crt"
	remoteNodeKey      = "/etc/wgfleet/node.key"
	remoteCACert       = "/etc/wgfleet/ca.crt"
	remoteHardenConf   = hardening.SSHDDropInPath
	remoteFail2ban     = hardening.Fail2banJailPath
	remoteNodeExpDef   = nodeexporter.DefaultsPath
	remoteNodeExpDrop  = nodeexporter.DropInPath
)

// awgHeldPackages are the AmneziaWG apt packages held back from unattended
// upgrades. The data plane depends on the tools and the kernel module agreeing
// with each other and with the params we generate; an upgrade of either is an
// operator decision, made with the fleet watched. See the hold step in BuildPlan.
var awgHeldPackages = []string{"amneziawg", "amneziawg-dkms", "amneziawg-tools"}

// BuildPlan renders the ordered bootstrap steps for a node. The order is
// deliberate: harden and firewall BEFORE the node accepts traffic, install
// dependencies, join the mgmt overlay, then install the agent identity and unit,
// and finally start the agent (which takes over via mTLS reconcile).
func BuildPlan(in BootstrapInput) Plan {
	steps := []Step{
		// Phase 0 preconditions (read-only).
		checkStep("verify AmneziaWG kernel module present (pre-flight requirement)",
			"lsmod | grep -qw amneziawg || modinfo amneziawg",
			func(ctx context.Context, r Runner) error {
				present, diag := awgKmodDiag(ctx, r)
				if !present {
					return fmt.Errorf("AmneziaWG kernel module %s — install/load via DKMS before provisioning", diag)
				}
				return nil
			}),

		// Phase 1a: SSH hardening — key-only, no root password login, no X11. The same
		// managed drop-in the agent's host planner re-asserts every reconcile pass.
		uploadStep("harden sshd (no root password, key-only auth)", remoteHardenConf,
			[]byte(hardening.SSHDConfig), 0o644, hardening.SSHDConfig),
		runStep("reload sshd", "systemctl reload sshd || systemctl reload ssh"),

		// Phase 1b: baseline firewall before the node is reachable for traffic.
		uploadStep("install baseline nftables (allow SSH/ZT/WG only)", "/etc/wgfleet/baseline.nft",
			[]byte(baselineNFT), 0o644, baselineNFT),
		runStep("apply baseline firewall", "nft -f /etc/wgfleet/baseline.nft"),
	}

	// Phase 1c: install missing dependencies.
	if pkgs := in.Facts.MissingPackages(); len(pkgs) > 0 {
		steps = append(steps,
			runStep("apt update", "apt-get update -y"),
			runStep("install dependencies: "+join(pkgs),
				"DEBIAN_FRONTEND=noninteractive apt-get install -y "+join(pkgs)),
		)
	} else {
		steps = append(steps, checkStep("dependencies already present", "(no packages to install)",
			func(context.Context, Runner) error { return nil }))
	}

	// Phase 1c-1: pin the AmneziaWG packages. An unattended `apt-get upgrade` of
	// these has already taken the fleet down once: amneziawg-tools v1.0.20260618
	// parsed H1/H2 with `== NULL`, so the params never reached the kernel and every
	// master<->exit handshake died silently (fixed in v1.0.20260618-2). The kernel
	// module is equally load-bearing — a DKMS rebuild against a new kernel is a
	// deliberate act, not something an unattended upgrade should trigger.
	//
	// Applied unconditionally, not only when we just installed something: nodes
	// provisioned before this step exist and are unpinned (pn80 was, 2026-07-20).
	// `apt-mark hold` is idempotent and succeeds on an already-held package.
	steps = append(steps, runStep("hold AmneziaWG packages (no unattended upgrades)",
		"apt-mark hold "+join(awgHeldPackages)))

	// Phase 1c-2: Docker engine. Every role runs containers — exits run blocky,
	// the master runs mihomo + wg-easy — so the compose reconcilers need it.
	if !in.Facts.HasDocker {
		steps = append(steps, runStep("install Docker engine (get.docker.com)",
			"curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && sh /tmp/get-docker.sh && rm -f /tmp/get-docker.sh"))
	} else {
		steps = append(steps, checkStep("docker already present", "(docker engine present)",
			func(context.Context, Runner) error { return nil }))
	}

	// Phase 1c-3: wgcf for WARP egress (exit nodes). wgcf ships only as a
	// GitHub-release binary — there is no apt package — so it gets its own step.
	// Installed on every exit; the agent invokes it only when egress=warp.
	if in.Node.Role == domain.RoleExit && !in.Facts.HasWgcf {
		steps = append(steps, runStep(
			"install wgcf "+wgcfVersion+" for WARP egress (GitHub release)",
			wgcfInstallCmd(in.Facts.Arch)))
	}

	// Phase 1c-4: fail2ban SSH brute-force protection. The package is installed by
	// the dependency phase above (MissingPackages adds it when absent); here we drop
	// our jail and (re)start the service. Idempotent — safe to re-run on an already
	// protected node.
	fail2banConf := hardening.RenderFail2banJail(in.MgmtIgnoreCIDRs)
	steps = append(steps,
		uploadStep("install fail2ban sshd jail", remoteFail2ban,
			[]byte(fail2banConf), 0o644, fail2banConf),
		runStep("enable + (re)start fail2ban",
			"systemctl enable fail2ban && systemctl restart fail2ban"),
	)

	// Phase 1c-5: host metrics. The package is installed by the dependency phase;
	// here it is bound to the mgmt overlay and made to survive booting before the
	// overlay address exists. The agent's host planner re-asserts both files.
	nodeExpDefaults := nodeexporter.RenderDefaults(in.Node.MgmtAddr)
	steps = append(steps,
		uploadStep("bind the host-metrics exporter to the mgmt address", remoteNodeExpDef,
			[]byte(nodeExpDefaults), 0o644, nodeExpDefaults),
		uploadStep("install the host-metrics exporter unit drop-in", remoteNodeExpDrop,
			[]byte(nodeexporter.DropIn), 0o644, nodeexporter.DropIn),
		runStep("enable + (re)start the host-metrics exporter",
			"systemctl daemon-reload && systemctl enable "+nodeexporter.Unit+" && systemctl restart "+nodeexporter.Unit),
	)

	// Phase 1d: join the mgmt overlay (ZeroTier) if configured.
	if in.ZeroTierNetwork != "" {
		// Quote the operator-supplied id even though config.Validate already
		// constrains it to 16 hex chars: defense in depth, so this command is never
		// a shell-injection sink regardless of how the value got here.
		steps = append(steps,
			runStep("join ZeroTier mgmt network", "zerotier-cli join "+shellQuote(in.ZeroTierNetwork)))
	}

	// Phase 1e: install the node's mTLS identity (cert/key/ca).
	steps = append(steps,
		uploadStep("install node certificate", remoteNodeCert, in.Bundle.CertPEM, 0o644, string(in.Bundle.CertPEM)),
		uploadStep("install node private key (0600, secret)", remoteNodeKey, in.NodeKey, 0o600, "<redacted: node private key>"),
		uploadStep("install CA certificate", remoteCACert, in.CACert, 0o644, string(in.CACert)),
		uploadStep("install agent config", remoteAgentYAML,
			[]byte(renderAgentYAML(in)), 0o644, renderAgentYAML(in)),
	)

	// Phase 1f: install the agent binary + systemd unit.
	if len(in.AgentBinary) > 0 {
		steps = append(steps, uploadStep(
			fmt.Sprintf("install wgfleet-agent binary (%d bytes)", len(in.AgentBinary)),
			remoteAgentBin, in.AgentBinary, 0o755, "<binary>"))
	} else {
		steps = append(steps, checkStep("agent binary install (provide via --agent-bin)",
			"upload "+remoteAgentBin, func(context.Context, Runner) error { return nil }))
	}
	unit := renderSystemdUnit(in)
	steps = append(steps,
		uploadStep("install systemd unit", remoteUnit, []byte(unit), 0o644, unit),
		runStep("reload systemd", "systemctl daemon-reload"),
		// restart (not `enable --now`): on a re-provision the agent is already
		// running, and `enable --now` would NOT restart it, so the freshly uploaded
		// binary/config would never be picked up. restart starts it if stopped.
		runStep("enable + (re)start agent",
			"systemctl enable wgfleet-agent && systemctl restart wgfleet-agent"),
	)

	return Plan{Node: in.Node.Name, Steps: steps}
}

// BuildUpgradePlan renders the minimal steps to roll a node's agent binary
// forward: upload the new binary, then restart the service. It deliberately skips
// the full bootstrap (hardening, deps, overlay, identity) — those are already in
// place on a provisioned node. The data plane (containers, kernel WG interfaces)
// survives an agent restart, so no drain is required; the reconcile loop simply
// blips and resumes against the same desired state.
func BuildUpgradePlan(in BootstrapInput) Plan {
	var steps []Step
	if len(in.AgentBinary) == 0 {
		return Plan{Node: in.Node.Name, Steps: []Step{
			checkStep("agent binary upload (provide via --agent-bin / controller.agent_bin)",
				"upload "+remoteAgentBin,
				func(context.Context, Runner) error {
					return fmt.Errorf("no agent binary configured; set controller.agent_bin")
				}),
		}}
	}

	sum := sha256.Sum256(in.AgentBinary)
	want := hex.EncodeToString(sum[:])

	steps = append(steps,
		// Snapshot before overwriting: this copy is the rollback target. `cp` (not
		// `mv`) so the running binary's path keeps its inode — and it is conditional
		// because a node whose binary is somehow absent must still be upgradable;
		// it just has nothing to roll back to.
		runStep("snapshot current agent binary for rollback",
			fmt.Sprintf("test -f %s && cp -f %s %s || true",
				shellQuote(remoteAgentBin), shellQuote(remoteAgentBin), shellQuote(remoteAgentBinPrev))),

		uploadStep(fmt.Sprintf("upload wgfleet-agent binary (%d bytes, sha256 %s)", len(in.AgentBinary), want[:12]),
			remoteAgentBin, in.AgentBinary, 0o755, "<binary>"),

		// Verify BEFORE restarting. An interrupted transfer once left a truncated
		// binary on a node: `cat > … && mv` reported success at every command level,
		// systemd started it, and it SEGV-crash-looped — the failure was invisible
		// until the node went silent. Comparing the digest of what actually landed
		// against the source is the only check that catches a partial write, and it
		// has to happen while the old binary is still the running one.
		checkStep("verify uploaded binary sha256 matches source",
			"sha256sum "+remoteAgentBin+"  # expect "+want,
			func(ctx context.Context, r Runner) error {
				return verifyRemoteSHA256(ctx, r, remoteAgentBin, want)
			}),

		// restart picks up the freshly uploaded binary; enable keeps it sticky
		// across reboots if a manual install ever left it disabled.
		runStep("restart agent", "systemctl enable wgfleet-agent && systemctl restart wgfleet-agent"),
	)
	return Plan{Node: in.Node.Name, Steps: steps}
}

// BuildRollbackPlan restores the binary an upgrade displaced and restarts the
// agent. It runs over SSH, which is independent of the agent process, so it works
// precisely when it is needed most: the new binary is dead and the node is no
// longer reporting. It refuses when no snapshot exists rather than restarting a
// node into the same broken binary.
func BuildRollbackPlan(node string) Plan {
	return Plan{Node: node, Steps: []Step{
		checkStep("verify a rollback snapshot exists",
			"test -s "+remoteAgentBinPrev,
			func(ctx context.Context, r Runner) error {
				if _, err := r.Run(ctx, "test -s "+shellQuote(remoteAgentBinPrev)); err != nil {
					return fmt.Errorf("no rollback snapshot at %s: %w", remoteAgentBinPrev, err)
				}
				return nil
			}),
		runStep("restore previous agent binary",
			fmt.Sprintf("cp -f %s %s && chmod 0755 %s",
				shellQuote(remoteAgentBinPrev), shellQuote(remoteAgentBin), shellQuote(remoteAgentBin))),
		runStep("restart agent on restored binary",
			"systemctl enable wgfleet-agent && systemctl restart wgfleet-agent"),
	}}
}

// verifyRemoteSHA256 compares the digest of a file on the node against want.
// sha256sum prints "<hex>  <path>"; anything else (a missing tool, a truncated
// read) is treated as a failure — an unverifiable binary is not an acceptable
// one to restart into.
func verifyRemoteSHA256(ctx context.Context, r Runner, remotePath, want string) error {
	out, err := r.Run(ctx, "sha256sum "+shellQuote(remotePath))
	if err != nil {
		return fmt.Errorf("sha256sum %s: %w (output: %s)", remotePath, err, strings.TrimSpace(out))
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) == 0 {
		return fmt.Errorf("sha256sum %s: empty output", remotePath)
	}
	if got := fields[0]; !strings.EqualFold(got, want) {
		return fmt.Errorf("uploaded binary corrupt: %s has sha256 %s, want %s "+
			"(partial transfer — NOT restarting into it)", remotePath, got, want)
	}
	return nil
}

// ProbeAgentVersion runs the agent binary on the node with --version and returns
// its version.Short() identity — the same string the agent reports over gRPC, so
// a rolling upgrade can gate on "the version I installed is the version now
// checking in" rather than on a timer.
//
// It doubles as an execution smoke test: a binary that is the right size and
// digest but cannot run on this host (wrong arch, missing loader) fails here,
// before the restart gate has to infer it from silence.
func ProbeAgentVersion(ctx context.Context, r Runner) (string, error) {
	out, err := r.Run(ctx, shellQuote(remoteAgentBin)+" --version")
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w (output: %s)", remoteAgentBin, err, strings.TrimSpace(out))
	}
	return parseAgentVersion(out)
}

// ProbeLocalAgentVersion runs a LOCAL agent binary with --version and returns its
// version.Short() identity. Sibling of ProbeAgentVersion, which does the same over
// SSH on a node; both go through parseAgentVersion so the two cannot drift.
//
// It exists so a rolling upgrade can select nodes against the binary it is about
// to push rather than against the controller's own build. Those are the same tree
// only when both binaries were deployed together — deploying just one (which
// deploy-master.sh supports) breaks the assumption, and the rollout then upgrades
// every node to the version it already had while the panel keeps reporting them
// outdated: a roll that always succeeds and never converges.
func ProbeLocalAgentVersion(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w (output: %s)", path, err, strings.TrimSpace(string(out)))
	}
	return parseAgentVersion(string(out))
}

// parseAgentVersion extracts the Short() identity from `wgfleet-agent --version`
// output, whose first line is "wgfleet-agent <version> (commit <sha>, built …)".
// It reassembles the identity through version.ShortOf so this parse and what the
// agent actually reports cannot drift apart.
func parseAgentVersion(out string) (string, error) {
	line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "wgfleet-agent" {
		return "", fmt.Errorf("unrecognized --version output %q", line)
	}
	ver := fields[1]
	commit := "none"
	if i := strings.Index(line, "(commit "); i >= 0 {
		rest := line[i+len("(commit "):]
		commit = strings.TrimSuffix(strings.Fields(rest)[0], ",")
	}
	return version.ShortOf(ver, commit), nil
}

// wgcfVersion pins the wgcf release the bootstrap installs. Bump deliberately;
// one PrivateKey = one WARP server, so the binary just registers.
const wgcfVersion = "2.2.22"

// wgcfInstallCmd downloads the wgcf release binary for the node's arch into
// /usr/local/bin and marks it executable. arch is uname -m from the facts.
func wgcfInstallCmd(arch string) string {
	a := "amd64"
	switch arch {
	case "aarch64", "arm64":
		a = "arm64"
	case "armv7l", "armhf", "armv7":
		a = "armv7"
	}
	url := fmt.Sprintf("https://github.com/ViRb3/wgcf/releases/download/v%s/wgcf_%s_linux_%s",
		wgcfVersion, wgcfVersion, a)
	return fmt.Sprintf("curl -fsSL -o /usr/local/bin/wgcf %q && chmod +x /usr/local/bin/wgcf", url)
}

// renderSystemdUnit fills the agent unit. It carries no per-node launch flags: the
// agent reads its identity from agent.yaml and defaults its Prometheus /metrics
// endpoint to <mgmt_addr>:9301 (written into agent.yaml below), so the unit stays
// generic and identical across the fleet.
func renderSystemdUnit(BootstrapInput) string {
	return fmt.Sprintf(systemdUnitTemplate, "")
}

func renderAgentYAML(in BootstrapInput) string {
	var extra string
	if addr := strings.TrimSpace(in.Node.MgmtAddr); addr != "" {
		// Config-driven mgmt address: the agent binds its /metrics endpoint to
		// mgmt_addr:9301 by default (no launch flag needed) and uses it for other
		// off-public surfaces. See config.AgentSection.MgmtAddr.
		extra += fmt.Sprintf("  mgmt_addr: %q\n", addr)
	}
	if in.ReconcileInterval > 0 {
		// Fleet-wide reconcile/self-heal cadence (fleet.reconcile_interval). Omitted
		// when 0 so the agent falls back to its built-in default.
		extra += fmt.Sprintf("  reconcile_interval: %s\n", in.ReconcileInterval)
	}
	if in.MgmtOverlayMSS > 0 {
		// Baked in from fleet config so the clamp is agent-local: it must not depend on
		// the control channel it protects (see config.AgentSection.MgmtOverlayMSS).
		extra += fmt.Sprintf("  mgmt_overlay_mss: %d\n", in.MgmtOverlayMSS)
	}
	// Scanner-ASN blacklist feed knobs (agent-local; the per-exit enable toggle rides
	// the wire as firewall.as_blacklist). Omitted when empty/0 so the agent defaults.
	if u := strings.TrimSpace(in.ASBlacklistV4URL); u != "" {
		extra += fmt.Sprintf("  as_blacklist_v4_url: %q\n", u)
	}
	if u := strings.TrimSpace(in.ASBlacklistV6URL); u != "" {
		extra += fmt.Sprintf("  as_blacklist_v6_url: %q\n", u)
	}
	if in.ASBlacklistInterval > 0 {
		extra += fmt.Sprintf("  as_blacklist_interval: %s\n", in.ASBlacklistInterval)
	}
	// Management-overlay scopes fail2ban must never ban. Baked in so the agent's host
	// fail2ban planner can re-render the sshd jail's ignoreip every reconcile pass
	// (agent-local, from fleet.MgmtCIDRs()). Omitted when empty so the planner leaves
	// the bootstrap jail untouched rather than narrowing its ignoreip.
	if cidrs := trimCIDRs(in.MgmtIgnoreCIDRs); len(cidrs) > 0 {
		extra += "  mgmt_ignore_cidrs:\n"
		for _, c := range cidrs {
			extra += fmt.Sprintf("    - %q\n", c)
		}
	}
	return fmt.Sprintf(`agent:
  role: %s
  controller: %q
  node_id: %q
%s  identity:
    cert: %q
    key: %q
    ca: %q
`, in.Node.Role, in.ControllerEndpoint, in.Node.ID, extra,
		remoteNodeCert, remoteNodeKey, remoteCACert)
}

// trimCIDRs drops blank entries and trims whitespace, preserving order.
func trimCIDRs(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}
