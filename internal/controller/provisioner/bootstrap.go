package provisioner

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/domain"
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
}

// Remote paths the bootstrap writes to. Kept here so plan and apply agree.
const (
	remoteAgentBin   = "/usr/local/bin/wgfleet-agent"
	remoteUnit       = "/etc/systemd/system/wgfleet-agent.service"
	remoteAgentYAML  = "/etc/wgfleet/agent.yaml"
	remoteNodeCert   = "/etc/wgfleet/node.crt"
	remoteNodeKey    = "/etc/wgfleet/node.key"
	remoteCACert     = "/etc/wgfleet/ca.crt"
	remoteHardenConf = "/etc/ssh/sshd_config.d/10-wgfleet-hardening.conf"
)

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

		// Phase 1a: SSH hardening — key-only, no root password login.
		uploadStep("harden sshd (no root password, key-only auth)", remoteHardenConf,
			[]byte(sshHardening), 0o644, sshHardening),
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
	steps = append(steps,
		uploadStep("install systemd unit", remoteUnit, []byte(systemdUnit), 0o644, systemdUnit),
		runStep("reload systemd", "systemctl daemon-reload"),
		// restart (not `enable --now`): on a re-provision the agent is already
		// running, and `enable --now` would NOT restart it, so the freshly uploaded
		// binary/config would never be picked up. restart starts it if stopped.
		runStep("enable + (re)start agent",
			"systemctl enable wgfleet-agent && systemctl restart wgfleet-agent"),
	)

	return Plan{Node: in.Node.Name, Steps: steps}
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

func renderAgentYAML(in BootstrapInput) string {
	return fmt.Sprintf(`agent:
  role: %s
  controller: %q
  node_id: %q
  reconcile_interval: 60s
  identity:
    cert: %q
    key: %q
    ca: %q
`, in.Node.Role, in.ControllerEndpoint, in.Node.ID,
		remoteNodeCert, remoteNodeKey, remoteCACert)
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
