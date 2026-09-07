package provisioner

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/nodeexporter"
)

func testInput() BootstrapInput {
	return BootstrapInput{
		Node: domain.Node{
			ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit,
			MgmtAddr: "10.20.0.5",
			SSH:      domain.SSHTarget{Host: "203.0.113.10", User: "root", KeyPath: "/tmp/k"},
		},
		Bundle:             pki.KeyPair{CertPEM: []byte("-----BEGIN CERTIFICATE-----\nNODECERT\n-----END CERTIFICATE-----\n")},
		NodeKey:            []byte("-----BEGIN EC PRIVATE KEY-----\nSUPERSECRETKEY\n-----END EC PRIVATE KEY-----\n"),
		CACert:             []byte("-----BEGIN CERTIFICATE-----\nCACERT\n-----END CERTIFICATE-----\n"),
		AgentBinary:        []byte("\x7fELF-fake-binary"),
		ControllerEndpoint: "master-xa-1.mgmt:8443",
		ZeroTierNetwork:    "8056c2e21c000001",
	}
}

func quietProvisioner() *Provisioner {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// planText joins every step's summary and display so tests can assert on the
// rendered bootstrap regardless of step kind.
func planText(p Plan) string {
	var b strings.Builder
	for _, s := range p.Steps {
		b.WriteString(s.Summary)
		b.WriteByte('\n')
		b.WriteString(s.Display)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestUpgradePlanIsBinaryAndRestartOnly(t *testing.T) {
	plan := BuildUpgradePlan(testInput())
	txt := planText(plan)
	if !strings.Contains(txt, remoteAgentBin) {
		t.Errorf("upgrade plan does not upload the agent binary:\n%s", txt)
	}
	if !strings.Contains(txt, "restart wgfleet-agent") {
		t.Errorf("upgrade plan does not restart the agent:\n%s", txt)
	}
	// It must NOT re-run bootstrap concerns.
	for _, forbidden := range []string{"sshd", "nftables", "ZeroTier", "node certificate", "get.docker.com"} {
		if strings.Contains(txt, forbidden) {
			t.Errorf("upgrade plan should not include %q:\n%s", forbidden, txt)
		}
	}
}

func TestUpgradeApplyUploadsBinary(t *testing.T) {
	r := NewMockRunner()
	// The upgrade verifies the uploaded binary's digest before it will restart the
	// agent, so the mock must answer sha256sum with the digest of what was sent.
	r.PrefixResponses["sha256sum"] = digestOf(testInput().AgentBinary) + "  " + remoteAgentBin
	p := quietProvisioner()
	if _, err := p.Upgrade(context.Background(), r, testInput(), ModeApply); err != nil {
		t.Fatalf("upgrade apply: %v", err)
	}
	if _, ok := r.Uploaded[remoteAgentBin]; !ok {
		t.Errorf("apply did not upload %s", remoteAgentBin)
	}
	if !r.RanCommand("restart wgfleet-agent") {
		t.Error("apply did not restart the agent")
	}
}

func TestUpgradeApplyFailsWithoutBinary(t *testing.T) {
	r := NewMockRunner()
	p := quietProvisioner()
	in := testInput()
	in.AgentBinary = nil
	if _, err := p.Upgrade(context.Background(), r, in, ModeApply); err == nil {
		t.Error("upgrade without a binary should fail")
	}
}

func TestBootstrapInstallsWgcfAndDocker(t *testing.T) {
	// A fresh exit VM: docker and wgcf are absent, so each gets its own step.
	// wgcf is the arch-specific GitHub release (no apt package); docker via its
	// own installer. Neither must appear in the apt install line.
	in := testInput() // role exit, arch unset → default amd64
	in.Facts = Facts{OS: "Linux", Arch: "x86_64", HasAWGKmod: true}
	got := planText(BuildPlan(in))

	if !strings.Contains(got, "install Docker engine") {
		t.Errorf("exit bootstrap missing Docker step:\n%s", got)
	}
	if !strings.Contains(got, "install wgcf") || !strings.Contains(got, "wgcf_2.2.22_linux_amd64") {
		t.Errorf("exit bootstrap missing wgcf GitHub-release step:\n%s", got)
	}

	// aarch64 picks the arm64 release asset.
	in.Facts.Arch = "aarch64"
	if a := planText(BuildPlan(in)); !strings.Contains(a, "wgcf_2.2.22_linux_arm64") {
		t.Errorf("aarch64 should download the arm64 wgcf asset:\n%s", a)
	}

	// A master needs docker but NOT wgcf (no WARP egress).
	in.Node.Role = domain.RoleMaster
	in.Facts.Arch = "x86_64"
	m := planText(BuildPlan(in))
	if strings.Contains(m, "install wgcf") {
		t.Errorf("master must not install wgcf:\n%s", m)
	}
	if !strings.Contains(m, "install Docker engine") {
		t.Errorf("master must install docker:\n%s", m)
	}

	// Already-present docker ⇒ no install step.
	in.Facts.HasDocker = true
	if d := planText(BuildPlan(in)); strings.Contains(d, "install Docker engine") {
		t.Errorf("docker present: must not reinstall:\n%s", d)
	}
}

func TestBootstrapHoldsAmneziaWGPackages(t *testing.T) {
	// An unattended upgrade of amneziawg-tools has already taken the fleet down
	// once (v1.0.20260618 dropped H1/H2 on the floor). The hold must be emitted
	// on every role, and — critically — even when there is nothing to install,
	// since already-provisioned nodes are the ones found unpinned.
	for _, role := range []domain.Role{domain.RoleExit, domain.RoleMaster} {
		for _, complete := range []bool{false, true} {
			in := testInput()
			in.Node.Role = role
			in.Facts = Facts{OS: "Linux", Arch: "x86_64", HasAWGKmod: true}
			if complete {
				// Nothing missing: the apt install step is skipped entirely.
				in.Facts = Facts{
					OS: "Linux", Arch: "x86_64", HasAWGKmod: true,
					HasAWGTools: true, HasWGTools: true, HasNft: true,
					HasConntrack: true, HasTracepath: true, HasFail2ban: true,
					HasAge: true, HasDocker: true, HasWgcf: true,
				}
			}
			got := planText(BuildPlan(in))
			for _, pkg := range awgHeldPackages {
				if !strings.Contains(got, pkg) {
					t.Errorf("role=%s complete=%v: hold missing %q:\n%s", role, complete, pkg, got)
				}
			}
			if !strings.Contains(got, "apt-mark hold") {
				t.Errorf("role=%s complete=%v: no apt-mark hold step:\n%s", role, complete, got)
			}
		}
	}
}

// Host metrics are part of what a provisioned node is: without them the master —
// the client entry point and the fleet's CPU bottleneck — had no CPU, memory or
// disk series at all. Bootstrap installs the exporter and binds it to the mgmt
// overlay; the agent's host planner re-asserts the same files every pass.
func TestBootstrapConfiguresNodeExporterOnTheMgmtAddress(t *testing.T) {
	in := testInput()
	in.Facts = Facts{OS: "Linux", Arch: "x86_64", HasAWGKmod: true}
	got := planText(BuildPlan(in))
	for _, want := range []string{
		nodeexporter.DefaultsPath, nodeexporter.DropInPath,
		"--web.listen-address=10.20.0.5:9100",
		"systemctl enable prometheus-node-exporter",
		"systemctl restart prometheus-node-exporter",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bootstrap plan lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "0.0.0.0:9100") {
		t.Errorf("exporter must not bind the wildcard:\n%s", got)
	}
}

func TestProvisionPlanModeChangesNothing(t *testing.T) {
	r := readyRunner()
	p := quietProvisioner()

	report, err := p.Provision(context.Background(), r, testInput(), ModePlan)
	if err != nil {
		t.Fatalf("provision plan: %v", err)
	}

	// Plan mode must not upload anything or run mutating commands. Only read-only
	// fact-collection commands (uname, command -v, lsmod) are allowed.
	if len(r.Uploaded) != 0 {
		t.Errorf("plan mode uploaded files: %v", keys(r.Uploaded))
	}
	for _, cmd := range r.Ran {
		if isMutating(cmd) {
			t.Errorf("plan mode ran a mutating command: %q", cmd)
		}
	}

	out := report.String()
	for _, want := range []string{
		"AmneziaWG kernel module", "harden sshd", "baseline nftables",
		"join ZeroTier", "node certificate", "systemd unit", "enable + (re)start agent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output missing %q\n%s", want, out)
		}
	}
	// The node private key must never appear in plan output.
	if strings.Contains(out, "SUPERSECRETKEY") {
		t.Error("plan output leaked the node private key")
	}
	if !strings.Contains(out, "<redacted: node private key>") {
		t.Error("plan output missing key redaction marker")
	}
}

func TestProvisionApplyRunsSteps(t *testing.T) {
	r := readyRunner()
	p := quietProvisioner()

	if _, err := p.Provision(context.Background(), r, testInput(), ModeApply); err != nil {
		t.Fatalf("provision apply: %v", err)
	}

	// Identity + config + binary + unit must be uploaded.
	for _, path := range []string{remoteNodeCert, remoteNodeKey, remoteCACert, remoteAgentYAML, remoteAgentBin, remoteUnit} {
		if _, ok := r.Uploaded[path]; !ok {
			t.Errorf("apply did not upload %s", path)
		}
	}
	// The real (unredacted) key must be what was written to the node.
	if got := string(r.Uploaded[remoteNodeKey]); !strings.Contains(got, "SUPERSECRETKEY") {
		t.Errorf("node key upload content wrong: %q", got)
	}
	// Mutating commands must have run.
	for _, want := range []string{"nft -f", "systemctl restart wgfleet-agent", "zerotier-cli join"} {
		if !r.RanCommand(want) {
			t.Errorf("apply did not run %q", want)
		}
	}
}

func TestProvisionAbortsWithoutAWGModule(t *testing.T) {
	r := readyRunner()
	r.PrefixResponses["k=$(uname -r)"] = "AWGKMOD=no (absent, test)" // module absent
	p := quietProvisioner()

	_, err := p.Provision(context.Background(), r, testInput(), ModeApply)
	if err == nil {
		t.Fatal("provision must abort when AmneziaWG kernel module is absent")
	}
	if !strings.Contains(err.Error(), "preflight") {
		t.Errorf("expected preflight error, got %v", err)
	}
	// Nothing should have been uploaded — preflight gates before any change.
	if len(r.Uploaded) != 0 {
		t.Errorf("aborted provision still uploaded: %v", keys(r.Uploaded))
	}
}

func TestAgentYAMLRendersIdentityPaths(t *testing.T) {
	yaml := renderAgentYAML(testInput())
	for _, want := range []string{
		"role: exit", `controller: "master-xa-1.mgmt:8443"`, `node_id: "exit-de-1"`,
		remoteNodeCert, remoteNodeKey, remoteCACert,
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("agent.yaml missing %q:\n%s", want, yaml)
		}
	}
	// No overlay MSS configured ⇒ the key is omitted entirely.
	if strings.Contains(yaml, "mgmt_overlay_mss") {
		t.Errorf("mgmt_overlay_mss should be absent when unset:\n%s", yaml)
	}
}

func TestAgentYAMLBakesOverlayMSS(t *testing.T) {
	in := testInput()
	in.MgmtOverlayMSS = 1240
	yaml := renderAgentYAML(in)
	if !strings.Contains(yaml, "mgmt_overlay_mss: 1240") {
		t.Errorf("agent.yaml should carry the overlay MSS clamp:\n%s", yaml)
	}
	// Must stay inside the agent: block and not break the identity block below it.
	if !strings.Contains(yaml, "  identity:") {
		t.Errorf("agent.yaml malformed after injecting overlay MSS:\n%s", yaml)
	}
}

// --- helpers ---

func isMutating(cmd string) bool {
	for _, m := range []string{"nft -f", "systemctl", "apt-get", "zerotier-cli join", "cat >"} {
		if strings.Contains(cmd, m) {
			return true
		}
	}
	return false
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
