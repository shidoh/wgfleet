package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/certrenew"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
)

// runCertsCheckExpiration prints when every certificate this host holds expires.
//
// The point is that the answer used to require openssl and knowing which files to
// look in. Node certificates last a year, and the fleet-wide consequence of that —
// nodes falling off the control plane one provisioning anniversary at a time — is
// invisible until somebody asks. Agents renew themselves now, so this is mostly a
// confirmation that the mechanism is working; the row that matters is the one whose
// remaining time stops going up.
func runCertsCheckExpiration(cfg *config.ControllerConfig) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CERTIFICATE\tEXPIRES\tREMAINING")

	// Every certificate this host actually holds, not just the CA.
	//
	// The loop used to be a one-element slice while the flag help said "prints what
	// this host holds" — and on a co-located master, which is the deployment this
	// project ships, the same box also holds the node certificate the agent presents
	// to the control plane. That is the one with a one-year life and the one an
	// operator running this command is asking about. It is absent when the controller
	// runs alone, which the empty-path skip below already handles.
	rows := 0
	for _, c := range []struct{ label, path string }{
		{"controller CA", cfg.Controller.PKI.CACert},
		{"this node's agent certificate", localNodeCertPath()},
	} {
		if c.path == "" {
			continue
		}
		nb, na, err := certrenew.NotBeforeAfter(c.path)
		if err != nil {
			fmt.Fprintf(w, "%s\t-\t%v\n", c.label, err)
			continue
		}
		_ = nb
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.label, na.UTC().Format(time.RFC3339), humanUntil(na))
		rows++
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("no certificates found; is this the controller host?")
	}
	fmt.Fprintf(os.Stderr, "\nThe OTHER nodes' certificates live on those nodes and are renewed by their own\n"+
		"agents (wire v%d and above), between 70%% and 90%% of the certificate's life. This\n"+
		"host cannot read them; wgfleet_agent_cert_expiry_timestamp_seconds is the\n"+
		"fleet-wide view, and a node whose remaining time stops rising is one to look at.\n"+
		"\nThe controller's own SERVER certificate is not listed because it is not a file:\n"+
		"it is minted in memory at every start and lives as long as the process does.\n", certRenewalWire)
	return nil
}

// localNodeCertPath is where an agent on THIS host keeps its client certificate.
// Read from the agent's own manifest when there is one, so a non-default layout is
// still found; "" when this host runs no agent, which is the split deployment.
func localNodeCertPath() string {
	acfg, err := config.Load(defaultAgentConfigPath, &config.AgentConfig{})
	if err != nil {
		return ""
	}
	path := config.ExpandPath(acfg.Agent.Identity.Cert)
	if _, serr := os.Stat(path); serr != nil {
		return ""
	}
	return path
}

// defaultAgentConfigPath is where a co-located agent's manifest lives. Named here
// rather than inlined so the one place that reads another component's file says so.
const defaultAgentConfigPath = "/etc/wgfleet/agent.yaml"

// humanUntil renders a duration the way an operator reads it: in days, and saying
// so plainly when it has already passed.
func humanUntil(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		return fmt.Sprintf("EXPIRED %d days ago", int(-d.Hours()/24))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// runCertsRenew re-issues one node's certificate out of band, for the case the
// automatic path cannot cover: a certificate that has ALREADY expired, whose node
// can no longer open the mTLS channel renewal would travel over.
func runCertsRenew(cfg *config.ControllerConfig, nodeID string, provider config.SecretProvider) error {
	if nodeID == "" {
		return fmt.Errorf("--certs renew needs a node name")
	}
	ca, err := loadCA(cfg, provider)
	if err != nil {
		return err
	}
	kp, err := ca.IssueNodeCert(nodeID)
	if err != nil {
		return fmt.Errorf("issue certificate for %q: %w", nodeID, err)
	}
	// Under a directory named after the node, the way --issue-node does, rather than
	// two bare filenames in whatever the current working directory happened to be —
	// a git checkout, /tmp, somebody's home — where a live node PRIVATE KEY then
	// stays, unnoticed, with instructions that never mention deleting it.
	outDir := filepath.Join("pki", nodeID)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	certPath := filepath.Join(outDir, "node.crt")
	keyPath := filepath.Join(outDir, "node.key")
	if err := os.WriteFile(certPath, kp.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, kp.KeyPEM, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n\n", certPath, keyPath)
	// The manifest already knows how to reach this node, so print the real target
	// rather than a <node> placeholder the operator has to go and look up.
	target := sshTargetFor(cfg, nodeID)
	fmt.Printf("Install them on %s and restart its agent:\n", nodeID)
	fmt.Printf("  scp %s %s %s:/etc/wgfleet/\n", certPath, keyPath, target)
	fmt.Printf("  ssh %s 'chmod 600 /etc/wgfleet/node.key && systemctl restart wgfleet-agent'\n", target)
	fmt.Printf("\nThen delete the local copy — it is a live node identity:\n  rm -rf %s\n", outDir)
	fmt.Fprintf(os.Stderr, "\nThe old certificate is NOT revoked — there is no CRL. It stops being useful\n"+
		"when it expires; until then both are valid.\n")
	return nil
}

// certRenewalWire is named here so the message above cannot drift from the gate.
const certRenewalWire = pki.NodeCertRenewalWire

// sshTargetFor renders the user@host the manifest already holds for a node, so the
// printed recipe is runnable rather than a template with a placeholder in it. Falls
// back to the placeholder when the node is not in the manifest.
func sshTargetFor(cfg *config.ControllerConfig, nodeID string) string {
	for _, e := range cfg.Fleet.Exits {
		if e.Name == nodeID && e.SSH.Host != "" {
			return sshUserHost(e.SSH.User, e.SSH.Host, e.SSH.Port)
		}
	}
	for _, m := range cfg.Fleet.Masters {
		if m.Name == nodeID && m.SSH.Host != "" {
			return sshUserHost(m.SSH.User, m.SSH.Host, m.SSH.Port)
		}
	}
	return "root@<node>"
}

func sshUserHost(user, host string, port int) string {
	if user == "" {
		user = "root"
	}
	if port != 0 && port != 22 {
		return fmt.Sprintf("-p %d %s@%s", port, user, host)
	}
	return user + "@" + host
}
