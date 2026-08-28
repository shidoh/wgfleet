package main

import (
	"fmt"
	"os"
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

	rows := 0
	for _, c := range []struct{ label, path string }{
		{"controller CA", cfg.Controller.PKI.CACert},
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
	fmt.Fprintf(os.Stderr, "\nNode certificates live ON the nodes and are renewed by their own agents\n"+
		"(wire v%d and above). Watch wgfleet_agent_cert_expiry_timestamp_seconds for the\n"+
		"fleet-wide view; a node whose remaining time stops rising is one to look at.\n", certRenewalWire)
	return nil
}

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
	certPath := nodeID + ".crt"
	keyPath := nodeID + ".key"
	if err := os.WriteFile(certPath, kp.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, kp.KeyPEM, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n\n", certPath, keyPath)
	fmt.Printf("Install them on %s and restart its agent:\n", nodeID)
	fmt.Printf("  scp %s %s root@<node>:/etc/wgfleet/\n", certPath, keyPath)
	fmt.Printf("  ssh root@<node> 'mv /etc/wgfleet/%s /etc/wgfleet/node.crt && "+
		"mv /etc/wgfleet/%s /etc/wgfleet/node.key && chmod 600 /etc/wgfleet/node.key && "+
		"systemctl restart wgfleet-agent'\n", certPath, keyPath)
	fmt.Fprintf(os.Stderr, "\nThe old certificate is NOT revoked — there is no CRL. It stops being useful\n"+
		"when it expires; until then both are valid.\n")
	return nil
}

// certRenewalWire is named here so the message above cannot drift from the gate.
const certRenewalWire = pki.NodeCertRenewalWire
