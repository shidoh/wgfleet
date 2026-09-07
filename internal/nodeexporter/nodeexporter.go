// Package nodeexporter renders the configuration wgfleet manages for the host
// metrics exporter (Debian/Ubuntu's prometheus-node-exporter package).
//
// The fleet had host metrics on three nodes out of seven — the three whose hoster
// happened to ship an exporter — and none on the master, which is the client
// entry point and the known CPU bottleneck. The bootstrap installs the package;
// both bootstrap and the agent's host planner write THESE files, so a reconcile
// pass converges exactly what bootstrap laid down (the same pairing as the sshd
// drop-in and the fail2ban jail).
//
// The exporter binds the management overlay only. Its output lists every
// listening socket, mount and interface on the box, which is a map of the node
// for anyone who can reach the port; the DESIGN rule "metrics only on the mgmt
// address, never the public interface" applies to it as much as to our own.
package nodeexporter

import "fmt"

const (
	// Package is the apt package the bootstrap installs.
	Package = "prometheus-node-exporter"
	// Unit is the systemd service the package ships.
	Unit = "prometheus-node-exporter"
	// Binary is where the package puts the exporter; its presence is how the agent
	// tells a bootstrapped node from one provisioned before host metrics existed.
	Binary = "/usr/bin/prometheus-node-exporter"
	// DefaultsPath is the EnvironmentFile the package's unit reads $ARGS from.
	DefaultsPath = "/etc/default/prometheus-node-exporter"
	// DropInPath is the unit drop-in that makes the exporter survive booting
	// before the overlay address exists.
	DropInPath = "/etc/systemd/system/prometheus-node-exporter.service.d/wgfleet.conf"
	// Port is the exporter's listen port, the node_exporter convention.
	Port = 9100
)

// RenderDefaults renders /etc/default/prometheus-node-exporter binding the
// exporter to mgmtAddr. An empty address falls back to loopback: the package
// default is the wildcard, and "we do not know the overlay address" must never
// turn into "listen on the public interface".
func RenderDefaults(mgmtAddr string) string {
	if mgmtAddr == "" {
		mgmtAddr = "127.0.0.1"
	}
	return fmt.Sprintf(`# Managed by wgfleet — do not edit; the agent re-asserts this every reconcile pass.
# Host metrics are scraped over the management overlay only (see docs/DESIGN.md §9).
ARGS="--web.listen-address=%s:%d"
`, mgmtAddr, Port)
}

// DropIn is the managed unit drop-in. The overlay address the exporter binds
// exists only once ZeroTier has joined, and a bind on an address the kernel does
// not hold yet fails — so the unit is ordered after the overlay and retries
// indefinitely instead of hitting systemd's start limit and staying down until
// someone notices there are no host metrics.
const DropIn = `# Managed by wgfleet — do not edit; the agent re-asserts this every reconcile pass.
[Unit]
After=zerotier-one.service
Wants=zerotier-one.service
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=5s
`
