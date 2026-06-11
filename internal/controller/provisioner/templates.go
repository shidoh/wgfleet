package provisioner

// sshHardening is the drop-in sshd config applied in Phase 1: key-only auth, no
// root password login. Placed in sshd_config.d so it overrides distro defaults
// without rewriting the main config.
const sshHardening = `# Managed by wgfleet — bootstrap hardening.
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
`

// baselineNFT is the minimal firewall installed BEFORE the node accepts traffic
// (Phase 1): only SSH, ZeroTier and the WG port are reachable. The agent's
// reconcile later replaces this with the full per-role ruleset.
const baselineNFT = `#!/usr/sbin/nft -f
# Managed by wgfleet — baseline bootstrap firewall. Replaced by agent reconcile.
flush ruleset

table inet wgfleet_baseline {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		tcp dport 22 accept
		udp dport 9993 accept
		udp dport 51820 accept
		icmp type echo-request accept
		icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept
	}
	chain forward { type filter hook forward priority 0; policy drop; }
	chain output { type filter hook output priority 0; policy accept; }
}
`

// systemdUnit runs the agent as a reconcile daemon, restarting on failure.
const systemdUnit = `[Unit]
Description=wgfleet node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml --log-format json
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`
