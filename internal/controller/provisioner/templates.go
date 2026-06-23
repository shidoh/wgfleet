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
// (Phase 1): only SSH, the management overlay (ZeroTier), and the WG port are
// reachable. The agent's reconcile later replaces this with the full per-role
// ruleset — but the master's agent does not re-apply an input firewall, so this
// baseline (which trusts the overlay) is also what keeps the master's mgmt surface
// reachable across reboots.
const baselineNFT = `#!/usr/sbin/nft -f
# Managed by wgfleet — baseline bootstrap firewall. Replaced by agent reconcile.
# Replace ONLY our own table (atomic add/delete/create), never ` + "`flush ruleset`" + `:
# a re-provision must not wipe the agent's live firewall / master NAT / other tables.
table inet wgfleet_baseline
delete table inet wgfleet_baseline

table inet wgfleet_baseline {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		iifname "zt*" accept
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

// fail2banJail is the drop-in jail config installed in Phase 1c-4 (placed in
// jail.d so it overrides distro defaults without rewriting jail.local). It bans
// SSH brute-force sources seen in the systemd journal. It coexists with the
// wgfleet nft ruleset: fail2ban's nftables action manages its OWN table, and a
// ban DROP there is terminal regardless of the wgfleet accept at the same hook,
// so banned scanners are dropped while legitimate (key-auth) logins are never
// touched. %s is the ignoreip list (loopback + the mgmt overlay).
const fail2banJail = `# Managed by wgfleet — SSH brute-force protection.
[DEFAULT]
backend = systemd
banaction = nftables[type=multiport]
bantime = 1h
findtime = 10m
maxretry = 5
# Never ban loopback or the management overlay: the operator and control plane
# reach nodes over it. Key auth never fails so a ban is unlikely anyway — this is
# belt-and-suspenders against self-lockout.
ignoreip = %s

[sshd]
enabled = true
`

// The agent's Prometheus /metrics endpoint binds on the node's mgmt/overlay address
// at config.DefaultAgentMetricsPort by default (kept off the controller's 9300 so a
// co-located controller+agent does not collide). The agent derives that bind from
// agent.yaml's mgmt_addr — no per-node launch flag — so the unit stays generic.

// systemdUnitTemplate runs the agent as a reconcile daemon, restarting on failure.
// %s is an ExecStart flags tail, currently always empty (the unit is generic).
const systemdUnitTemplate = `[Unit]
Description=wgfleet node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml --log-format json%s
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`
