package provisioner

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
