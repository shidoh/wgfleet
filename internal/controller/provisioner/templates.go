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
// nftUnitTemplate replays the last rendered ruleset at boot. The file persists at
// /etc/wgfleet/wgfleet.nft; only the kernel state is lost on a reboot, and nothing
// used to put it back until the agent had started, registered AND completed a pass —
// so a node rebooted while the controller was unreachable came up with no wgfleet
// table at all and stayed that way. ConditionPathExists makes it a no-op on a node
// that has never rendered one.
const nftUnitTemplate = `[Unit]
Description=wgfleet firewall (replay the last rendered ruleset)
DefaultDependencies=no
After=nftables.service
Before=network-pre.target
Wants=network-pre.target
ConditionPathExists=/etc/wgfleet/wgfleet.nft

[Service]
Type=oneshot
RemainAfterExit=yes
# A master renders THREE rulesets, not one: the input firewall (both roles), its
# NAT table, and the client-facing IPv6 table. Replaying only the first would put
# the firewall back while leaving clients with no egress — a node that looks
# protected and does not work, which is worse than one that is plainly down.
#
# Applied in a loop over the files that EXIST rather than as three ExecStart lines
# with a leading dash: on an exit both master files are absent, and the dash form
# recorded that as a non-zero ExecMainStatus, so systemctl status reported a
# failure on every healthy exit. A unit whose whole job is to be trustworthy at
# boot must not cry wolf when it worked.
ExecStart=/bin/sh -c 'for f in /etc/wgfleet/wgfleet.nft /etc/wgfleet/wgfleet-master.nft /etc/wgfleet/wgfleet-master-v6.nft; do [ -f "$$f" ] && /usr/sbin/nft -f "$$f"; done; exit 0'
Restart=no

[Install]
WantedBy=sysinit.target
`

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
