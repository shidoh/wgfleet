package support

// NodeCollectors returns the observations taken on one node for a support
// bundle. It is deliberately wider than wgfleet's own units, logs and
// interfaces: three of six real diagnoses from one day of operating this
// fleet were about things wgfleet does not own — a third-party unit spinning
// in a busy loop, a stale listening socket bound to an address no longer on
// the interface, a failing third-party timer. A bundle scoped to "just our
// stuff" would have missed or half-missed all three, which is exactly the
// class of problem that cannot be diagnosed remotely by any other means.
//
// Every command here is read-only. None ever runs `awg showconf` or
// `wg showconf` — both print the private key.
//
// `awg show` is NOT self-redacting, whatever this comment used to claim. It hides
// the private and preshared keys and then prints the AmneziaWG 3.x header
// protection key in full; a real bundle from a live fleet carried it, in a file the
// tool tells the operator to send to a tester. The redaction layer is what makes
// this command safe to collect, not the command's own manners — see
// secrets.secretKeyRe, which now knows that name and the space-separated spelling
// every WireGuard tool uses.
func NodeCollectors(role string) []Collector {
	cs := []Collector{
		// identity.txt — what node is this, what is it running, what time does
		// it think it is.
		{File: "identity.txt", Name: "hostname", Cmd: "hostname"},
		{File: "identity.txt", Name: "uptime", Cmd: "uptime"},
		{File: "identity.txt", Name: "uname", Cmd: "uname -a"},
		{File: "identity.txt", Name: "date", Cmd: "date -u"},
		{File: "identity.txt", Name: "timezone", Cmd: "timedatectl show -p Timezone --value"},
		{File: "identity.txt", Name: "agent version", Cmd: "/usr/local/bin/wgfleet-agent --version"},
		{File: "identity.txt", Name: "controller version", Cmd: "/usr/local/bin/wgfleet-controller --version"},

		// network.txt — addresses, routes, firewall, and the sockets actually
		// listening, so a stale bind can be spotted against ip addr.
		{File: "network.txt", Name: "addresses", Cmd: "ip addr show"},
		{File: "network.txt", Name: "routes", Cmd: "ip route show"},
		{File: "network.txt", Name: "rules", Cmd: "ip rule list"},
		{File: "network.txt", Name: "wg routing table", Cmd: "ip route show table 51820"},
		{File: "network.txt", Name: "awg show", Cmd: "awg show"},
		{File: "network.txt", Name: "nft ruleset", Cmd: "nft list ruleset"},
		{File: "network.txt", Name: "listening sockets", Cmd: "ss -ltnp"},
		{File: "network.txt", Name: "conntrack count", Cmd: "conntrack -C"},

		// services.txt — our two units by name, plus every failed unit
		// fleet-wide (not just ours) and the running containers.
		{File: "services.txt", Name: "wgfleet unit status", Cmd: "systemctl is-active wgfleet-agent wgfleet-controller"},
		{File: "services.txt", Name: "failed units (fleet-wide)", Cmd: "systemctl list-units --state=failed --no-legend --no-pager"},
		{File: "services.txt", Name: "containers", Cmd: "docker ps --format '{{.Names}}\t{{.Status}}'"},

		// logs.txt — bounded journal tails for our two units, journal volume
		// and disk headroom (a log-spewing unit is invisible without both),
		// and a per-unit line count over the window so a busy-loop unit that
		// isn't ours still shows up.
		{File: "logs.txt", Name: "agent journal", Cmd: "journalctl -u wgfleet-agent -n 300 --no-pager -o short-iso"},
		{File: "logs.txt", Name: "controller journal", Cmd: "journalctl -u wgfleet-controller -n 300 --no-pager -o short-iso"},
		{File: "logs.txt", Name: "journal disk usage", Cmd: "journalctl --disk-usage"},
		{File: "logs.txt", Name: "disk headroom", Cmd: "df -h /"},
		{File: "logs.txt", Name: "journal lines per unit (last hour)", Cmd: "journalctl --since=-1h -n 20000 --no-pager -o short-iso | awk '{print $3}' | sed -E 's/\\[[0-9]+\\]:?$//;s/:$//' | sort | uniq -c | sort -rn | head -50"},

		// containers.txt — bounded tails of the containers we know this fleet
		// runs (wg-easy included: it runs on masters only, but a missing
		// container on an exit is a normal failure, not an error to chase).
		{File: "containers.txt", Name: "mihomo log", Cmd: "docker logs --tail 100 mihomo 2>&1"},
		{File: "containers.txt", Name: "xray log", Cmd: "docker logs --tail 100 xray 2>&1"},
		{File: "containers.txt", Name: "blocky log", Cmd: "docker logs --tail 100 blocky 2>&1"},
		{File: "containers.txt", Name: "wg-easy log", Cmd: "docker logs --tail 100 wg-easy 2>&1"},
	}

	if role == "master" {
		cs = append(cs,
			// network.txt — the ZeroTier management overlay only masters carry.
			Collector{File: "network.txt", Name: "zerotier status", Cmd: "zerotier-cli listnetworks"},
		)
	}

	return cs
}

// NotCollected is the boundary rendered into every manifest: the files and
// classes of file a support bundle never reads, so a tester can see what was
// deliberately left out rather than only what was taken. Every entry here
// carries a private key, a session key, or the material to derive one.
func NotCollected() []string {
	return []string{
		"controller.yaml — node identities, manifest secrets",
		"agent.yaml — node join material",
		"awg0.conf, wgcf.conf — AmneziaWG/WARP configs (private keys)",
		"mihomo config.yaml — proxy credentials",
		"xray config.json — REALITY/VLESS private keys",
		"wg-easy config and its database — client private keys",
		"node.key — this node's private key",
		"ca.key — fleet certificate authority private key",
		"any file under a sops-encrypted path — sops age/PGP key material",
		"awg showconf / wg showconf output — never run; prints the private key",
	}
}
