# Changelog

What changed for operators in each wgfleet release — behaviour, manifest keys, CLI flags, the console, the scripts in the archive, and the steps an upgrade asks of you.
Every release archive carries this page as `CHANGELOG.md`.
New releases are announced, with the archives attached, in the Telegram channel [t.me/wgfleet](https://t.me/wgfleet).

## v0.3.5 — unreleased

- New manifest key `fleet.masters[].client_vless.last_resort` (default `false`). When set, the master's VLESS goes last in every device profile's `auto` group, after every master's AmneziaWG and every other master's VLESS. Use it for a master whose TCP path is known to be bad. The inbound and the master's own group are unchanged. Restart the controller after editing the manifest; devices pick up the new order on their next profile update.
- MPTCP is off on every listener the fleet runs: the agent, the controller and the xray containers (exit REALITY, client VLESS, REALITY portal). Go opens MPTCP listeners by default, and an MPTCP listener is what the published remote root exploit for the Linux kernel bug CVE-2026-98432 needs. Clients that ask for MPTCP get plain TCP; no fleet client asks for it. The xray compose files change, so every xray container is recreated once after the upgrade; its connections drop for a few seconds. The kernel bug itself is fixed only by a patched kernel (Ubuntu 24.04: 6.8.0-149, 22.04: 5.15.0-203); install it when Ubuntu releases it.
- Release binaries are built with Go 1.27.3. v0.3.4 and earlier archives were built with Go 1.26.0 and lack its security fixes to crypto/tls, crypto/x509 and the HTTP/2 server behind the portal. Upgrade the controller and every agent.
- gRPC 1.85.0 (was 1.82.1): fixes memory exhaustion from fragmented HTTP/2 DATA frames and a server panic on a request without `:authority`. Only a node with a fleet certificate could reach either.
- mihomo on the masters is v1.19.33 (was v1.19.32): a probe answered in under a millisecond is no longer counted as a failure, fake-ip allocations survive a config reload, abandoned DoH queries no longer pile up. The image change restarts mihomo once on every master that does not pin `mihomo_tag`; client connections drop for a few seconds.
- The agent retries a container image change that did not take. Before, if `docker compose up -d` was killed (the agent restarted by a rollout) or failed (an image that did not pull), the compose file was already new, the old containers kept running, and no later pass retried. The agent now records `<compose file>.applied` after a successful `up -d` and runs `up -d` again while it is missing or stale. Applies to the master stack, blocky, the exits' xray, the client VLESS inbound and the REALITY portal. The first pass after the upgrade runs `up -d` once on every stack; for containers that already match it changes nothing.
- An exit that fails one master probe is asked again in the same pass before it is held out of rotation. Before, one probe that reached fewer than two of four destinations — common while a single client's download fills the master's link — took the exit out of `wg-best`, moved a share of sites to another exit and back a pass later, and broke every session pinned to the exit's address. A member that passes the re-ask stays in rotation and the agent logs `exit failed one probe and answered the re-ask; kept in rotation`. A member that fails both is held out as before.
- A client interception move that has confirmed (two clean client-path passes) is reverted to the host path after 6 failing passes (3 minutes) instead of 2. A move that has not confirmed yet still reverts after 2. Before, two missed DNS probes on a busy link recreated mihomo twice and dropped every client connection.
- Masters can use the scanner feed too: `fleet.masters[].as_blacklist: off | observe | enforce` (default `off`). `observe` counts new inbound connections from listed networks and drops nothing; `enforce` drops them. Replies to connections the master or its clients opened are not matched, so clients still reach sites in listed networks. To turn it off, set `off` and restart the controller.
- New metric `wgfleet_fw_as_blacklist_hits_total`: packets opening a connection from a scanner-feed network. Exits with `firewall.as_blacklist: true` report it too; their firewall table is re-applied once after the upgrade to add the counter.
- The scanner feed takes a second source: [sngvy/AntiScanner](https://gist.github.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8), a list of the scanners themselves (GRCHC/CyberOK, Censys, Shodan and others) that C24Be mostly lacks. No manifest change: every node with the feed on fetches it after the upgrade, on its first pass. All sources or none: if one fails to download, the node keeps its last good list.
- New metrics `wgfleet_fw_as_blacklist_source_prefixes{source,family}` and `wgfleet_fw_as_blacklist_source_ipv4_addresses{source}`: what each source gave the last good list, so a source that publishes half its list shows up.
- Dashboard: the top row shows scanner knocks (last hour, and a ranking of nodes over the selected range, and knocks per minute per node, where a one-off sweep at one node shows as a short spike); the inventory row shows the scanner list size by source and per node. Paste `deploy/monitoring/grafana-dashboard-v2.json` into the dashboard's JSON editor to update it.
- The node page and the new metric `wgfleet_node_awg_module_info{node,build,srcversion}` show which AmneziaWG kernel module build each node runs: the `amneziawg-dkms` package version and the module's srcversion. `modinfo` prints the same version for every build, so this was not visible before. The build reads `unknown` until the node's agent is upgraded, when the module was not installed from the package, and while a newer package waits for `prepare-node.sh --upgrade-awg` or a reboot to load it (the node page says `reload pending`). Nothing is gated on it yet. No wire change: an older agent keeps working and reports no build.
- wg-easy is gone. A master with `client_awg.address_pool` always serves its AmneziaWG clients on the agent's `wg0`; without a pool it has no AmneziaWG clients.
    - Manifest keys `client_awg.managed`, `compose.wg_easy_image`, `compose.wg_easy_tag` and `compose.wg_easy_web_port` are ignored: the controller warns `was removed with wg-easy and is ignored`. Delete the lines.
    - `wgfleet-controller --import-wg-easy` and `--wg-easy-db` are removed.
    - Backups no longer carry wg-easy's database; restoring an older archive skips its wg-easy entries with a warning.
    - The node page no longer links to a wg-easy console.
    - The agent no longer creates `/etc/wgfleet/wg-easy-admin-password`. Leftovers from old installs (`/etc/wireguard/wg-easy.db`, `/etc/wireguard/wg0.conf`, `/etc/wgfleet/wg-easy-admin-password`) are not touched; delete them by hand.
    - No restart: the master's container stack renders as before.

## v0.3.4 — 2026-10-26

!!! warning "Read before upgrading: an incomplete `ssh` block stops the new controller"

    **Before the upgrade**

    - Run `--check-config` with the NEW binary from the archive: `./wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config`. The installed one does not know the new rule and passes a manifest the new controller refuses at start: a node `ssh` block with some keys but without all of `host`, `user`, `key_path`.

    **Order**

    1. Controller.
    2. Every master: `deploy-master.sh` for the one beside the controller, the node page's upgrade for the others. The uplink measurement needs both the controller (it hands out the targets) and the master agent.
    3. Exits: rolling upgrade.

    No wire change (14): an older agent keeps working and lacks the new behaviour until it is rolled.

    **After the upgrade**

    - Re-apply `vmrule.yaml` or `prometheusrule.yaml` (six new alerts, six recording rules) and re-import the dashboard.
    - `WgfleetRealityBridgeUnstable` can fire at once on a path that was already freezing: it is the path, not the release.
    - New on disk: exits keep `/var/lib/wgfleet/warp-endpoint.json` once the WARP fallback has picked an endpoint; masters get nftables chains `uplink_syn_out`, `uplink_synack_in` (counters only, policy accept). Rolling an exit agent back loses the pick: wgcf returns to the profile's endpoint.

    **Tell your users**

    - Update the profile in the mihomo app; in Clash Verge Rev, restart the core after the update.

### Added

- Alerts on a master↔exit path that slowly degrades, the way blocking creeps in: `WgfleetMasterPathsDegrading` (two or more exits from one master), `WgfleetExitPathDegrading` (one path), `WgfleetExitDegradingFromAllMasters` (one exit from every master). A path counts when over 10% of the day's probes failed or took over 1 s, it is worse than the other masters' path to the same exit, and it is over twice its best day of the two weeks before. Recording rules `wgfleet:exit_tunnel_bad_share:1d` and `wgfleet:exit_tunnel_bad_share:best_day_14d`. Re-apply `vmrule.yaml` or `prometheusrule.yaml`.
- Every master measures its own uplink: every 30 s it opens a TCP connection to each other master and closes it, and counts the TCP handshakes on the address its traffic leaves with. Metrics `wgfleet_agent_uplink_probes_total{peer,result}`, `wgfleet_agent_uplink_connect_seconds{peer}`, `wgfleet_fw_uplink_handshake_packets_total{direction}`; alert `WgfleetMasterUplinkDegrading` when connects from one master degrade while the other direction stays clean. No manifest key: the controller picks each peer's client VLESS port, else its first `public_tcp_ports` entry. A master agent older than this release measures nothing. Re-apply `vmrule.yaml` or `prometheusrule.yaml`; upgrade the controller and every master.
- Short hold-outs are counted and alerted: `wgfleet_agent_exit_holdouts_total{exit}` counts every time a master takes an exit out of rotation, including those over before a scrape sees `exit_held_out`. Alerts `WgfleetExitFlapping` (two hold-outs of one exit in 6 h) and `WgfleetRealityBridgeUnstable` (a REALITY bridge to one master frozen more than 3 times an hour, for an hour). Dashboard panels "Hold-outs per hour, master → exit" and "REALITY bridge freezes per hour, exit → master" under Master → exit. Re-apply `vmrule.yaml` or `prometheusrule.yaml`; re-import the dashboard.
- An exit whose WARP endpoint stops answering moves to the next one on its own: when `wgcf` has had no handshake for 5 m and that lasts 3 m more, the agent tries `engage.cloudflareclient.com` on ports 2408, 500, 1701 and 4500 in turn and keeps the first that answers, across reboots. Before, an exit whose handshakes to `:2408` were refused stayed without WARP until someone changed the endpoint by hand. A live tunnel is not moved: its handshake never ages past ~3.5 m. No manifest key.
- `--check-config` and the controller's startup log name every manifest key nothing reads, as warnings: a misspelled key (`key:` for `key_path:`) or one indented under the wrong block used to vanish silently.

### Changed

- The device profile's `auto` group tries every master's AmneziaWG before any VLESS (`m1-awg, m2-awg, m1-vless, m2-vless`, was `m1-awg, m1-vless, m2-awg, …`) and checks every 60 s (was 300) over HTTPS; each master's own group checks every 300 s over HTTPS. A stuck AmneziaWG no longer lands the device on VLESS of the same master, and a tunnel that passes small packets but loses large ones now fails the check: the certificate chain crosses it. Tell your users to update the profile; in Clash Verge Rev, restart the core after the update.
- A node's `ssh` block is all or nothing: with any key set, `host`, `user` and `key_path` are required and the manifest is refused without them. Before, it loaded and every provision, upgrade and rollback of the node failed later with `has no ssh target`. Run `--check-config` before upgrading.

## v0.3.3 — 2026-10-16

!!! warning "Read before upgrading: the controller cannot go back without a backup, and clients reconnect"

    **Before the upgrade**

    - Take a controller backup: `wgfleet-controller --backup <file>`. The first start migrates the store; a v0.3.2 controller refuses the migrated store, so going back means restoring that backup. `deploy-master.sh` now also keeps a copy of the store (`state.db.prev`) and restores it when the new controller does not start.
    - Run `wgfleet-controller --check-config`. Now refused: `fingerprint: none` or `random` in `client_vless` or `transports.reality`; `fleet.masters[].dns` alongside `fleet.master_dns` or with two or more masters. A refused manifest stops the controller at startup.

    **Order**

    1. Controller.
    2. Every master: `deploy-master.sh` for the one beside the controller, the node page's upgrade for the others. The rolling upgrade skips masters.
    3. Exits: rolling upgrade.

    Agents are not upgraded on their own: an older agent stays supported and lacks the new behaviour until it is rolled.

    **What drops**

    - mihomo restarts once on every master that does not pin `mihomo_tag` (image v1.19.32): every client of that master reconnects.
    - The master's client xray restarts once where `client_vless` is on: VLESS clients reconnect.
    - Auto-suspended exits return to the load balancer once after the controller restart and are suspended again 5 minutes later; each change restarts mihomo on every master.

    **Tell your users**

    - Update the profile in the mihomo app: the two device-profile fixes below reach a device only then.
    - A VLESS config without its short-id stops connecting: reissue it from the portal.
    - The VLESS fingerprint becomes `chrome` unless the manifest sets one.

### Added

- `fleet.exits[].transports.reality.exit_initiated`: the exit's xray dials every master instead of listening, for exits where TCP the master opens is cut after its first data segment. Each master runs a second xray, `xray-portal`, on `fleet.masters[].reality_portal.listen_port` (derived from the master name when unset), opened world-facing. Wire 14. Procedure and checks: [operations.md](operations.md#exit-initiated-reality).
- Exit health check `reality-bridge` (in the mode, replaces `reality-inbound`), master health check `reality-portal`, metrics `wgfleet_agent_reality_bridge_connected` and `wgfleet_agent_reality_bridge_kills_total`, alert `WgfleetRealityBridgeDown`.
- A watchdog on both ends of the exit-initiated REALITY link kills a connection that stopped receiving (the exit's bridge after 30 s of silence, the master's portal when the bridge stopped acknowledging), so the link redials instead of waiting out TCP retransmission. The agent journal says `killed a silent socket`; the bridge's count is `wgfleet_agent_reality_bridge_kills_total`.
- Several masters: `fleet.masters` accepts more than one. Each master is a peer on every exit's single AmneziaWG interface, on the addresses of its `slot`. With two or more, `fleet.interface_anchor` is required — the validation message gives the value that keeps existing tunnels as they are.
- `fleet.interface_anchor` and `fleet.masters[].slot`. A fleet with one master sets neither and renders as before.
- `fleet.master_dns`: the resolver settings of every master with `dns_filter`, same keys as `fleet.masters[].dns`.
- The console shows every master with its own view of the exits.
- An exit reports each master peer's endpoint and handshake (wire 13). Upgrade the controller first.
- Alert `WgfleetDNSMetricsMissing`: a node the controller knows that no `blocky` scrape target covers. The `blocky` job needs per-target `node`/`role` labels — `deploy/monitoring/vmstaticscrape.yaml` has the template.
- Metric `wgfleet_client_info`: the name and device of each client credential (`kind` awg or vless). The dashboard has a per-client traffic table and a busiest-clients graph: WireGuard on the master and on an exit's lifeline, and VLESS.
- Per-client VLESS traffic: `wgfleet_vless_user_rx_bytes`, `_tx_bytes`, `_online_ips` and `wgfleet_vless_collector_up` from the master agent; alert `WgfleetVLESSStatsUnreadable`. Clients are labelled by a hash of the UUID, never by the UUID.
- Prometheus service discovery on the controller's metrics address: `/sd/wgfleet`, `/sd/node-exporter`, `/sd/blocky`. `deploy/monitoring/vmscrapeconfig-sd.yaml` scrapes the fleet through it, so a new node needs no scrape-list edit.

### Changed

- REALITY ClientHellos from mihomo carry the X25519MLKEM768 key share (`reality-opts.support-x25519mlkem768: true` on the master's exit proxies, in the subscription and in the portal download). With the `chrome` profile this is what Chrome sends; xray 26.9.8 and later refuses REALITY ClientHellos without it. Clients refresh the subscription to get it. The fleet's xray is still 26.6.22, which accepts both: this prepares clients for a later move to 26.9.8, and a client that has not refreshed keeps working until then.
- The master's client VLESS inbound accepts only the short-ids of issued credentials. A public key alone no longer completes the REALITY handshake; a client config without its short-id stops connecting.
- The client VLESS profile's default uTLS fingerprint is `chrome` (was `firefox`): with the key share above it is the only built-in profile xray 26.9.8 and later accepts. An A/B from a home ISP found no difference in blocking between the two. Clients switch on the next subscription refresh; a manifest that sets `client_vless.fingerprint` keeps its value.
- `fingerprint: none` and `random` are rejected for `fleet.masters[].client_vless` and `fleet.exits[].transports.reality`: mihomo cannot dial REALITY without a fixed uTLS profile.
- The master's client VLESS inbound counts traffic per client: xray serves its stats API on `127.0.0.1:10085`. The first agent upgrade restarts xray once; VLESS clients of that master reconnect after a few seconds.
- The Grafana dashboard is rebuilt: firing alerts, clients online and client traffic, DNS, and an exit × master matrix come first; the earlier rows are below, most of them collapsed. New `$master` and `$exit` variables; an "Agent restarts" annotation marks rollouts. Re-import `grafana-dashboard.json` (Grafana ≤12) or paste `grafana-dashboard-v2.json` (Grafana 13).
- Wire contract 14 (13 brought several masters, 14 brings exit-initiated REALITY). Upgrade the controller, then every master, then the exits. An exit on an older agent keeps serving the master in slot 0 only. The controller store is migrated: see the warning at the top of this release.
- `deploy-master.sh` stops the controller and copies its store to `<store>.prev` before installing a new controller, and restores that copy with the previous binary when the new one does not start. `STATE_DB` overrides the store path (default `/var/lib/wgfleet/state.db`).
- Plan output masks every secret in an xray config: all REALITY private keys, SOCKS passwords, VLESS ids and short-ids.
- mihomo on the masters is v1.19.32 (was v1.19.30): fixes for AmneziaWG 3.x tunnels and WireGuard start-up. The image change restarts mihomo once on every master that does not pin `mihomo_tag`; client connections drop for a few seconds.
- wgfleet installs wgcf 2.3.1 (was 2.2.32) on exits, for WARP registration against the current Cloudflare API. Running WARP interfaces are not touched.
- An exit on the new agent edits its master peers in place and checks them against the kernel on every pass; adding or removing a master no longer restarts the interface. An exit on an older agent still restarts it.
- A reserve (lifeline) config is offered only to clients of the master in slot 0.
- `transports.awg.exit_initiated` works with several masters: the state is kept per master and exit. Every master needs a public IPv4; `master_port` applies to the master in slot 0.
- The rolling upgrade rolls an exit first as "reserve" only when every master lists it in `routing.reserve_exits`.
- The "no exit in rotation" alert is per master (label `node`); tunnel alerts join on master and exit.
- A direct route coming or going on an exit on the new agent no longer flushes all of conntrack: only the flows to that destination are dropped. An exit on an older agent still flushes everything.
- Two masters with one WireGuard key (a master built from a copy of another's disk): the master that registers the key second is refused at registration. If both keys are already stored, the exits peer the earlier master in manifest order; the other one is not peered and gets no AmneziaWG tunnel, and the controller logs `two masters present the same WireGuard key`. Before, the two took each other's tunnel down on every exit. Generate a new key on the copy.
- A master removed from the manifest is listed on the fleet page under NOT IN MANIFEST and can be deleted from its node page. The delete removes its client credentials (WireGuard and VLESS) and their device attachments. A master that is still in the manifest cannot be deleted.
- The address an exit confirmed for `exit_initiated` is stored. A controller restart no longer disarms the master's gate or restarts the wait before a silent tunnel's port is moved.
- A store read error while rendering an `exit_initiated` tunnel fails the render; the node keeps its last spec. Before, the tunnel was handed its first port again.
- `--check-config` prints the anchor label, the base master and every master's slot, and warns when several masters run without `fleet.mgmt_subnet`.
- The manifest is refused when `fleet.interface_anchor` is `clients`, `lifeline` or holds whitespace or `|`.
- The manifest is refused when `fleet.masters[].dns` is set with two or more masters, or alongside `fleet.master_dns`. Move the block to `fleet.master_dns`. A fleet with one master and `masters[].dns` loads as before.
- `--check-config` and the controller's startup log warn when an exit is given more than 80 direct rules (`routing.direct_cidrs` of the master in slot 0, the management CIDRs and one per other master). The manifest still loads; an exit with WARP egress cannot apply its routing past that count.
- The controller logs which master holds an exit at AmneziaWG 2.0 when `awg3` is on.

### Fixed

- The device profile for mihomo apps sends each proxy's own server — its address, port and network only — `DIRECT` ahead of every other rule. ClashMetaForAndroid protects its core's sockets from its own VPN only once the tun is up; the AmneziaWG socket opened at start was not protected, its packets came back through the tun and `MATCH` sent them into the same proxy. AmneziaWG was dead after most app starts, the app fell back to VLESS and switched back and forth, and connections stalled at 0 B/s. Other apps never match the new rules. Update the profile in the app to pick it up.
- `exit_initiated`: a tunnel could stay off the master's pinned port with the gate reading armed — after the pin was armed over a running tunnel, after the pinned port moved, or when the exit's endpoint still named the port the master used before the pin. The master agent waited for a knock the exit could not send while the master kept answering from the old port. The master now refuses any flow the exit opens from its AmneziaWG port and deletes a flow off the pinned port at once; the tunnel is back on the pinned port within one exit agent pass (about 30 s without traffic through that exit).
- A controller restart no longer returns an auto-suspended exit to the load balancer. The suspension is stored; before, the exit went back into rotation at once and was suspended again five minutes later, and each of the two changes restarted mihomo on every master, dropping client connections. The first upgrade to this release still returns suspended exits once.
- `exit_initiated`: switching an exit back from REALITY to AmneziaWG, or an exit returning from auto-suspend, no longer moves the master's pinned port at once. The tunnel had been idle, and its stale handshake was read as a silent port; it now gets five minutes to handshake first.
- A controller that cannot read its own state while rendering a node's spec (a database read error) now answers the agent as unavailable, and the agent keeps reconciling on its last spec. Before, the agent took it as a refusal: the node showed Error and applied nothing that pass. The controller journal now has a line for every spec it could not render (`spec not rendered`).
- A decommissioned node no longer rebuilds itself when the controller is unreachable. Its agent kept the last live spec on disk and converged on it whenever the controller did not answer; the cached spec is now removed once the teardown completes.
- An exit with WARP egress kept the `ip rule` of a direct destination that left its list (a master removed from the manifest, a shortened `direct_cidrs`): client traffic to that address went on leaving direct. The rule is now removed. A rule left behind earlier is removed on the next agent pass.
- Re-provisioning a node that is already running (`--provision`, the Provision button) no longer leaves it behind the bootstrap firewall. Before, when the node's own ruleset had not changed, the bootstrap table stayed loaded and dropped every new connection except SSH and the overlay — on the stand a master stopped answering new clients — until the ruleset next changed or the node rebooted. The agent now removes it within one pass.
- Changing an exit's `egress` in the manifest takes effect without restarting its agent. Before, the exit could stay on the egress the manifest no longer listed.
- The device profile for mihomo apps gives the AmneziaWG proxy `allowed-ips: 0.0.0.0/0` instead of the split list of the `.conf`. Before, with `client_awg.exclude_from_tunnel` set, a `fleet.client_sites` network was unreachable while the device was on AmneziaWG, and `<site>-auto` fell to `DIRECT` away from the site. Update the profile in the app to pick it up.
- An agent upgrade, rollback or re-provision that cannot open SSH to a node's `ssh.host` tries the node's `mgmt_addr` with the same port, user and key. Before, an exit whose public SSH path was cut failed the rollout with `ssh: handshake failed: i/o timeout` while it stayed reachable over the mgmt network.
- The ROLLING AGENT UPDATE panel in the console stays open once opened. Before, the page's refresh closed it every 15 seconds and at the end of a run.
- The mihomo dashboard on the master (`external_controller`) opens for a device connected over the VLESS profile when its port is in `client_admin_ports`. Before, the same URL answered over AmneziaWG and returned an empty reply over VLESS.

## v0.3.2 — 2026-09-30

!!! note "New: the exit can start the master↔exit AmneziaWG tunnel"

    For exits whose path cuts flows the master opens and passes flows the exit opens. On such a path a flow the master starts barely gets through, while a flow the exit starts passes cleanly.

    - Per exit, off by default: `fleet.exits[].transports.awg.exit_initiated: true`.
    - The exit knocks on a pinned UDP port of the master; the master answers only from that port and only after it has heard the exit.
    - The tunnel comes back on its own after a mihomo restart, an agent restart, a master reboot and a ban on the path.
    - When the path poisons or freezes the pinned flow, the controller moves the port itself after 5 minutes without a handshake, and the exit opens a new flow. Recovery took 4–6 minutes on a test bench that emulated those filters.
    - Needs: controller, master agent and exit agents on this release; one master with a public IPv4; `conntrack` on the master.
    - REALITY is not affected. Client configs do not change, nothing to reissue.
    - How to switch it on, check it and switch it off: Operations, section "Exit-initiated AmneziaWG flow".

### Added

- `fleet.exits[].transports.awg.exit_initiated` and `fleet.exits[].transports.awg.master_port` (the pinned port; derived from the master and exit names when unset).
- Master metrics `wgfleet_agent_awg_pin_armed`, `wgfleet_agent_awg_exit_heard`, `wgfleet_agent_awg_exit_heard_age_seconds`, `wgfleet_agent_awg_gate_drops_total`, and the `WgfleetAWGExitNotHeard` alert in the archive's rules.

### Changed

- Wire contract 12. Upgrade the controller first, then the master agent, then the exit agents.
- `prepare-node.sh` installs `conntrack`. On nodes prepared earlier: `apt-get install conntrack` on the master.
- The master's REALITY XHTTP proxy to an exit with `transports.reality.mux: true` holds at most 3 connections to it. Some path filters ban an address for minutes once a client holds more than about 4 parallel connections to it.

### Fixed

- The master agent finds leaked mihomo WireGuard devices again while mihomo runs in its own network namespace, and restarts mihomo to clear them. Before, a reload that leaked a second device to an exit went unnoticed and the tunnel to that exit flapped.

## v0.3.1 — 2026-09-29

### Added

- `fleet.client_sites`: the operator's own networks (home, office) in the device profile get a switch — `DIRECT` while a probe inside the site answers directly, through the tunnel when it does not, with a manual override in the app. Without it those networks stay `DIRECT` as before. mihomo apps only; the AmneziaWG `.conf` is unchanged.

### Changed

- Client DNS is `enhanced-mode: fake-ip` in the device profile and in the Clash `.yaml` download (was `redir-host`), with a filter that still answers every name with its real address. On macOS, Clash Verge Rev moves the system resolver into the tunnel only under `fake-ip`; with `redir-host` a router's DNS stayed in place and every name the OS looked up went past the tunnel. `dig` and `nslookup` keep showing real addresses. Users update the profile in the app.
- Device profile IP rules no longer carry `no-resolve`, so a name that resolves to a private address still follows `route_through_cidrs` or the local-network rule.

### Fixed

- The master returns from the reserve tier once the primary tier is alive again. Before, dead primary exits used up the probe time and the live ones were counted as down, so traffic could stay on the reserve tier indefinitely.
- A new exit, or one whose WARP account is re-registered, brings its `wgcf` interface up. Current `wgcf` writes both addresses on one `Address` line, which the agent rejected as an incomplete profile and then failed every pass.

## v0.3.0 — 2026-09-27

!!! warning "Read before upgrading: this release changes what clients see and cannot be rolled back without a backup"

    **Before the upgrade**

    - Take a controller backup: `wgfleet-controller --backup <file>`. The first start migrates the store (existing AmneziaWG credentials become devices); an older controller refuses to open the migrated database, so going back means restoring that backup.
    - Run `wgfleet-controller --check-config` on your manifest. A new warning names every master whose `exclude_from_tunnel` hides the client portal or the mgmt overlay from AmneziaWG — devices there cannot refresh their subscription over AmneziaWG.
    - Check what is listed in `client_admin_ports`: those ports are now reachable by VLESS clients too, not only AmneziaWG clients. The portal port must be there for subscriptions to refresh.

    **What your users will notice — tell them**

    - `/sub/<master>/<uuid>` (the v2rayTun subscription) is gone. Hand out a device link or the plain `vless://` link instead.
    - Their `/c/<id>` portal page now leads with a mihomo subscription link; the AmneziaWG `.conf` is under "AmneziaWG app instead". The links they already have keep working.
    - A new device's first profile comes as a `.yaml` file from you (console → **Devices** → **Download profile (.yaml)**); after connecting they add the subscription link from the portal and remove the file profile.
    - **One app at a time.** The AmneziaWG app and a mihomo app with the device's profile share one key. Running both — even with the mihomo app's TUN off — breaks the connection every few seconds. Once the mihomo app connects, turn the AmneziaWG app off.
    - Edits made inside the subscription profile are lost at the next update. Own rules go into the app's layer on top of the profile (Clash Verge Rev: Merge).

### Added

- Client devices: one link per device serves a mihomo profile with AmneziaWG and VLESS proxies on every master, automatic fallback, internal networks and internal names. Console → **devices**; tested apps: FlClash, ClashMetaForAndroid, ClashX Meta, Clash Verge Rev.
- **Download profile (.yaml)** on a device's page, for the first import on a device that cannot reach the portal yet.
- Existing AmneziaWG credentials become devices on the first controller start; links already handed out keep working.

### Changed

- The Clash config download for VLESS clients resolves over TCP :53 through the tunnel instead of DNS-over-TLS.
- A credential attached to a device loses its own portal link for good; hand out the device link.
- `client_admin_ports` now also opens on mihomo's namespace veth, not only the client AWG interface: a VLESS client's connection to those ports (the portal among them) is dialled DIRECT from the namespace and arrives there, not on AWG — so a device on VLESS alone can still reach it.
- Existing `/c/<id>` portal pages now lead with the mihomo subscription link and QR; the AmneziaWG `.conf` moved under a collapsed "AmneziaWG app instead" details block instead of being the page's main offer.
- Console: **Nodes** and **Devices** are the top bar's sections; devices moved out of the account links.
- Device page: hand-over steps, then one slot per transport and master. An occupied slot offers only **Detach**; an empty one offers **Add** (issue new or attach). A new device issues both credentials by default.
- The portal page warns against running the AmneziaWG app together with the mihomo app, and that edits inside the profile are lost on update.
- The portal page fits a phone screen: it was wider than a 390 px screen and scrolled sideways.
- The profile download carries `filename*` (RFC 6266) next to `filename`: Clash Verge Rev names an imported profile correctly instead of `\"name.yaml\`.
- The console links its stylesheet and scripts by content hash: after an upgrade the browser loads the new ones at once instead of drawing the new pages with the cached old stylesheet for up to an hour.

### Removed

- **Breaking:** `/sub/<master>/<uuid>` and the v2rayTun routing object. Move v2rayTun users to a device link or to the plain `vless://` link.

## v0.2.7 — 2026-09-25

A node's own certificate rotation can no longer leave it holding a key nobody certifies, host metrics stop being a reason a node falls into `Error`, and a slow probing phase no longer pulls healthy exits out of the load balancer.

### Added

- Count this node's certificate rotations as `wgfleet_agent_cert_renew_total{result}` and failed re-reads of its certificate and key from disk as `wgfleet_agent_cert_reload_errors_total`. A failed re-read keeps the agent on the pair it loaded at startup and logs that the next restart will not be able to load the files on disk.
- Alert with `WgfleetNodeCertRenewFailing` when every renewal attempt in 3 hours failed — months before `WgfleetNodeCertExpiring` — and with `WgfleetNodeCertUnloadable` when a node's own pair failed to load from disk. Both are in `deploy/monitoring/`; re-apply the rule file.

### Changed

- Treat host metrics as an optional component: when something already serves node metrics on the node's mgmt-overlay address — the distribution package, a binary of your own, any version — the agent and the provisioner leave it alone instead of installing, enabling or starting `prometheus-node-exporter`. Upgrading that exporter is yours. An exporter of your own listening on a wildcard or public address is named in the node's plan with the address to bind it to; the packaged one is rebound to the mgmt address.

### Fixed

- Keep a failed certificate rotation where it began: the new pair is verified before anything is written, and a certificate write that fails puts the previous key back. A key that exists but cannot be read stops the rotation before it starts; the current pair keeps authenticating and the next pass tries again.
- Make every file the agent writes atomically durable across a power loss: the directory is fsynced after the rename.
- Spend the master's probing budget by skipping members that no longer fit, never by cancelling a probe in flight. A cancelled probe was recorded by mihomo as a dead exit and silently removed it from `wg-best`.
- Stop a masked or missing `prometheus-node-exporter` unit from holding a node in `Error`; in that state every self-check and an exit's egress failover were cancelled with it.
- Print the changelog link in full in the release announcement.

## v0.2.6 — 2026-09-11

The console says why an exit stopped carrying traffic instead of only that it did, a rolling upgrade can no longer be held hostage by one wedged node, and the reserve configs from v0.2.5 survive a reboot, a split-tunnelled master and a credential being issued.

### Added

- Show the master's own verdict on every exit it is not routing through, on the fleet panel and on the exit's node page: **out of rotation `12m` · probes `0/3`** for an exit its multi-destination probe pulled from the load balancer, **no usable path** for a reserve-tier member the warm probe could not reach the internet through. A green `Ready` beside the badge is not a contradiction — the state pill is the node's own self-checks, the badge is the tunnel to it. An agent older than this release reports no verdict and gets no badge.
- Report each reserve-tier member's own probe result as `wgfleet_agent_standby_tier_member_usable{exit}`, with the `WgfleetStandbyTierMemberUnusable` alert. One dead reserve exit used to hide inside "2 of 3 usable", which is a tally nobody can act on.
- Collect the lifeline interface like every other one (`wgfleet_wg_*` per interface) and alert with `WgfleetLifelineCheckMissing` when no exit reports a `lifeline` health check at all — the failure mode a per-node check cannot see.
- Override what a reserve config routes into the tunnel with `fleet.exits[].lifeline.allowed_ips` (IPv4 only, default `0.0.0.0/0`).

### Changed

- Bound a rolling upgrade at every step: `--node-timeout` (default `5m`) covers one node's upload, install and restart; an SSH dial that connects and then swallows everything is abandoned 20 s into the handshake; a node that fails is reported by name and skipped instead of stopping the run. A node whose SSH never opens keeps the agent it had and is never downgraded.
- Add and remove client peers on the live interface instead of bouncing it: pausing or revoking one credential no longer takes every other session on that interface down with it — on a lifeline, everyone there because their normal path is already gone.
- Hand out a reserve config only while the exit reports its lifeline healthy — an offer the exit cannot honour is worse than no offer, because it is taken at the moment the master is already gone.
- Give a reserve config a full tunnel instead of the master's split-tunnel routes, which wg-quick cannot install on a client.
- Replace wgcf on re-provision when the version this build pins differs from the one stamped on the node, instead of skipping the install because some wgcf is already there.
- Pin blocky to `v0.35.0` instead of the moving `latest` tag; override per node with `dns.tag`.

### Fixed

- Keep the lifeline's deferral until the interface actually comes up, so a failed bring-up is reported rather than recorded as done.
- Persist `ip_nonlocal_bind`, so after a reboot the resolver on a lifeline exit can bind the gateway address again.
- Update `golang.org/x/*` and gRPC for the reported vulnerabilities.

## v0.2.5 — 2026-09-08

An exit can carry a reserve client-facing interface, so every credential gets a second profile to switch to when the master stops answering.

### Added

- Give an exit a reserve client-facing AmneziaWG interface with `fleet.exits[].lifeline` (`listen_port`, `address_pool`, `egress: direct|warp`, `dns`, `mtu`); it carries the same credentials the master serves, at the same host offsets shifted into its own pool, with a preshared key derived per exit. Requires `masters[].client_awg.managed: true`.
- Hand out a reserve config per lifeline exit from each credential's card in the console and from the self-service page a user already holds; the console lists every declared exit with the reason one cannot yet hand out a config, the self-service page lists only the ready ones.
- Report the reserve interface with a `lifeline` health check on the exit's node page. It reads the agent's own reason for not applying a spec before it looks at the interface, so an `awgl0` still serving an older config is not reported healthy.

### Changed

- Rewrite the documentation as a reference: configuration, operations, quickstart, onboarding, upgrade, client migration and support bundle are tables, steps and commands, and every manifest-driven section shows the YAML that switches it on beside a link into the key reference.
- The controller↔agent wire moves to v11, carrying the lifeline interface and its firewall port. An agent below v11 is rendered no lifeline at all rather than a firewall hole in front of a listener it cannot raise; the controller says so once per exit in its log.
- Every exit now carries two `DOCKER-USER` accepts naming `awgl0` and generates and publishes a lifeline key each pass, whether or not a lifeline is configured: the rules name an interface that may not exist and the key is cheap, and both being there already is what makes enabling a lifeline a pure manifest edit with nothing to wait for.

### Fixed

- Redact the lifeline block in a node's raw spec view: every projected credential's preshared key and the interface's header-protection key were shown in full, where the master's own client interface had been redacted all along.

## v0.2.4 — 2026-09-08

A master still served by wg-easy survives an AmneziaWG module upgrade, the namespace move works on Ubuntu 22.04, and both binaries gain five log levels switchable on a running process.

### Added

- Upgrade a node's AmneziaWG module and tools with `prepare-node.sh --upgrade-awg`; it moves both packages together through the agent's own apt hold and reloads the module; interfaces the agent renders come back on its next pass.
- Run the wg-easy image that matches the kernel module's generation (v15.3.0 on a 1.x module, v15.4.0 on 3.x), read every reconcile pass; the client interface returns with the same key within one pass.
- Add five log levels to the agent and the controller (`agent.log_level`, `controller.log_level`, `--log-level`: `trace`, `debug`, `info`, `warn`, `error`); `SIGUSR1` steps a running process one level more verbose, `SIGUSR2` returns it to the configured level.
- Log a summary of every applied action, and name which config keys moved when mihomo is reloaded.
- Drain an exit from the manifest with `fleet.exits[].drain: true`; the console shows it as *drained by config* and will not undrain it.
- Export host metrics from every node, expose mihomo restarts, and add a client-path row to the Grafana dashboard.
- Carry the versions a diagnosis turns on in the support bundle (nftables, module and its srcversion, tools, dkms, apt holds, Docker) plus the namespace-move state.

### Changed

- Drop design-note references and rationale from console copy, help text and the headers of rendered files; the console now says what a control does, not why it exists.
- Default the client and exit I-packet prologue to a per-end STUN+QUIC cover, chosen after testing on mobile networks; the previous plain-noise default fared worst on mobile.
- Earn an exit's auto-suspend with minutes of evidence rather than passes, and measure egress throughput against several independent targets instead of one speed-test page.
- Name the console buttons Drain and Undrain, label the topology's second group NOT CARRYING instead of RESERVE, and show a decommission the node cannot carry out as stuck, with Delete as the way out.
- Move client interception into mihomo's namespace only when it can be watched: no move while wg-easy owns the client interface, no verdict from a pass in which nothing was measured or the interface was down, readiness satisfied by any reachable exit, and the prober resolving where the clients resolve; a revert names the probes that failed.

### Fixed

- Client interception moves into mihomo's namespace on Ubuntu 22.04: the moved-state NAT ruleset used a chain priority nftables 1.0.2 rejects, so every move silently reverted; priorities are rendered numerically, checked for portability before every write, and a rejected ruleset now reports its component unconverged with the reason.
- Keep a deleted node deleted: its next registration is refused until an operator provisions it again, instead of re-creating its own row within a minute.
- Stop the AmneziaWG apt pin failing the whole pass on a node whose module is not from the PPA.
- Judge a node's come-back after a rolling upgrade against its pre-upgrade state, not against Ready.
- Warn when a file rule provider in `mihomo.overrides` points at a file the node does not have.

### Docs

- Rewrite the operator documentation for the closed beta: no internal references, no incident history, every page written for a reader without repository access.
- Publish the operator documentation as a site at <https://shidoh.github.io/wgfleet-docs/>, built from the same pages the archive ships.
- Add `REQUIREMENTS.md`, the system requirements and compatibility page: Ubuntu 24.04 supported, older releases best effort, plus the versions the platform pins.
- Add "AmneziaWG is down: where to look" and the module upgrade runbook to `OPERATIONS.md`.

## v0.2.3 — 2026-09-06

### Changed

- Apply a changed `mihomo.client_via_netns` decision at once instead of waiting out the interval.
- Adopt a namespace move that is already in place at agent startup instead of tearing it down and rebuilding it.
- Isolate a failing component in the reconcile engine so it no longer takes the rest of the node down with it.
- Page on the guard that must be zero, not on the one that catches stragglers, in the shipped alert rules.
- Write every key and cached spec atomically, so an interrupted write cannot leave an empty key file that wedges the node.

### Fixed

- Let REALITY/VLESS clients resolve DNS again: the client resolver is handed out and firewalled end to end as DNS-over-TLS (`tls://`, port 853); a namespace firewall that trusted the resolver only on plain port 53 had silently black-holed their DNS.
- Stop dropping client QUIC, DNS and ICMP after the namespace move, and make the master's admin/dashboard port reachable through the tunnel again.
- Withdraw the host TPROXY relics after the move, floor the veth MTU, and count guard drops on a metric.
- Close mihomo's own listeners to clients and narrow the host's trust in the namespace veth.
- Tell an unanswered client-path probe from a negative one, and refuse to install a half-rendered namespace firewall.

### Docs

- Add "Kernel upgrades (your call, not ours)" to `OPERATIONS.md`: what Ubuntu does by default, the kernel/DKMS constraint, and what the platform will not touch.

## v0.2.2 — 2026-09-05

Client UDP reaches the client again: interception moved into mihomo's own network namespace, on by default and self-reverting.

### Added

- Move client interception into mihomo's network namespace (`fleet.masters[].mihomo.client_via_netns`, default `auto`); the master verifies the client path from its own client peer end to end and reverts the move on its own if the path stops verifying. `off` converges back to host interception.
- Ship `mihomo-ns.sh` and `netns-move-check.sh` in the archive for inspecting and watching the namespace move.
- Probe an exit's backup transport and show in the console whether it is usable.
- Export master↔exit tunnel health and the state of the exit tier as metrics; narrow the rotation alerts and panels to the tier that carries traffic.
- Add a Grafana dashboard in the Grafana 13 schema beside the classic one.
- Count mihomo's own error output as a metric instead of leaving it in the container log, and bound the container log so it stops eating disk.
- Assert, as a health check, that no UDP port the node holds black-holes client traffic.

### Fixed

- Stop silently dropping every client QUIC flow (YouTube, Google, any HTTP/3 site): replies to client QUIC no longer collide with the client interface over a port.
- Keep a probe-evicted exit out of rotation instead of handing it back to mihomo.
- Stop a busy dpkg lock failing the whole reconcile pass.
- Clamp the management-overlay MSS in both directions.
- Check an nft ruleset before writing it and keep the previous one as the way back.
- Stop a cancelled probe stamping an exit as down, and bound the probe phase.
- Keep the control API reachable at its address through the move, and redirect it on every door it was reachable from.

## v0.2.1 — 2026-09-01

### Fixed

- Follow the manifest when a node's public address changes: after the `public_ip` edit and a controller restart, the tunnels are re-rendered at the new endpoint instead of staying pinned to the old one.

## v0.2.0 — 2026-08-31

The client interface can move from wg-easy into the controller, AmneziaWG 3.x arrives behind an opt-in, agents renew their own certificates, and a node survives a controller that is down.

### Added

- Manage the client AmneziaWG interface from the controller (`fleet.masters[].client_awg.managed`): issue, pause, rename and revoke credentials in the console, hand each client a self-service portal link (`controller.client_portal`), and give every client its own obfuscation decoy. Import an existing wg-easy database with `--import-wg-easy <master> --wg-easy-db <path>` (dry run with `--plan`). Follow `CLIENT-MIGRATION.md` before enabling it on a live master; the agent adopts wg-easy's interface key, and retires wg-easy only after the managed interface is observed up.
- Add `client_awg.exclude_from_tunnel` to keep private networks out of the client tunnel (refused if it would cut clients off from their gateway or DNS), and `client_awg.keepalive` as one value or a per-credential band.
- Add AmneziaWG 3.x behind an opt-in: `fleet.awg3` / `fleet.exits[].awg3` for the master↔exit tunnels and `client_awg.awg3: timers|full` for the client interface. Header protection needs `fleet.awg3_key`, which the controller refuses to start without once it is required; run `--check-config` before the restart. `full` means every client must re-import.
- Renew each agent's control-plane certificate automatically between 70% and 90% of its lifetime, with `--certs check-expiration` and `--certs renew` for the out-of-band case, plus a certificate-expiry metric and alert. Agents from before this release never renew: roll them before their certificates age out.
- Converge on the last-good spec when the controller cannot be reached, and replay the last rendered firewall at boot, so a node that reboots while the controller is down comes back converged.
- Add `--check-config` so a bad manifest is caught before it can crash-loop the control plane, and report when the running config differs from the file on disk.
- Carry client UDP through mihomo with TPROXY instead of leaking it, and answer client IPv6 with an audible refusal instead of a silent bypass; the console shows whether IPv6 is blocked and whether client UDP is carried.
- Add `fleet.hardening.sshd` and `fleet.hardening.fail2ban` (fleet, master and exit level) as the opt-out from managed sshd and fail2ban, `fleet.masters[].whitelist` as the master-side firewall source whitelist, and `public_udp_ports` for masters and exits beside the existing `public_tcp_ports`.
- Enable TCP MTU probing on every node so a PMTU black hole cannot wedge a connection, and throttle self-heal restarts so a broken service is not bounced forever.
- Log every console action that changes fleet or credential state.
- Ship alert rule templates in the archive's `monitoring/` (`vmrule.yaml`, `prometheusrule.yaml`), and replace the node spec text dump with a summary card and collapsible detail sections.

### Changed

- Replace I-packet protocol mimicry with opaque noise; measurement showed the mimicked QUIC/STUN/DTLS gave DPI more to key on than noise does.
- Shift the AmneziaWG junk window past the S4 floor and derive the keepalive period per tunnel end; the shift bounces every master↔exit tunnel once during the rollout.
- Keep the shipped systemd units at systemd's defaults and drop the controller's start limit, so a crashing controller keeps retrying instead of needing a manual reset; re-copy the units from the archive's `systemd/` if you installed them by hand.
- Bump mihomo to v1.19.30 and metacubexd to v1.273.0; a mihomo config that mihomo rejects is rolled back instead of left in place.
- Rebuild the clients page around scanning: a scannable QR behind its own control, the portal link surfaced, the client app named, "Pause access" instead of "Mute", and AWG named as AWG throughout the console.
- Confirm every destructive console action on the server, not only in JavaScript, and enforce the exit-only routing lifecycle server-side.
- Skip nodes that are down in a rolling upgrade, refuse a rollout while no controller is serving, and confirm the node came back on every path that upgrades an agent.

### Fixed

- Stop the console leaking client preshared keys and the 3.x header-protection key, forbid caching on every page that carries or lists a credential, and stop the support bundle shipping the header-protection key in cleartext.
- Carry the fleet secret and the REALITY key in a backup, name what cannot travel, validate a restore before writing, restore only to the paths this host's own configuration names, accept an age identity for a recipient-encrypted archive, and warn when `age` is missing.
- Make the console Upgrade button and the wire-version self-upgrade actually run (both had deadlocked against their own lock since they were added), and do not roll back a node the upgrade never reached.
- Survive SIGHUP in both binaries, and retry the controller's HTTP binds until the overlay address is up instead of reporting healthy with none.
- Resolve mihomo's own lookups only through the fleet resolver, never in the clear to a public one, while keeping that resolver a preference rather than a hard dependency of forwarding.
- Detect firewall and nft drift by content rather than by a table merely existing, self-heal the transparent UDP listener as well as the TCP one, and reverse everything teardown installed.
- Remove the WARP policy routing when egress fails over to direct, and delete every egress rule on teardown, not only the first match.
- Write operator-supplied `extra_files` that carry secrets with mode 0600 so they stop wedging reconcile.
- Apply a revoke of the last remaining credential instead of refusing it forever, and fail a spec render that cannot read its inventory or tunnel keys rather than de-issuing every VLESS client.
- Survive a controller rollback without bricking the store schema, and never render a client interface with no peers on a store failure.
- Refuse two CLI subcommands at once, honour `--store`, refuse a bare `--plan`, list every certificate the host holds, apply `controller.agent_bin` on the CLI provisioning path, and refuse a bootstrap with no agent binary.
- Let the console delete a node the manifest declares but the store never knew.
- Keep the guides when `install.sh` installs straight off the internet, and stop macOS extended attributes turning every unpack into a wall of tar warnings.

### Docs

- Ship `CLIENT-MIGRATION.md`, `MANIFEST.md`, `ONBOARDING.md`, `CLI.md`, `OPERATIONS.md` and `SECURITY.md` in the archive, with every intra-doc link rewritten to the archive's names so each guide works from the tarball alone.
- Correct the upgrade and master-migration guides against what the code does, and give the check that decides the client cutover its own step.

## v0.1.7 — 2026-08-05

### Added

- Write a read-only diagnostic archive with `wgfleet-agent --support-bundle` (with `--note <text>`), and walk every exit from the controller with `wgfleet-controller --support-bundle --fleet`; secrets are masked, and a value the scrubber cannot mask makes the bundle refuse to write.
- Ship `client-diag.sh` for diagnosing a problem from the client's side, and `SUPPORT-BUNDLE.md` as its runbook.
- Render the fleet topology as a vertical trunk and bus, with exits partitioned into carrying and reserve.

### Fixed

- Select rolling-upgrade targets against the binary being pushed, not the controller's own version, and stop the rollout panel listing the same nodes twice.
- Bound the fleet walk's SSH commands and per-exit budget so one unreachable exit cannot stall the bundle.
- Cap tracepath hops so the WARP path-MTU probe terminates.
- Stop a SIGPIPE failing `prepare-node.sh`'s module and ZeroTier checks, and cap the systemd journal during OS prep.

### Docs

- Add `MASTER-MIGRATION.md`, the runbook for moving a master to a new host.
- Bring the reference docs up to what the code does, and stop calling the fleet's tunnels WireGuard where they are AmneziaWG.

## v0.1.6 — 2026-07-29

### Changed

- License the project under AGPL-3.0 and ship `LICENSE` and `DISCLAIMER.md` in the archive.
- Answer DNS-filtered names with NXDOMAIN instead of `0.0.0.0`, and shorten the block TTL to one minute so filter changes are not pinned for six hours.

### Fixed

- Guard the master's and each exit's egress against private-source leaks, and drop invalid transit on exits.
- Stop the controller rewriting and logging unchanged registrations.
- Pin the WARP path-MTU probe to IPv4.
- Surface scheduled probes that never succeed as a metric.

### Docs

- Ship the complete configuration reference as `CONFIGURATION.md` and the Grafana dashboard and scrape configs in the archive's `monitoring/`.
- Stop the installer's closing summary and the generated `controller.yaml` pointing at files that are not in the archive.
- Record the AmneziaWG 3.0 readiness verdict and its gating conditions.

## v0.1.5 — 2026-07-25

### Changed

- Reconcile SSH hardening and fail2ban every pass instead of applying them once at bootstrap, so a hand-edit drifts back.
- Write the fleet manifest owner-only (0600).

### Docs

- Ship the RU/non-RU split-tunnel and DNS-filter recipe in the archive as `examples/RU-SPLIT-TUNNEL.md` with its manifest `examples/controller-split-ru.yaml`, deepened with production hardening.
- Sync the README with the client VLESS metrics and health check and with `public_tcp_ports`.

## v0.1.4 — 2026-07-23

### Changed

- Stamp the release version into the archive filename.
- Announce each release in the Telegram channel with the archives attached.

### Fixed

- Restore the capability the exit's REALITY container needs to bind a privileged port, so a REALITY listener below 1024 comes up again.

## v0.1.3 — 2026-07-22

### Added

- Add a client-facing VLESS+REALITY+XHTTP transport on the master for clients whose AmneziaWG is throttled, with `fleet.masters[].client_vless.mode` (`xhttp` or `vision`), `fingerprint` (default firefox), `mux` (on by default) and `allow_ipv6`.
- Redesign the clients page: larger QR codes, the VLESS link as the primary hand-out, a collapsible subscription with embedded routing, and a Clash config download.
- Expose the client VLESS listener as a health check and a per-master client count metric, with a Grafana row.

### Changed

- Hold the AmneziaWG packages against unattended upgrades at provisioning, and pin the wg-easy image by digest.

### Fixed

- Stop and wipe the client VLESS xray (config, REALITY key, issued UUIDs) when a master is decommissioned.
- Enable UDP on the SOCKS bridge so DNS works for VLESS clients.
- Rate-limit subscription-token guesses per source IP so one bad actor cannot lock out every client.

### Docs

- Show the master-to-resolver mihomo DNS override for private domains in the example manifest.

## v0.1.2 — 2026-07-20

### Added

- Ship one self-contained archive per architecture (`wgfleet-linux-amd64.tar.gz`, `wgfleet-linux-arm64.tar.gz`) carrying both binaries, `install.sh`, `INSTALL.md`, `prepare-node.sh`, reference configs and the systemd units.
- Open world-facing TCP ports on a node with `public_tcp_ports`.

### Changed

- Run `install.sh` in two modes: it installs the binaries next to it when run from an unpacked archive, otherwise downloads and checksum-verifies the archive; it also copies the examples to `/etc/wgfleet/examples/`.

### Fixed

- Route the master's own public IP direct instead of through an exit.

### Docs

- Add `INSTALL.md`, the eight-step quickstart from ZeroTier through to a connected client, with a troubleshooting table.

## v0.1.1 — 2026-07-20

### Added

- Roll the agent across every exit with `--rolling-upgrade`, verifying each node and rolling it back if it does not come back.
- Split exits into primary and reserve tiers with `fleet.masters[].routing.reserve_exits`, and tune how many failed probes evict an exit with `fleet.masters[].mihomo.max_failed_times`; the reserve tier is kept warm and measured.
- Give each master↔exit tunnel its own master key instead of one shared key, and include the master's tunnel key in backups.

### Changed

- Verify, snapshot and roll back in `deploy-master.sh` the way exit upgrades already do.
- Refuse to write a secret-bearing file group- or world-readable.

### Fixed

- Repair exit failover and the AmneziaWG device leak after a mihomo hot reload.
- Bring the AmneziaWG interface down on an exit when the AWG transport is disabled.
- Repair file-mode drift, not only content drift.
- Guard `--upgrade-agent` with the per-node lock so it cannot run against a node a rolling upgrade is mid-way through, and make the single-rollout exclusion fleet-wide.
- Report every bad `reserve_exits` entry at once instead of the first, and show multi-exit carriage in the topology badge.

## v0.1.0 — 2026-06-29

First release.

### Added

- Install a co-located master in one line with `install.sh`: host dependencies (AmneziaWG DKMS, ZeroTier, Docker), checksum-verified binaries, systemd units left disabled, config templates, and a printed list of the remaining steps; idempotent, never starts a service on its own.
- Gate the console behind first-run setup and login, with an admin profile, password change, `controller.session_ttl`, and `--set-admin-password` for bootstrap and lockout recovery.
- Show the fleet as clickable master↔exit topology cards, per-exit tunnel health on the master page, the freshest handshake per node, and an auto-refreshing node status; decommission is gated on drain and can be cancelled.
- Back up and restore the controller with `--backup` and `--restore` (age-encrypted, restore with `--plan` and a preflight backup), or download a backup from the console; `age` is installed at bootstrap.
- Run exits with two transports, AmneziaWG plus VLESS+REALITY+XHTTP, switchable from the console and written through to the manifest, with `transports.reality.mode`, `fingerprint`, `mux` and `allow_ipv6`.
- Serve clients from a DNS filter on the master, with a self-check.
- Hide exits from VPN scanners with an auto-refreshed scanner-ASN blacklist (`firewall.as_blacklist`), and install fail2ban at bootstrap.
- Derive collision-safe AmneziaWG junk parameters and distinct I-packets per tunnel end.
- Watch egress throughput and suspend a starved exit from the balancer; fail over on censorship with live drift repair; set a per-exit `link_mtu`.
- Default the WARP MTU to 1380 with a path-MTU auto-probe (`warp_mtu`).
- Serve agent metrics at `<mgmt_addr>:9301` by default, with a Grafana dashboard and Prometheus and VictoriaMetrics scrape configs.
- Set the reconcile cadence fleet-wide with `fleet.reconcile_interval` (default 30s) and mihomo's exit health-check interval with `mihomo.health_interval`.

### Fixed

- Pin wg-easy client AllowedIPs to IPv4 only; clients issued before this fix carry `::/0` and must be re-imported.
- Self-heal mihomo's redirect listener after the client interface is recreated.
