# Changelog

What changed for operators in each wgfleet release — behaviour, manifest keys, CLI flags, the console, the scripts in the archive, and the steps an upgrade asks of you.
Every release archive carries this page as `CHANGELOG.md`.
New releases are announced, with the archives attached, in the Telegram channel [t.me/wgfleet](https://t.me/wgfleet).

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

    - Take a controller backup: `wgfleet-controller --backup`. The first start migrates the store (existing AmneziaWG credentials become devices); an older controller refuses to open the migrated database, so going back means restoring that backup.
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
- Default the client and exit I-packet prologue to a per-end STUN+QUIC cover, measured across four mobile operators; the previous plain-noise default was the worst of the set on mobile.
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
