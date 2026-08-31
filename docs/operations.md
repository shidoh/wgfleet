# Operations

Running a fleet day to day: planning changes, the dashboard, issuing client
access, backup and restore, metrics, and how a node's health state is derived.

See also [cli.md](cli.md) for every flag and [upgrade.md](upgrade.md) for rolling
the agent binary forward.

---

## Dry-run everywhere

`--plan` (agent) and `--provision … --plan` (controller) render every config and
the exact change set and write nothing — the trust mechanism for autoprovisioning.
Plan output shows files (with secrets redacted), commands, and DB updates.

## Web dashboard

`controller.webui` serves a fleet view (bind the ZeroTier address):

- Fleet list with a per-state summary and live refresh (htmx), state badges.
- Per-node detail: inventory, latest status + health checks, rendered `NodeSpec` preview
  (AWG params, peers, routing, firewall, DNS, master data plane, etc.), and a version-skew badge
  (when agent's wire version is incompatible).
- **Actions** (all confirmed POSTs with CSRF + same-origin checks):
  - **Provision** — SSH-bootstrap a `Pending` node asynchronously (Pending → Provisioning → Ready).
  - **Upgrade** — roll the agent binary forward over SSH without tearing down the data plane.
  - **Take out of routing** (drain) — keep the node as a configured proxy but remove
    it from load-balance; existing connections survive, no new traffic.
  - **Resume routing** (undrain) — rejoin the load-balance group.
  - **Decommission** — tell the agent to tear down the data plane on next reconcile
    (stop services, clear routing/firewall, best-effort reverse reconcile). It also
    destroys the node's WireGuard and REALITY private keys, so a recommissioned node
    comes back with new ones and is re-peered from scratch.
  - **Delete** — remove the exit from inventory AND from the manifest (its block in
    `fleet.exits`, plus its name in any `reserve_exits`), so it does not return as a
    Pending card. It does **not** revoke the certificate: a box still running its
    agent re-registers within a reconcile pass and reappears. Delete once the server
    is gone, or stop its agent first. No client credential lives on an exit, so
    nobody's config is deleted by this.
  - Drain, Decommission and Delete are **exits only**, enforced server-side: the
    master is the client gateway and load balancer, and tearing it down would
    invalidate every client config in the field. Undrain and Recommission are
    deliberately NOT restricted, so a node that somehow carries either flag always
    has a way back from the console.
  - **Download backup** — export an age-encrypted archive of the controller (and co-located master) state.

## Client credentials (AmneziaWG)

On a master with `client_awg.managed`, its node page has a **Client credentials**
panel. This is where the day-2 work lives, and all of it is one click:

- **Issue** — creates a credential and takes you straight to its card. Hand the
  person their **self-service link** (a page carrying only their own profile, reached
  over the tunnel or the portal address) rather than the file itself, so a lost phone
  is a revoke rather than a re-send. The `.conf` and a QR are on the same card.
- **Pause** — the reversible one. The peer is removed from the interface, so the
  device stops connecting and their self-service page says so; the same config works
  again the moment you resume. This is what you want for a device that will come
  back: a holiday, a phone being repaired, a suspicion you have not confirmed.
- **Rename** — the credential's name is only a label for you. Renaming changes
  nothing the person holds.
- **Revoke** — permanent. The credential and its key are deleted, the person is off
  the fleet immediately, and there is no way back except issuing a new profile. The
  console asks you to confirm on its own page, naming the credential, because the
  browser dialog is JavaScript and can silently fail to load.

A VLESS credential (below) has no pause: revoking is the only way to cut one off.

## Client access (VLESS)

On a master with `client_vless.enabled`, its node page has a **VLESS clients** entry.
There you **issue** per-client credentials and hand each user one of:

- **Clash config (`.yaml`)** — the recommended client on macOS. It bakes in the
  proxy plus tun `strict-route` (macOS otherwise leaves RFC1918 off the tunnel, so
  the master's internal/ZeroTier networks would be unreachable) and DNS pointed at
  the master's blocky over the tunnel (so private-domain split-horizon resolves).
  Import into **Clash Verge Rev** and enable Tun Mode.
- **vless:// link / QR** — for v2rayTun and other clients. To reach internal
  networks in v2rayTun, also import the routing object (Routing → import from
  clipboard, `v2rayTun://import_route/…`, shown on the page).
- **Subscription URL** — carries the vless link and the routing rules in a
  `routing` response header (reachable over the mgmt/ZT overlay).

`client_vless.route_through_cidrs` in the manifest controls which internal networks
clients route through the tunnel. See below for the hard-won
client-side details (strict-route, DNS split, import formats).

## Break-glass: reaching a node you just cut off

Every dangerous change in this system lands on the master — the firewall, the
client interface, the NAT — and the master is usually the box you are connected
*through*. So know the way in that your changes cannot close, before you need it.

**SSH over the ZeroTier mgmt overlay survives every knob in the manifest.** The
rendered input chain accepts `iifname "zt*"` unconditionally, and that rule sits
ahead of everything `masters[].whitelist`, `public_udp_ports`, `public_tcp_ports`
or the AS blacklist can express. The egress leak guard is gated on the exit role
and cannot touch a master at all.

The SSH port is opened unconditionally too, but **after** the AS-blacklist drop —
so direct SSH from an address the scanner feed has flagged can be refused while
the overlay path still works. That asymmetry is the reason the overlay, not the
public IP, is the escape hatch.

In practice:

- **Keep a second SSH session open** on the master for the whole of any firewall,
  routing or client-interface change. If the new state locks you out, the old
  session is still there and `wgfleet-agent --once --plan` will show you why.
- **Reach an exit through the master** when its own public path wedges:
  `ssh <master>` then `ssh root@<exit-mgmt-addr>`.
- **Have provider console access ready** (VNC/serial) before touching the master's
  firewall. It is the only path that does not depend on anything in this repo.
- The agent holds its **last-good spec**, and holds it on disk
  (`/var/lib/wgfleet/last-spec.json`, 0600). A controller that is down, or refusing a
  bad manifest, does not take the data plane with it — and a node that REBOOTS in
  that window comes back converged rather than bare: it re-applies the last spec that
  worked, including nftables, interfaces and routing. You have time.
  - **A node running from the cache reports nothing** — there is nobody to report to
    — so it goes stale in the console and in `wgfleet_node_last_report_age_seconds`
    while being perfectly healthy. Read "not reporting" together with "is the
    controller up", not on its own. Its log says
    `converging on the last-good spec instead of standing still`.
  - The fallback happens only when NOTHING ANSWERED (dial failure, timeout). A
    controller that answers and refuses — a deleted node, a revoked certificate, a
    wire-version mismatch — is obeyed. A node you deleted does not rebuild itself.

## Support bundle

A read-only diagnostic archive, for handing a broken fleet to someone who has no
access to it. It contains no secrets, is not encrypted, and is plain text
throughout, so whoever runs it can read exactly what they are about to send.

```bash
# One node. Depends on nothing — this works when the control plane is down.
wgfleet-agent --support-bundle --note "clients stopped resolving around 14:00"

# The exits, plus a fleet inventory. Needs a live controller and SSH.
wgfleet-controller --support-bundle --fleet
```

Read it before sending it: `tar tzf <archive>` lists, `tar xzf <archive>`
extracts, and `MANIFEST.txt` names every file, the command behind it, and — just
as importantly — what was deliberately **not** collected.

Three layers keep the no-secrets promise: no configuration file is ever a
collector source, secret-bearing values in uncontrolled text (container logs,
third-party units) are masked, and if a secret the node actually holds survives
into the assembled bundle the tool **refuses to write the archive at all** and
names the file and line. A refusal is worth reporting rather than working around.

Two limits worth knowing. `--fleet` walks the exits; it collects nothing about
the co-located master beyond one inventory line, so run the agent bundle there
too when the master is the problem. And the fleet-mode secret check can only
compare against secrets the controller itself holds — it cannot see an exit's own
on-disk keys, because fetching them would mean collecting exactly what this
feature refuses to collect. The local agent run does not have that gap.

The full runbook ships to operators as `SUPPORT-BUNDLE.md`. For client-side
problems — a device that connects but loads nothing — `client-diag.sh` ships
alongside it and runs from the client, not the server.

## Backup & restore

One command captures the **irreplaceable** state and one restores it onto a fresh
node — for disaster recovery and migration. Everything else (nft, mihomo/xray/blocky
configs, compose files) is regenerated by the agent's reconcile loop and is not captured.

**Two things are neither captured nor regenerable, and the archive says so on every
run.** Copy them somewhere the master is not:

- **The SSH private keys the exits are provisioned with** (`exits[].ssh.key_path`).
  Only the paths travel, in the manifest. A restored controller can see the fleet and
  cannot provision, upgrade or roll back a single exit — the recovery channel is the
  part that is missing.
- **The ZeroTier identity** (`/var/lib/zerotier-one/`). Rejoining as the SAME mgmt
  address, which the migration steps below tell you to do, is impossible without it —
  and on this fleet the ZT controller itself runs on the machine you are rebuilding.

```bash
# Export (controller may stay live; the db snapshot is WAL-consistent).
wgfleet-controller --backup fleet.tar.age --age-recipient age1...
#   ...or without --age-recipient to be prompted for a passphrase.

# Restore onto a fresh node (controller MUST be stopped). --plan shows the change set.
# An archive written with --age-recipient needs --age-identity on BOTH lines; without
# it age cannot decrypt and the --plan line fails before it shows you anything.
wgfleet-controller --restore fleet.tar.age --age-identity key.txt --plan
wgfleet-controller --restore fleet.tar.age --age-identity key.txt
#   ...drop --age-identity for a passphrase-encrypted archive; age prompts for it.
```

What is captured: the store db (consistent `VACUUM INTO` snapshot), the CA cert + key,
`controller.yaml`, the sops secrets file (verbatim, when configured), the fleet secret
`awg3.key`, and — when this node is also a master — the master's own AmneziaWG key, the
client-interface key, the client-facing VLESS/REALITY key, the wg-easy client db and
admin password (where wg-easy is still in use), and the node identity
(`node.crt`/`node.key`/`agent.yaml`). That is **six private keys** in one envelope, so
the age envelope is its only at-rest protection — store it like a secret.

A secret the controller cannot put in the archive is warned about **before** the archive
is written, on the console's Backup button as well as the CLI: a `pki.ca_key` behind
`env://` or `secret://`, an `awg3_key` that is not a file, or either of them configured
at a path this host cannot read. An archive without the CA cannot issue or renew any
certificate on a rebuilt host, and every node then falls off the control plane as its
certificate expires — so treat that warning as a failed backup, not a note.

Restore checks every destination in the archive **before it writes anything**, then
moves each existing file aside to `<path>.bak-<timestamp>` and writes atomically. It
writes only where this host's own `controller.yaml` says its files live, with this
host's own permissions rather than the modes recorded in the archive — `age -r` does
not authenticate a sender, so both the path and the mode are untrusted input. A
rejected archive therefore leaves the box exactly as it found it. It also removes a
stale SQLite write-ahead log beside a restored database, which otherwise belongs to the
generation of the file just replaced. It refuses to run while a controller is still serving on
the configured endpoint.

**Migration.** Agents dial `controller: <mgmt>:8443`. The zero-touch path is to rejoin
ZeroTier on the new node as the **same mgmt address** — the CA, certs, and endpoint all
match and the fleet re-adopts itself. If the mgmt address changes, update every node's
`agent.yaml` `controller:` and re-issue the server cert SAN (restore prints this reminder).

## Certificates

Every node authenticates to the controller with an mTLS certificate issued for a
year, and **agents renew their own** between 70% and 90% of that — in place, over the
control plane, with no restart and nothing for you to do. The renewal moment is
spread deterministically per node name, so a fleet provisioned in one week does not
renew in one week.

What to watch: `wgfleet_agent_cert_expiry_timestamp_seconds`. On a healthy node that
number steps forward roughly once a year; a node whose remaining time **stops going
up** is one whose renewal is failing, and by the time `WgfleetNodeCertExpiring` fires
it has been failing for at least forty days. The usual causes are a node that has
been offline, a controller with no CA loaded, or a clock that is wrong.

`wgfleet-controller --certs check-expiration` prints what THIS host holds: the fleet
CA, and the local agent's certificate on a co-located master. It cannot see the other
nodes — those certificates are on those nodes.

If one does lapse, the automatic path is closed to it: renewal travels over the mTLS
channel the expired certificate opens, so the handshake fails before the request. Use
the out-of-band path:

```bash
sudo wgfleet-controller --certs renew --node exit-de-1
```

It writes `pki/exit-de-1/node.{crt,key}` and prints the scp/ssh lines for that node,
taken from the manifest. Delete the local copy afterwards — it is a live node
identity — and note that the old certificate is not revoked (there is no CRL); it
simply stops being useful when it expires.

A node that leaves the fleet cannot renew either: `Decommission`, or deletion from
the inventory, refuses the request. That is deliberate, and it is the only revocation
this system has.

## Metrics

The controller (`controller.metrics`) and every agent expose Prometheus text on
the ZeroTier address only. The agent endpoint is **on by default** at
`<mgmt_addr>:9301` (from `agent.mgmt_addr`); `--metrics <addr>` overrides the bind
and `--metrics off` disables it.

**Controller** (a scrape-time projection of the state store):

```
wgfleet_nodes{state="Ready"}                               # node count per lifecycle state
wgfleet_node_info{node,role,region,state}                  # inventory info (=1)
wgfleet_node_agent_info{node,agent_version,wire_version}   # agent build + wire version (=1)
wgfleet_node_last_report_age_seconds{node}                 # since last status report
wgfleet_node_reconcile_failed{node}                        # 1 if last reconcile errored
wgfleet_node_health_check{node,check}                      # 1 ok / 0 failing
wgfleet_node_egress_info{node,egress_ip}                   # observed egress IP (=1)
wgfleet_node_drain{node}                                   # 1 if administratively drained (out of LB)
wgfleet_node_decommission{node}                            # 1 if flagged for decommission (data plane torn down)
wgfleet_node_client_vless_clients{node}                    # VLESS/REALITY clients issued on a master
```

**Agent** (its own reconcile/health counters):

```
wgfleet_agent_reconcile_total{result}              # success | error
wgfleet_agent_reconcile_duration_seconds           # histogram
wgfleet_agent_state_info{state}                    # current lifecycle state (=1)
wgfleet_agent_health_check{check}                  # 1 ok / 0 failing
wgfleet_agent_drift_total{component}               # count of unexpected config changes (drift-repairs)
wgfleet_agent_egress_active{method}                # current active egress method (e.g. warp, direct)
wgfleet_agent_egress_reachability{state}           # ok | degraded | blocked (censorship signal)
wgfleet_agent_start_time_seconds                   # for uptime
```

## Node lifecycle & health

After each apply reconcile the agent runs role-specific self-checks and reports
the derived state:

- **Exit checks:** `wg-handshake` (freshest handshake under 3m: a tunnel whose
  handshake is older than that has stopped carrying traffic, even though the
  interface still looks up),
  `egress-reachability` (censorship signal: ok | degraded | blocked),
  `warp-egress` (egress via Cloudflare WARP, when `egress=warp`), `dns-filter`.
- **Master checks:** `client-wg` (interface up), `mihomo-api` (Clash API
  `/version`), and — when `client_vless.enabled` — `client-vless` (the
  VLESS+REALITY inbound is up; a down inbound shows **Degraded**).

Aggregation: reconcile failed → **Error**; all checks pass → **Ready**; any check
fails → **Degraded**; no checks → **Reconciling**.

If an agent goes silent, the controller's **staleness sweep** demotes its node
(`Ready`/`Reconciling`) to **Degraded** after `controller.staleness_after`
(default 3m; `<0` disables) so the dashboard and metrics reflect a dead agent.
`Error` nodes are left as-is (they keep their failure reason); when the agent
recovers, its next report restores the state.
