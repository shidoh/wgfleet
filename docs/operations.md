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

## A node changed its public address

A node moves — the provider reassigns it, or you migrate it. The address the
fleet dials is declared in the manifest, and nowhere else: no agent discovers or
reports it. So a move is a manifest edit plus a controller restart.

1. Edit the node's entry.
   - **An exit:** `public_ip` when it is set, otherwise `ssh.host` — that is what
     `public_ip` defaults to. Set both if SSH and the tunnel should go to
     different addresses; that is exactly what `public_ip` is for.
   - **A master:** `public_ip`, and only that. It does not fall back to
     `ssh.host` (which is often the management overlay, and must never reach a
     client profile), so a master with no `public_ip` has no endpoint to hand out
     and the client pages say so.
2. Restart the controller. It reads the manifest once at startup and never
   reloads it, so nothing changes until you do.
3. Wait for two reconcile passes (~60s with the default 30s interval). They are
   not synchronised: the master's next pass re-renders the tunnel at the new
   endpoint and re-dials, then the exit's own next pass sees the fresh handshake
   and leaves **Degraded**. No re-provisioning, no touching the node itself.

Re-provisioning is not required. It is what refreshes the node's stored copy of
the address, which is otherwise only visible as the value the console falls back
to for a node the manifest does not declare. The console shows the manifest's
value either way.

An exit's address must be an IP literal: the master dials `ip:port` and the
kernel gets a `/32`, so a DNS name there is skipped and the next source is used.
A master's `public_ip` may be a DNS name — `docs/master-migration.md` recommends
one, so a future move is a record change — and the routing rules that need a
literal fall back to the provisioned address.

If it was the **master** that moved, client profiles already handed out still
carry the old endpoint: re-issue them and have each device re-import. Nothing on
the fleet side rewrites a config a user already has.

> Up to and including 0.1.7 this did not work: the endpoint came from a copy of the address
> taken at first provisioning, and nothing ever refreshed it. Editing the
> manifest and restarting changed nothing, the master kept dialing the old
> address, and the exit sat in **Degraded** with a dead `wg-handshake`.

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

## Kernel upgrades (your call, not ours)

AmneziaWG is a DKMS module: it is compiled against a specific kernel. If a node
boots a kernel the module was never built for, it has no AmneziaWG — therefore no
tunnels — and the agent cannot fix that, because it cannot build a module for a
kernel that is already running.

What Ubuntu actually does by default (checked against the Ubuntu Server docs, not
from memory): `unattended-upgrades` is installed and enabled, it takes the release
and `-security` pockets only, and **automatic reboot is off**. Kernel security
updates do come through `-security`, so a new kernel can be INSTALLED on its own —
but it is not booted until somebody reboots, and DKMS builds the module at install
time as long as matching headers are there. `prepare-node.sh` installs
`linux-headers-generic` for exactly that reason.

So the failure needs three things at once: a kernel upgrade lands, DKMS fails to
build for it (missing headers, a kernel API change), and the node reboots. That is
rare and it is not silent — but it takes out the data plane completely when it
happens.

wgfleet does **not** touch your package policy. It does not hold packages, does not
enable or disable unattended upgrades, and does not decide when your nodes reboot.
That is your machine and your maintenance window. What we do is name the
constraint:

- after any reboot, check the module came back: `modinfo amneziawg` on the node, or
  simply that it returns to Ready;
- keep `linux-headers-generic` installed alongside the kernel metapackage — without
  matching headers DKMS cannot rebuild;
- if you would rather kernel upgrades be deliberate, hold the metapackage:
  `apt-mark hold linux-image-generic linux-headers-generic`. Check the name first —
  `linux-image-virtual` and `linux-image-kvm` exist on other images, and `apt-mark
  hold` on a package that is not installed succeeds and appears in `apt-mark
  showhold` while holding nothing.

Some provider images ship no kernel metapackage at all, only a versioned
`linux-image-6.x`. Those nodes will not receive kernel upgrades on their own: safe
for the module, and no kernel security updates either. Worth knowing; still yours
to decide.

The one apt hold wgfleet does keep is on `amneziawg`, `amneziawg-dkms` and
`amneziawg-tools` — our own component, pinned because the userspace tools and the
kernel module must stay on the same AmneziaWG generation — AmneziaWG 3.0 changed the
netlink attribute layout between them, so a node whose tools and module disagree fails
`awg setconf` outright and the interface never comes up. It blocks automatic
upgrades only, and the agent re-establishes it at whatever version you chose.

### Upgrading the AmneziaWG module

Neither a wgfleet upgrade nor a re-run of `prepare-node.sh` touches the module: the
script builds it only when it is missing, and the agent keeps the packages held.
A node prepared under an early release therefore still runs the module the PPA
shipped that day (a 1.x build, before AmneziaWG 3.x), and keeps working on it —
a 2.0 config runs on either generation. You need a newer module only when you
turn on `awg3` (the agent then refuses the config and says so in the reconcile
error), or when upstream fixes something you are hitting.

```bash
prepare-node.sh --upgrade-awg
```

That installs `amneziawg-dkms` and `amneziawg-tools` together, then reloads the
module, which deletes every AmneziaWG interface on the node; the agent rebuilds
them on its next pass (a few seconds of loss). By hand it is:

```bash
apt-get update
apt-get install -y --allow-change-held-packages amneziawg-dkms amneziawg-tools
modprobe -r amneziawg && modprobe amneziawg   # or reboot
modinfo -F version amneziawg                  # 3.1.… for the current line
```

On a master whose clients are still served by wg-easy (client-migration.md, part 3
not done) the container is the thing to watch, not the interface. wg-easy drives
`wg0` with the amneziawg-tools it bundles, and those must be of the module's
generation: the pinned v15.3.0 bundles generation-1 tools and on a 3.x module its
`awg-quick up wg0` dies with `Unable to modify interface: Invalid argument` — the
client base is gone until something changes. The agent handles this since v0.2.4:
it reads the module generation every pass and recreates wg-easy from v15.4.0
(generation-3 tools) within one pass of the reload; do not `docker restart` it by
hand in between, that only restarts the container that cannot work. An agent
older than that cannot help; the way out there is the migration in
client-migration.md, parts 2-3. Once v15.4.0 has run, do not take the module
back to 1.x: it migrated wg-easy's database forward and v15.3.0 will not open it.

Do **not** `apt-mark unhold` first: the agent re-pins the packages on every
reconcile pass (about every 30 s), so by the time `apt-get update` has finished
the hold is back and `apt-get install -y` fails with "Held packages were changed".
`--allow-change-held-packages` is the honest way through — both packages move as
one transaction and the agent re-pins the new version.

If the DKMS build itself fails, the reason is in
`/var/lib/dkms/amneziawg/1.0.0/build/make.log`. It is usually the kernel: on
Ubuntu 22.04 the GA kernel is 5.15, and upstream has broken the build for
pre-6.7 kernels before (fixed the same day, but the PPA build you get is whatever
is current). Moving to the HWE kernel (`linux-generic-hwe-22.04`) is the cheap
way out — your package decision, per the section above.

### AmneziaWG is down: where to look

Three places on the node, in this order, and none of them is `awg-quick@` — the
agent never installs that unit. A tester lost an evening in its journal.

```bash
journalctl -u wgfleet-agent -b --no-pager | grep -i -E 'error|warn|awg|wg0' | tail -30
ip -br link | grep -E 'wg|awg'
docker ps -a --format '{{.Names}} {{.Status}}'        # master: is wg-easy up and healthy?
```

The first says what the agent tried and where it stopped. `wg0 not found` in a
health check is the agent NOTICING the interface is gone, not failing to create
it: on a master before the client-leg migration the creator is the wg-easy
container, and its reason is in `docker logs --tail 40 wg-easy`. On an exit the
interface is `awg0`, the agent raises it itself, and the failing `awg-quick up`
is in the journal with its output.

Start with the versions; two of the three causes below are version splits:

```bash
nft --version                           # 1.0.2 on Ubuntu 22.04, 1.0.9 on 24.04
modinfo -F version amneziawg; awg --version
```

What it has been so far, in order of likelihood:

- **Tools and module of different generations** — `awg setconf … Invalid
  argument`. Compare `modinfo -F version amneziawg` (module) with
  `awg --version` on the host and, on a wg-easy master, inside the container
  (`docker exec wg-easy awg --version`). The major versions must agree. See the
  section above.
- **Module not built for the running kernel** — `dkms status` has no `installed`
  line for `uname -r`. See "Kernel upgrades" above.
- **The move into mihomo's namespace reverts every time, probes say "connection
  refused"** — the host is still intercepting clients after mihomo left. Look for
  `nft rejects the rendered ruleset` in the agent journal and check
  `nft list table ip wgfleet_master` for a `dnat to <gateway>:7895` line while
  mihomo's network mode is `container:…`. Fixed for nftables 1.0.2 in v0.2.4; the
  agent now reports the component unconverged instead of keeping quiet.
- **The interface is back but `udp-return-path` keeps failing** — the namespace
  mover gave up while the interface was down (`client interception not moving …
  reverted 3 times` in the journal). Fixed in v0.2.4; on an older agent toggle
  `mihomo.client_via_netns` to `off`, wait a pass, and back to `auto`.

When it is not one of those, take a support bundle and send it rather than
guessing further: `wgfleet-agent --support-bundle --note "..."` on the node — it
carries all three of the above plus the container logs, and nothing secret.

## Client interception in mihomo's network namespace

mihomo's TPROXY reply path binds the **server's** address:port for every
intercepted flow, so any UDP port the host already holds is a silent black hole
for client traffic to that port. On this fleet the client AmneziaWG interface
holds `0.0.0.0:443`, and client QUIC was one-way for eight days with every
component metric green. Moving mihomo into a network namespace of its own removes
the collision as a category rather than fixing one port.

### The knob

`fleet.masters[].mihomo.client_via_netns`:

| value | meaning |
|---|---|
| unset | `auto` — the fix ships on, see below |
| `off` | interception stays on the host — the way it has always worked |
| `auto` | every client moves, once the agent has proved the namespace works |

There is no per-client mode. It existed, and the stand showed it doing the
opposite of what its name promised: mihomo moves as a whole, so the host went on
steering every client OUTSIDE the chosen prefix at listeners that had left — the
blast radius of a "canary" was everyone except the canary. `tproxy` can only hand
a packet to a socket in its own namespace and there is one mihomo, so a CIDR here
is refused with that explanation rather than quietly half-working. The unit of
staging is the NODE.

Anything else is refused with an error naming the knob, so a typo cannot enable
the migration.

**It ships on.** An operator cannot be expected to know their master black-holes
client UDP to every port it happens to hold, so shipping the fix off by default
ships the outage by default. The agent proves the namespace resolves and reaches
an exit before moving anything, measures the client path from its own synthetic
client after, and reverts itself if that path breaks — and `off` is a full,
converging way back, not just a switch that stops future moves.

On a fleet with more than one master, move them one at a time and watch the first
for a day before the next. On a single-master fleet the staging you have is the
automatic revert, plus `off` as a converging way back.

The whole cycle was rehearsed on a two-VM stand on 2026-09-05, with the client
interface on the production port: canary → full move → break the namespace's path
→ automatic revert → clients back, plus a reboot in the moved state. Eight
blockers came out of that rehearsal and none of them were visible in review; the
write-up is in `obsidian/claude/wgfleet/2026-09-05-netns-move-lima-rehearsal.md`.
What it did NOT cover is real clients under load, so the first live master should
run as a canary on one device for a day before `auto`.

### After switching it on, WATCH — do not just look

Every point-in-time check can be green while the migration is failing, and on
2026-09-05 they all were. mihomo was in the namespace, the rules were right, the
client-path probes were green — and a self-heal probe still aimed at the host was
restarting mihomo on every pass. Each restart re-initialises mihomo's userspace
WireGuard devices; three exits fell out of the balancer within three minutes, and
the first thing anybody noticed was traffic moving to the reserve tier.

Two live attempts failed in ways no snapshot could see. The first: a self-heal
probe still aimed at the host restarted mihomo every pass, and each restart
re-initialised its userspace WireGuard devices — three exits gone in three
minutes. The second: the veth was narrower than the uplink, so mihomo's own
tunnel packets did not fit; WireGuard handshakes are 148 bytes and passed, every
tunnel reported UP while carrying nothing, and four exits died. One needs
WATCHING, the other needs a BIG packet.

So take a baseline first, then watch:

```bash
./netns-move-check.sh --baseline     # BEFORE the flip
# ... set client_via_netns: auto, restart the controller ...
./netns-move-check.sh 180            # AFTER
```

It fails on a mihomo that restarts, on a self-heal being throttled (the same
defect with the symptom suppressed), on a packet the size of the uplink not
leaving the namespace, on mihomo in an orphaned namespace, on an unreachable
control API, and — compared against the baseline rather than eyeballed — on any
tunnel that was alive before the move and is not after.

The control API keeps its address across the move: a redirect on the management
overlay sends it into the namespace, so `http://<mgmt>:9090/ui` works either way.

### How to tell where a master is

```bash
# The decision machine, from the agent's metrics.
curl -s <mgmt>:9301/metrics | grep netns_move
#   wgfleet_agent_netns_move_state{state="attached"} 1
#   wgfleet_agent_netns_move_attempts 0

# The kernel's version of the same question.
ip rule list | grep -E '^(390|400):'      # exemptions, then the move itself
ip route show table 51822                 # default via the veth
nsenter --net=$(docker inspect -f '{{.State.Pid}}' wgfleet-netns | sed 's|^|/proc/|;s|$|/ns/net|') nft list table ip wgfleet_netns

# Where mihomo actually is (not where compose says it should be).
readlink /proc/$(docker inspect -f '{{.State.Pid}}' mihomo)/ns/net
readlink /proc/$(docker inspect -f '{{.State.Pid}}' wgfleet-netns)/ns/net
```

Clash API moves with mihomo: once attached it is on the namespace end of the
veth (`100.127.255.2:9090` by default), not on the management address.

### How to go back

Set `client_via_netns: off` and let the agent converge — it withdraws the routing
rule, the destination exemptions and the namespace route table, and mihomo returns
to host networking. The agent also reverts **itself** if the client path breaks
after a move, without needing the controller.

By hand, on the master, when the agent is not running:

```bash
ip rule del pref 400                       # stop routing clients into the namespace
while ip rule del pref 390 2>/dev/null; do :; done   # the direct exemptions
ip route flush table 51822
docker compose -f /etc/wgfleet/docker-compose.yml up -d --force-recreate mihomo
nft -f /etc/wgfleet/wgfleet-master.nft     # re-arm the host interception
```

The rule at priority 400 sorts ahead of the TPROXY mark rule, so leaving it in
place after mihomo has moved back is worse than the move was: marked client
packets go into an empty namespace. Remove it first.

### Downgrading the binary after a move

An agent old enough not to know about the namespace does not know about any of
the above either: it will not remove the ip rules, and `docker compose up -d`
leaves the holder running as an orphan. **Revert with the knob and let the current
agent converge before rolling the binary back.**

### The alert that will be standing

`WgfleetClientUDPBlackHole` is a warning, not a page, and on a master that still
intercepts on the host it is true and standing for every UDP port the host holds.
That is the finding, not an incident: it clears when the interception moves (or
when the port is freed or the traffic refused). The user-visible outage has its
own critical alert, `WgfleetClientPathDead`.

Before rolling this out to a master, take the inventory the check will read:

```bash
ss -lunp        # every UDP port this host holds is a black hole today
```
