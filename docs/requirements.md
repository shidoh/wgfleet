# System requirements and compatibility

What a node must be for wgfleet to run on it, what the platform installs
itself, and which combinations are supported. "Supported" means the fleet is
developed and tested on it; "works" means it has run, but nobody promises to
keep it running.

## Node operating system

| | Status | Notes |
|---|---|---|
| **Ubuntu 24.04 LTS** (amd64, arm64) | **Supported** | Kernel 6.8, nftables 1.0.9, Docker from get.docker.com. |
| Ubuntu 22.04 LTS | Works, not guaranteed | Kernel 5.15 GA (HWE 6.8 available), nftables **1.0.2**, which accepts less syntax than 1.0.9. From v0.2.4 the agent renders rulesets for it and checks every ruleset for portability; new rules are still developed against 1.0.9 first. |
| Anything older, Debian, other distributions | Not supported | The scripts target apt; nothing else has been tried. |

Everything below Ubuntu 24.04 is best effort: a report is welcome, a fix is not
promised.

## Per node

- **Root SSH** for bootstrap (`controller --provision`); the agent runs as root.
- **A public IPv4 address.** The data plane is IPv4-only; IPv6 is refused on the
  client interface. A client handed `::/0` over an IPv4-only tunnel black-holes
  every IPv6 destination instead of falling back.
- **AmneziaWG kernel module** built by DKMS against the running kernel, from
  `ppa:amnezia/ppa` — `prepare-node.sh` does it. Kernel headers must match the
  running kernel; on 22.04 with the HWE kernel that is
  `linux-headers-generic-hwe-22.04`, not `linux-headers-generic`.
- **Module and tools of one generation.** The agent pins `amneziawg`,
  `amneziawg-dkms` and `amneziawg-tools` with `apt-mark hold` and upgrades them
  only through `prepare-node.sh --upgrade-awg`. On a master that still runs
  wg-easy, the container image follows the module generation automatically
  (v15.3.0 for a 1.x module, v15.4.0 for 3.x).
- **Docker Engine with the Compose v2 plugin** (installed by the provisioner from
  get.docker.com). Client interception inside mihomo's network namespace uses
  `network_mode: container:…`, which needs Compose v2.
- **ZeroTier** for the management overlay (installed by `prepare-node.sh`; the
  node must be authorised in ZeroTier Central).
- **nftables** owns the firewall; `nftables.service` is masked by the scripts
  because its distro default flushes the ruleset on boot.
- **conntrack** (the `conntrack` package, installed by `prepare-node.sh`): the
  agent deletes stale flows with it after routing changes and on masters with
  `transports.awg.exit_initiated`. Without it those repairs are skipped with a
  warning in the agent journal.

## Sizing

| Role | Minimum | Notes |
|---|---|---|
| Exit | 1 vCPU, 1 GB RAM, 10 GB disk | ZeroTier throughput is CPU-bound: a 1 vCPU box tops out at roughly 20–30 Mbit/s over the overlay. |
| Master (with the controller co-located) | 2 vCPU, 2 GB RAM, 20 GB disk | mihomo, blocky, the namespace holder and the controller share the box. |

Journal size is capped by `prepare-node.sh` (200 MB, keep 1 GB free).

## Controller host

The controller is normally co-located with the master
(`docs/colocated-controller-master.md`). It needs the same node requirements,
plus the `age` binary for `--backup`/`--restore`. State is a single SQLite
database; the schema is migrated forward on start and a database from a newer
build is refused rather than downgraded.

## Versions the platform pins

| Component | Version | Where |
|---|---|---|
| mihomo | `v1.19.33` | `compose.DefaultMihomoImage` |
| wg-easy (legacy client interface) | `15.3.0` by digest on a 1.x module, `15.4.0` by digest on a 3.x module | `compose.DefaultWGEasyImage`, `DefaultWGEasyImageAWG3` |
| xray-core (REALITY) | `26.6.22` | `compose.DefaultXrayImage` |
| blocky | `v0.35.0` (override with `dns.tag`) | `compose.DefaultBlockyImage` |
| wgcf (WARP egress, exits only) | `2.3.1`, stamped on the node at provisioning | `provisioner` bootstrap |
| AmneziaWG module / tools | whatever `ppa:amnezia/ppa` ships at prep time, then held | `prepare-node.sh` |

Every image and tag is overridable per node in the manifest
(`docs/configuration.md`).

## Controller ↔ agent compatibility

Compatibility rides on the **wire-contract version**, not on the build string:
the controller serves `[MinSupportedWire .. WireContractVersion]` and refuses an
agent outside that window. Upgrade the controller first, then the agents
(`docs/upgrade.md`). A build's contract is printed by `--version`.

## Clients

wgfleet's responsibility ends at the config it hands out. Clients used with a
fleet:

- **AmneziaWG 2.0 clients** (AmneziaVPN, the `awg` tools) on the client
  interface. AmneziaWG 3.x on the client interface is opt-in and needs a 3.x
  module on the master first (`docs/client-migration.md`, part 4).
- **VLESS + REALITY clients** (mihomo apps via a device subscription — FlClash,
  ClashMetaForAndroid, ClashX Meta, Clash Verge Rev; any VLESS client via the
  `vless://` link) on the client VLESS inbound. Split-tunnel behaviour is a
  client-side setting and differs per app: a client's tun mode decides whether
  private ranges go through the tunnel, and some apps expose no switch for it.

A client bug is documented, not worked around on the server.
