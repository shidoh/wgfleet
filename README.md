<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="wgfleet — a control plane for AmneziaWG exit fleets. Declare the fleet; wgfleet builds it and holds it there. A terminal panel shows real dry-run output from wgfleet-agent --once --plan for node exit-de-1: it would create awg0.conf with the private key redacted and the derived AmneziaWG obfuscation parameters, then run awg-quick to bring the interface up; the REALITY inbound stays disabled — writing nothing.">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-3ddc84?style=flat-square&labelColor=0c1017"></a>
  <a href="https://go.dev/"><img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26%2B-5b8def?style=flat-square&labelColor=0c1017"></a>
  <img alt="Status: MVP, active development" src="https://img.shields.io/badge/status-MVP%20%C2%B7%20active-f5b14c?style=flat-square&labelColor=0c1017">
  <img alt="Data plane: Linux" src="https://img.shields.io/badge/data%20plane-linux-8b93a1?style=flat-square&labelColor=0c1017">
</p>

<p align="center">
  <a href="https://shidoh.github.io/wgfleet-docs/"><b>Documentation</b></a> ·
  <a href="https://shidoh.github.io/wgfleet-docs/docs/QUICKSTART/">Quickstart</a> ·
  <a href="https://shidoh.github.io/wgfleet-docs/docs/manifest/">Manifest</a> ·
  <a href="https://shidoh.github.io/wgfleet-docs/docs/operations/">Operations</a> ·
  <a href="https://shidoh.github.io/wgfleet-docs/docs/cli/">CLI</a> ·
  <a href="https://shidoh.github.io/wgfleet-docs/DISCLAIMER/">Disclaimer</a> ·
  <a href="https://shidoh.github.io/wgfleet-docs/SECURITY/">Security</a>
</p>

---

# A control plane for AmneziaWG exit fleets

You declare the fleet in one config file. wgfleet takes a blank Ubuntu VM,
provisions it into a working exit node — AmneziaWG server, Cloudflare WARP
egress, DNS filtering, policy routing, firewall, metrics — joins it to the load
balancer, and then holds every node at that state with a pull-based reconcile
loop.

> [!WARNING]
> wgfleet is research / infrastructure-automation software for **lawful** use
> only, provided **without warranty**. It operates VPN and traffic-obfuscation
> infrastructure; the legality of deploying, operating, or using such tools
> varies by jurisdiction and is **your responsibility**. Read
> [the disclaimer](https://shidoh.github.io/wgfleet-docs/DISCLAIMER/) before using it.

| Without wgfleet | With wgfleet |
|---|---|
| SSH into each VM, run Ansible or manual steps | Declare the node in the fleet manifest |
| Copy AmneziaWG keys around by hand | Keys generated on-node; the controller brokers public keys only |
| Hand-edit AmneziaWG obfuscation in a UI | Parameters derived deterministically, then rendered and applied |
| Tweak mihomo / nftables / routing per node | Rendered from desired state, idempotently |
| Hope nothing drifted | A reconcile loop converges and reports health |
| No fleet-wide view | Web dashboard + Prometheus metrics |

---

## See the change before it happens

Every reconcile can run as a side-effect-free **plan**: it renders every config,
prints the exact change set with secrets redacted, and writes nothing. The same
engine serves every component, so plan and apply cannot diverge.

Output of the [local run](#try-it-locally) below — no root, no VPN tools, no
servers:

```console
$ wgfleet-agent --config exit-agent.yaml --once --plan \
    --public-ip 198.51.100.7 --mgmt-addr 10.20.0.5 --state-dir state/exit-de-1

reconcile plan — 30 change(s)

=== firewall (nftables) ===
  + create    state/exit-de-1/wgfleet.nft — 1740 bytes, mode 644
      | #!/usr/sbin/nft -f
      …

=== amneziawg interface ===
  + create    state/exit-de-1/awg0.conf — 378 bytes, mode 600
      | [Interface]
      | PrivateKey = <redacted>
      | Address = 10.81.0.1/24
      | ListenPort = 22891
      | MTU = 1360
      | Jc = 5
      | Jmin = 45
      | Jmax = 105
      | S1 = 27
      | S2 = 38
      | S3 = 63
      | S4 = 23
      | H1 = 29838687-159838687
      | H2 = 717803267-847803267
      | H3 = 1073039351-1203039351
      | H4 = 1504901982-1634901982
      | I1 = <b 0x000100002112a442><r 12>
      | I2 = <b 0xc3000000010e><r 14><b 0x0c><r 12><b 0x00><r 97>
      …
  ! exec      awg-quick — bring interface up with new config
      | awg-quick up state/exit-de-1/awg0.conf

=== policy routing ===
  + create    state/exit-de-1/routing.applied — 533 bytes, mode 644
      | sysctl -w net.ipv4.conf.all.rp_filter=0
      | sysctl -w net.ipv4.conf.default.rp_filter=0
      …

=== reality inbound (xray) ===
    no-change reality inbound — disabled

=== exit forwarding (ip_forward + DOCKER-USER) ===
  ! exec      sysctl — enable IPv4 forwarding
      | sysctl -w net.ipv4.ip_forward=1
      …
```

`+ create` · `~ update` · `! exec` · `no-change` — the same four markers for
files, commands and database writes. Drop `--plan` to apply exactly that.

---

## Architecture

<img src="assets/readme/architecture.svg" width="100%" alt="wgfleet architecture. Control plane: a single wgfleet-controller binary holds desired state and inventory in SQLite, runs the PKI and per-node mTLS certificates, brokers node public keys only, renders each NodeSpec, provisions blank VMs over SSH, and serves a gRPC API, Web UI and metrics. Agents on every node pull their NodeSpec and push status plus their public key over gRPC with mTLS. Data plane: clients connect over AmneziaWG or VLESS to the master, where the agent owns the client AmneziaWG interface, xray serves the opt-in client VLESS inbound, and mihomo routes and load-balances from its own network namespace, alongside nftables and blocky. The master reaches each exit over AmneziaWG by default, with VLESS+REALITY+XHTTP as a per-exit fallback switched live from the UI. Each exit runs awg-quick, an xray REALITY inbound for the fallback, wgcf for Cloudflare WARP egress that fails over to direct when a block is detected, policy routing, nftables and blocky, and leaves to the internet under a WARP IP or its own. Russian and private destinations go direct, never through an exit, and all management interfaces bind the ZeroTier overlay only.">

Two binaries. **`wgfleet-controller`** holds desired state, brokers keys,
provisions nodes and serves the API, UI and metrics. **`wgfleet-agent`** runs on
every managed node; its role (`master` or `exit`) comes from config. It pulls its
`NodeSpec`, drives the node to it idempotently, and reports health.

Tunnels are **AmneziaWG** by default, both client↔master and master↔exit; the
only vanilla-WireGuard tunnel is the external WARP tunnel to Cloudflare. Each
exit can additionally run a VLESS + REALITY + XHTTP transport as a **fallback
for when AmneziaWG is blocked** by DPI, switched per-exit from the Web UI, and
clients can connect to the master over VLESS as well as AmneziaWG.

---

## What you get

- **Declarative fleet** — describe masters and exits once; the reconcile loop
  converges every node and keeps it there.
- **Autoprovisioning** — a prepared Ubuntu VM (kernel module + ZeroTier join by
  `prepare-node.sh`, then SSH only) becomes a `Ready` exit node and joins the
  load balancer, from the CLI or a button in the Web UI.
- **Key broker for nodes** — a node's own AmneziaWG keys are generated on-node and
  never leave it. This does **not** extend to end-user credentials: the controller
  stores each client's private key so it can re-issue a config. See
  [Security model](#security-model).
- **Dry-run everywhere** — plan mode for reconcile, provisioning, upgrades and
  restore.
- **Support bundle** — one command produces a plain-text archive of diagnostic
  state for someone who cannot reach your servers. It carries no secrets, is not
  encrypted, and refuses to be written at all if a secret survives into it.
- **AmneziaWG obfuscation** — collision-safe S1–S4, per-end decoy traffic,
  computed MTU ([details](#amneziawg-done-right)).
- **Censorship-adaptive egress** — block detection with automatic WARP ↔ direct
  failover and a throughput watchdog that demotes a throttled path.
- **DPI-resistant client transport** — clients can connect over VLESS + REALITY
  + XHTTP alongside client AmneziaWG; credentials, QR and a ready-to-import
  Clash config are issued from the Web UI.
- **Client devices** — one link per device serves a mihomo subscription with
  AmneziaWG and VLESS on every master and switches between them on its own.
- **Reserve configs on exits (lifeline)** — an exit can carry a second
  client-facing AmneziaWG interface holding every issued credential; each person
  gets a reserve profile per such exit, added in advance, so losing the master
  does not cut them off.
- **Two-tier DNS filtering** — blocky on the master and on every exit, with
  conditional forwarding for local zones.
- **Scanner-resistant firewall** — rendered nftables with an auto-refreshed
  scanner-ASN blacklist and a management-overlay allowlist.
- **Observability** — Prometheus `/metrics` on every binary plus a built-in
  dashboard with fleet topology and per-node health.
- **Safe lifecycle** — graceful drain, decommission and teardown, versioned
  upgrades behind a wire-contract gate, and encrypted backup/restore.

---

## Try it locally

Runs the whole control plane on your laptop and shows what a node reconcile
*would* do. No root, no VPN tools, nothing to clean up but a directory. Requires
**Go 1.26+** and the source tree.

```sh
go build -o bin/wgfleet-controller ./cmd/wgfleet-controller
go build -o bin/wgfleet-agent      ./cmd/wgfleet-agent

cat > controller.yaml <<'YAML'
controller:
  listen:  "127.0.0.1:8443"
  webui:   "127.0.0.1:9000"
  metrics: "127.0.0.1:9300"
  store:   "state/state.db"
  pki:
    ca_cert: "state/ca.crt"
    ca_key:  "file://state/ca.key"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
      routing:    { direct_cidrs: [10.0.0.0/8], direct_geo: [RU], balance: health }
  exits:
    - name: exit-de-1
      region: de
      egress: warp
      address_pool: 10.81.0.0/24
      mgmt_addr: 10.20.0.5
      dns_filter: true
      firewall: { as_blacklist: true }
YAML

# Bootstrap the CA and issue each node an mTLS bundle.
bin/wgfleet-controller --config controller.yaml --init-pki
bin/wgfleet-controller --config controller.yaml --issue-node master-xa-1 --issue-out pki/master
bin/wgfleet-controller --config controller.yaml --issue-node exit-de-1   --issue-out pki/exit

# Serve gRPC + Web UI + metrics.
bin/wgfleet-controller --config controller.yaml &

cat > exit-agent.yaml <<'YAML'
agent:
  role: exit
  controller: "127.0.0.1:8443"
  node_id: "exit-de-1"
  identity: { cert: "pki/exit/node.crt", key: "pki/exit/node.key", ca: "pki/exit/ca.crt" }
YAML

# Register + publish this node's public key so the master can peer it.
bin/wgfleet-agent --config exit-agent.yaml --once \
  --public-ip 198.51.100.7 --mgmt-addr 10.20.0.5 --state-dir state/exit-de-1

# Plan it: renders awg0.conf, nftables, routing, wgcf and blocky — writes nothing.
bin/wgfleet-agent --config exit-agent.yaml --once --plan \
  --public-ip 198.51.100.7 --mgmt-addr 10.20.0.5 --state-dir state/exit-de-1

open http://127.0.0.1:9000                       # dashboard
curl -s http://127.0.0.1:9300/metrics | grep wgfleet_
```

Rendering, dry-run, PKI, transport, store, metrics and UI run cross-platform.
Applying is Linux-only: on macOS an apply stops at the first missing tool
(`nft`, `awg-quick`, `ip`, `wgcf`, `docker`) and reports `Error`.

---

## Deploy a real fleet

**Start with [`docs/QUICKSTART.md`](https://shidoh.github.io/wgfleet-docs/docs/QUICKSTART/)** — two blank Ubuntu
servers to a working VPN in about 30 minutes.

Each release ships one version-stamped archive per architecture containing both
binaries, the installer, `INSTALL.md`, reference configs and systemd units.
Unpack it on the master and run the installer; it installs the host dependencies
(AmneziaWG kernel module, ZeroTier, Docker), the binaries, the units and config
templates, then prints the remaining operator steps.

```sh
tar xzf wgfleet-<version>-linux-amd64.tar.gz && cd wgfleet-linux-amd64
sudo ./install.sh
# or seed values up front:
sudo ZT_NETWORK=<id> PUBLIC_IP=<ip> ./install.sh
```

The installer is idempotent and **starts nothing** — the master needs a
filled-in config and a locally-issued mTLS identity first, and it prints those
exact steps. The annotated manual equivalent is
[`docs/colocated-controller-master.md`](https://shidoh.github.io/wgfleet-docs/docs/colocated-controller-master/).

Adding an exit is one manifest entry plus one command (or the **Provision**
button in the UI):

```sh
# Dry-run: collect facts over SSH, show the bootstrap plan, change nothing.
wgfleet-controller --config controller.yaml --provision exit-de-1 --plan

# Apply: harden sshd, lay a baseline firewall, install deps, join ZeroTier,
# install the mTLS identity + agent binary + systemd unit, and start it.
wgfleet-controller --config controller.yaml --provision exit-de-1 \
  --agent-bin /usr/local/bin/wgfleet-agent
```

sshd hardening and a drop-all-but-SSH/ZT/WG baseline firewall land **before**
the node accepts traffic; the agent's own reconcile later replaces the baseline
with the full per-role ruleset.

Each VM needs the AmneziaWG kernel module and the ZeroTier join before
provisioning. One script per VM handles both:

```sh
ssh root@<vm-ip> 'bash prepare-node.sh <zerotier-network-id>'
```

The provisioner pre-flights the module and aborts if it is absent; it does not
build DKMS for you. Full walkthrough: [`docs/onboarding.md`](https://shidoh.github.io/wgfleet-docs/docs/onboarding/).

---

## How it works

<img src="assets/readme/lifecycle.svg" width="100%" alt="Node lifecycle. A node moves from Pending, meaning it is in the config but not yet touched, to Provisioning during SSH bootstrap of the blank VM, to Reconciling while it converges to its NodeSpec, to Ready once every self-check passes. From Reconciling or Ready a node drops to Degraded when a self-check fails or the agent goes silent past the staleness window, or to Error when a reconcile pass fails. Both recover back to Ready on the next good pass. Below the states, flags orthogonal to state, shown under the state pill in the console: drained (from the console, out of the balancer), drained by config (manifest drain: true), egress blocked (WARP unreachable, likely an ISP or DPI block), egress: direct (failed over, returns to WARP by itself), low throughput (below the floor, held out of the balancer) and decommissioning (data plane torn down, keys destroyed). NOT CARRYING in the topology is a grouping of exits the master is not routing through, not a state.">

- **Declarative desired state + reconcile.** You describe the fleet; agents
  converge each node toward its rendered `NodeSpec` and keep it there.
- **Dry-run is first-class.** Plan mode is side-effect-free; effects run only in
  apply mode.
- **The controller brokers node keys, never holding them.** Each node's AmneziaWG
  keys are generated and kept on that node; only the public key is published.
  End-user credentials are the exception — see the security model.
- **mTLS identity.** Each node gets a client certificate at bootstrap whose CN
  is its node ID. Removing a node from the inventory, or decommissioning it, makes
  the controller refuse to renew that certificate — see the gaps note below.
- **Self-checks drive lifecycle state.** After each apply the agent runs
  role-specific checks — handshake freshness, egress reachability, WARP egress,
  DNS filter, the lifeline interface, mihomo API — and the derived state feeds
  the dashboard and metrics.
  If an agent goes silent, a staleness sweep demotes its node to `Degraded`.
- **Customization without forking renderers.** Operators inject deep-merged
  `overrides` and extra files instead of patching the templates.

---

## AmneziaWG, done right

wgfleet derives the obfuscation parameters in code and verifies them against the
upstream kernel module and tools sources.

- **Identical on both ends:** `S1–S4` (junk prefix sizes) and `H1–H4` (packet
  junk header ranges). **Per-end:** `Jc`, `Jmin`, `Jmax` and `I1–I5`.
- **`H1–H4` are non-overlapping ranges** — the kernel enforces it.
- **`S1–S4` are message-size collision-safe.** The userspace classifier keys on
  packet size; a data packet that collides with a handshake size stalls roughly
  half of new TLS connections. The generator iterates until the sizes are safe.
- **`I1–I5`:** `I1` is a STUN Binding Request and `I2` a QUIC v1 Initial prefix
  with per-end sizes; `I3–I5` are empty. The random parts are regenerated by the
  module on every handshake initiation.
- **All obfuscation lives in `[Interface]`,** never in `[Peer]`, and shared
  parameters are derived deterministically from a per-tunnel seed so both ends
  compute the same set with no coordination.

---

## Security model

- Node AmneziaWG private keys are generated and stay **on the node**; the
  controller stores their public keys only.
- **End-user credentials are different.** So the console can re-issue a config,
  the controller's SQLite store holds every client's WireGuard **private key**
  (`client_wg_credentials.private_key`), alongside the fleet CA key and `awg3_key`
  when those are `file://` paths. The file is 0600 and not encrypted at rest.
  Anyone who obtains that one file — seizure, a provider snapshot, a stolen
  backup — de-anonymises every user, retroactively. Keep the encrypted backup
  somewhere the master is not.
- **mTLS** between controller and agents, one client certificate per node
  (CN = node ID), issued at bootstrap. Revocation removes the node.
- The Web UI, metrics and every node admin endpoint bind the **ZeroTier
  management overlay only**, never the public interface.
- SSH is used only during bootstrap, key-based; afterwards management is mTLS.
- A baseline firewall is installed **before** the node accepts traffic.
- sshd hardening (key-only auth, no root password, no X11) and a fail2ban sshd
  jail are **continuously reconciled**: a partial overwrite is repaired on the
  next pass. Each is individually switchable via `fleet.hardening`; both default
  to on.
- Secrets resolve through a provider (`env://`, a `0600` `file://`, or SOPS/age).
  No keys or real IPs in git.

Known gaps: there is **no certificate revocation list**. Node certificates last
a year and agents renew their own between 70% and 90% of that; the controller
refuses renewal for a node that has been decommissioned or deleted, but a
certificate already issued stays valid until it expires. Cutting a node off
sooner means reissuing the CA. The gRPC endpoints are **not rate-limited**, and
the Web UI speaks **plain HTTP** behind a password login; both rely on being
bound to the management overlay.

Reporting a vulnerability: [the security policy](https://shidoh.github.io/wgfleet-docs/SECURITY/).

---

## Status

MVP, in active development.

| Area | Status |
|---|---|
| Domain model, config, SQLite store, gRPC/mTLS transport, PKI, key broker | ✅ |
| Reconcile engine with first-class dry-run | ✅ |
| Exit data plane — awg-quick, wgcf/WARP, policy routing, nftables, blocky | ✅ |
| Master data plane — mihomo in its own network namespace, NAT, agent-owned client AWG interface, container lifecycle | ✅ |
| SSH provisioner, UI-triggered provisioning, agent upgrade, wire-contract gate | ✅ |
| Health checks, drift repair, graceful drain, teardown, staleness sweep | ✅ |
| AmneziaWG parameter generator, auto-MTU, SOPS/age secrets | ✅ |
| Egress-block detection + censorship-adaptive failover | ✅ |
| Web dashboard, Prometheus metrics, encrypted backup/restore | ✅ |
| Dual transport — VLESS + REALITY + XHTTP fallback, per-exit, live switch | ✅ |
| Client VLESS + REALITY + XHTTP — credentials and QR from the console | ✅ |
| Client devices — one mihomo subscription per device, AWG + VLESS with automatic fallback | ✅ |
| Lifeline — reserve client interface on exits, reserve profiles in the console and the portal | ✅ |
| Tiered exit selection, throughput watchdog with auto-suspend, drain by config | ✅ |
| Console login, certificate self-renewal, node tombstones | ✅ |
| AmneziaWG 3.x — plumbing shipped, **off by default** | ⏸ |

Apply-side actions and live SSH are supported on **Linux**: Ubuntu 24.04 is
the tested platform; 22.04 works but is not guaranteed
([requirements](https://shidoh.github.io/wgfleet-docs/docs/requirements/)).
Automatic AmneziaWG → REALITY failover is not implemented; switching transports
is a manual, per-exit action.

**AmneziaWG 3.x is off by default.** The knobs are `fleet.awg3`,
`fleet.exits[].awg3` (master↔exit tunnels) and
`masters[].client_awg.awg3: off | timers | full` (the client interface). Two
gates stand behind them: the controller requires wire v7 from **both** ends of a
tunnel, and each agent requires a 3.x kernel module on its own node, so a
premature flip stays on 2.0 rather than producing a dead tunnel. Header
protection additionally needs a `fleet.awg3_key` secret and is incompatible with
2.0 peers: every client must re-import. The timers half needs no client change.
Enable order: [AmneziaWG 3.x for clients](https://shidoh.github.io/wgfleet-docs/docs/client-migration/).

---

## Reference

| Document | What it covers |
|---|---|
| [Quickstart](https://shidoh.github.io/wgfleet-docs/docs/QUICKSTART/) | Two blank servers to a working VPN, start here |
| [System requirements](https://shidoh.github.io/wgfleet-docs/docs/requirements/) | System requirements and compatibility: supported OS, sizing, pinned versions, controller↔agent contract |
| [Manifest](https://shidoh.github.io/wgfleet-docs/docs/manifest/) | Annotated `controller.yaml` and `agent.yaml`, with secret schemes |
| [Key reference](https://shidoh.github.io/wgfleet-docs/docs/configuration/) | Exhaustive per-key reference |
| [CLI](https://shidoh.github.io/wgfleet-docs/docs/cli/) | Every flag on both binaries |
| [Operations](https://shidoh.github.io/wgfleet-docs/docs/operations/) | Dashboard, VLESS client access, backup/restore, metrics, health |
| [Recipes](https://shidoh.github.io/wgfleet-docs/docs/recipes/ru-split-tunnel-dns-filter/) | Task-oriented configs, e.g. split-tunnel + DNS filtering |
| [Onboarding a node](https://shidoh.github.io/wgfleet-docs/docs/onboarding/) | Node prerequisites and the provisioning walkthrough |
| [Controller on the master](https://shidoh.github.io/wgfleet-docs/docs/colocated-controller-master/) | Running the controller on the master, the small-fleet default |
| [Upgrading](https://shidoh.github.io/wgfleet-docs/docs/upgrade/) | Agent upgrades and wire-contract versioning |
| [AmneziaWG 3.x for clients](https://shidoh.github.io/wgfleet-docs/docs/client-migration/) | AmneziaWG 3.x on the client interface: `timers`, `full`, the `full` rollout |
| [Moving the master](https://shidoh.github.io/wgfleet-docs/docs/master-migration/) | Moving the controller and master to another host |
| [Support bundle](https://shidoh.github.io/wgfleet-docs/docs/support-bundle/) | Collecting a secret-free diagnostic archive |
| [Secrets with SOPS](https://shidoh.github.io/wgfleet-docs/docs/secrets-sops/) | SOPS/age secret provider setup |
| [Security policy](https://shidoh.github.io/wgfleet-docs/SECURITY/) | Reporting vulnerabilities and operating securely |

### Build & test

Requires **Go 1.26+** and the source tree. Regenerating protobuf additionally
needs `protoc` on PATH.

```sh
make build                        # go build ./...
make test                         # go test ./...
make race                         # go test -race ./...
make vet fmt                      # go vet ./... ; gofmt -w
make proto                        # regenerate gRPC from proto/
make agent-linux ARCH=amd64       # versioned Linux agent into dist/
make controller-linux ARCH=amd64  # versioned Linux controller into dist/
make release-archive ARCH=amd64   # the shippable archive
```

No JS toolchain or codegen is needed for the Web UI.

---

## License

wgfleet is licensed under the **GNU Affero General Public License, version 3**
(AGPL-3.0) — see [LICENSE](LICENSE).

Copyright (C) 2026 John Smith and wgfleet contributors.

Under the AGPL's network clause (section 13), if you run a modified wgfleet to
operate a fleet for anyone other than yourself, you must offer those users the
corresponding source of your modifications. Running an unmodified wgfleet, or a
modified one purely for your own use, triggers no such obligation.

This program is distributed in the hope that it will be useful, but **WITHOUT
ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the license for details, and
[the disclaimer](https://shidoh.github.io/wgfleet-docs/DISCLAIMER/) for the operational and legal caveats specific to
running censorship-circumvention infrastructure.
