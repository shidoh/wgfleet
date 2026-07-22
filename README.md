# wgfleet

A Go **control plane for a fleet of WireGuard / AmneziaWG VPN nodes**. The
operator declares the desired fleet in a config file; the platform provisions
each node from a blank VM and holds it at that desired state with a pull-based
reconcile loop — kubelet / Cluster API, but for censorship-circumvention VPN exit
nodes.

It automates a real, hand-built topology (RU gateway + EU exit nodes + Cloudflare
WARP, with AmneziaWG obfuscation, mihomo load-balancing, blocky DNS filtering and
ZeroTier management overlay). The hard-won operational lessons from running that
by hand are baked into the reconcile logic, not left as comments.

**AmneziaWG is the primary transport** between the master and the exits. Each
exit can additionally run a VLESS + REALITY + XHTTP transport as a **fallback for
when AmneziaWG is blocked** by DPI (e.g. an exit on a censored network path) — the
operator switches that exit to the fallback from the Web UI; AWG stays the default
everywhere else.

> Working language: **all code, comments, identifiers, logs and commits are in
> English.** Project design notes (`docs/DESIGN.md`) and discussion are in Russian.

> ⚠️ **Disclaimer.** wgfleet is research / infrastructure-automation software for
> **lawful** use only, provided **without warranty**. It operates VPN and
> traffic-obfuscation infrastructure; the legality of deploying, operating, or
> using such tools varies by jurisdiction and is **your responsibility**. Read
> [DISCLAIMER.md](DISCLAIMER.md) before using it.

📄 [Disclaimer](DISCLAIMER.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [Reference architecture](#2-reference-architecture)
3. [Platform architecture](#3-platform-architecture)
4. [Core concepts](#4-core-concepts)
5. [Current status](#5-current-status)
6. [Repository layout](#6-repository-layout)
7. [Build & test](#7-build--test)
8. [Quick start (local dry-run)](#8-quick-start-local-dry-run)
9. [Installation & deployment](#9-installation--deployment)
10. [Configuration reference](#10-configuration-reference)
11. [CLI reference](#11-cli-reference)
12. [Operations](#12-operations)
13. [AmneziaWG parameter rules](#13-amneziawg-parameter-rules)
14. [Security model](#14-security-model)
15. [Design decisions (ADRs)](#15-design-decisions-adrs)
16. [Roadmap](#16-roadmap)

---

## 1. What it does

| Without wgfleet | With wgfleet |
|---|---|
| SSH into each VM, run Ansible/manual steps | Declare the node in `fleet.yaml` |
| Copy WireGuard keys around by hand | Keys generated on-node; controller brokers public keys only |
| Hand-edit AmneziaWG obfuscation in a UI | Parameters derived deterministically and rendered/applied |
| Tweak mihomo / nftables / routing per node | Rendered from desired state, idempotently |
| Hope nothing drifted | Reconcile loop converges + reports health |
| No fleet-wide view | Web dashboard + Prometheus metrics |

The headline feature is **autoprovisioning**: point the controller at a blank
Ubuntu VM (SSH only) and it turns it into a `Ready` exit node — AmneziaWG server,
WARP egress, DNS filtering, policy routing, firewall, metrics — and joins it to
the load balancer on the master.

### Features

- **Declarative fleet** — describe masters and exits in `fleet.yaml`; the
  reconcile loop converges every node to that state and keeps it there.
- **Autoprovisioning** — bootstrap a blank Ubuntu VM (SSH only) into a `Ready`
  exit node, then join it to the load balancer automatically.
- **Key broker, not key store** — WireGuard/AmneziaWG keys are generated on-node;
  the controller renders peer topology from public keys only.
- **Dry-run / plan everywhere** — a first-class, side-effect-free plan mode shows
  the rendered configs and diffs (secrets redacted) before anything is applied.
- **AmneziaWG obfuscation, done right** — collision-safe S1-S4, per-end decoy
  (Jc/Jmin/Jmax + I1-I5 real-protocol mimicry), computed MTU — encoded in the
  renderer, not left to guesswork.
- **Censorship-adaptive egress** — block detection and automatic egress failover
  (WARP ↔ direct), with a throughput watchdog so a throttled path is demoted.
- **AmneziaWG-first, REALITY fallback** — AmneziaWG is the primary master↔exit
  transport; each exit can also run a VLESS + REALITY + XHTTP transport as a
  fallback for when AWG is blocked by DPI, switchable live from the Web UI.
- **DPI-resistant client transport** — clients can also connect over VLESS +
  REALITY + XHTTP (alongside client AmneziaWG) for paths where AWG is throttled.
  Per-client credentials are issued in the Web UI — vless:// link, QR, a
  subscription, and a ready-to-import Clash config — and their traffic converges
  into the same mihomo routing, so internal/ZeroTier networks stay reachable
  through the master (ADR-0031).
- **Two-tier DNS filtering** — blocky on the master and exits, with conditional
  forwarding for local zones.
- **Scanner-resistant firewall** — rendered nftables with an auto-refreshed
  scanner-ASN blacklist and a management-overlay allowlist.
- **Observability** — Prometheus `/metrics` on every binary plus a built-in Web
  dashboard with fleet topology and per-node health.
- **Safe lifecycle** — graceful drain, decommission/teardown, versioned upgrades
  with a wire-contract gate, and built-in encrypted controller backup/restore.

---

## 2. Reference architecture

This is the real topology being automated. IPs/keys/ports are config & secrets,
never in the repo.

```
Clients (AmneziaWG)
    │
    ▼
MASTER  (role: master, RU VPS — "ru-gw")
  ├── wg-easy          client-facing AmneziaWG server (UI/QR for client mgmt)
  ├── mihomo           proxy router + load balancer (tproxy/redir mode)
  │     ├── RU / private destinations → DIRECT
  │     └── everything else           → one of the exit nodes (load-balanced)
  └── nftables         DNAT clients→mihomo, MASQUERADE, DROP QUIC (UDP/443)
    │
    ▼  (AmneziaWG, one tunnel per exit — carried inside mihomo)
EXIT  (role: exit, EU VPS — "exit-a/exit-b/exit-c")
  ├── awg-quick        AmneziaWG server (accepts the tunnel from the master)
  ├── wgcf             Cloudflare WARP egress (Table=off, computed MTU)
  ├── blocky           DNS filtering
  ├── policy routing   client traffic → WARP; SSH/ZT/handshake → direct
  └── nftables         firewall + AS-blacklist + whitelist
    │
    ▼
Internet (egress under a Cloudflare WARP IP)
```

- **All fleet-internal tunnels are AmneziaWG** (client↔master and master↔exit),
  not vanilla WireGuard. The only vanilla-WG leg is the external WARP tunnel to
  Cloudflare (Cloudflare does not speak AmneziaWG).
- Management (admin UIs, metrics, DNS) listens on the **ZeroTier overlay only**,
  never on the public interface.

---

## 3. Platform architecture

```
                 ┌─────────────────────────────────────────────┐
                 │                 CONTROLLER                    │
                 │  - desired fleet state (config) + inventory   │
                 │  - SQLite state store                         │
                 │  - PKI (CA) + key broker (public keys only)   │
                 │  - NodeSpec renderer (topology, AWG params)   │
                 │  - provisioner (SSH bootstrap of blank VMs)   │
                 │  - gRPC/mTLS API   - Web UI   - /metrics       │
                 └───────────────┬─────────────────────────────┘
                                 │  pull NodeSpec / push status+pubkey (mTLS)
            ┌────────────────────┼───────────────────────────┐
            ▼                                                 ▼
   ┌──────────────────┐                          ┌──────────────────┐
   │ AGENT role=master│                          │ AGENT role=exit  │
   │  reconcile:      │◄──── AmneziaWG tunnels ──►│  reconcile:      │
   │  - wg-easy AWG   │      (inside mihomo)      │  - awg-quick     │
   │  - mihomo config │                          │  - wgcf / WARP   │
   │  - master NAT    │                          │  - policy routing│
   │                  │                          │  - nftables      │
   │                  │                          │  - blocky DNS    │
   └──────────────────┘                          └──────────────────┘
```

- **Controller** holds desired state, brokers keys, provisions nodes, serves the
  API/UI/metrics. One binary: `wgfleet-controller`.
- **Agent** runs on every managed node; its role (`master`/`exit`) comes from
  config. One binary: `wgfleet-agent`. It pulls its `NodeSpec`, drives the node
  to it idempotently, and reports health.

---

## 4. Core concepts

- **Declarative desired state + reconcile.** The operator describes the fleet;
  agents converge each node toward its rendered `NodeSpec` and keep it there.
- **Dry-run is first-class.** Every reconcile can run as a *plan*: it renders all
  configs and the exact changes, and **writes nothing**. One engine
  (`reconcile.Engine`) enforces this for all components — `Plan()` is
  side-effect-free; effects run only in apply mode. (ADR-0004)
- **The controller brokers public keys, never private keys.** WireGuard keys are
  generated and kept on each node; only the public key is published. A
  compromised controller cannot leak node private keys. (ADR-0003)
- **mTLS identity.** Each node gets a client certificate at bootstrap; its CN is
  its node ID. Revoking the cert removes the node from the fleet. (ADR-0001)
- **AmneziaWG everywhere**, with parameters verified against the upstream kernel
  module and tools sources. (ADR-0005, [§13](#13-amneziawg-parameter-rules))
- **Config customization without forking renderers.** Operators inject arbitrary
  overrides (deep-merged) and extra files via `CustomConfig`. (ADR-0007)
- **Node lifecycle:** `Pending → Provisioning → Reconciling → Ready / Degraded /
  Error`, driven by agent self-checks. (ADR-0009)

---

## 5. Current status

MVP, in active development. Implemented and tested (`go test -race` green):

| Area | Status | Where |
|---|---|---|
| Domain model, config (koanf/YAML + secrets), SQLite store | ✅ | `internal/domain`, `internal/config`, `internal/controller/store` |
| Controller↔agent transport: gRPC over mTLS, identity = cert CN | ✅ | `internal/api`, `internal/controller/grpcapi`, `internal/agent/client` |
| PKI: CA bootstrap, per-node cert issuance, mTLS configs | ✅ | `internal/controller/pki` |
| Key broker: pubkey registry + topology/NodeSpec rendering | ✅ | `internal/controller/keybroker` |
| Reconcile engine with first-class dry-run | ✅ | `internal/agent/reconcile` |
| Exit data plane: awg-quick, wgcf (Table=off/MTU), routing, nftables | ✅ | `internal/agent/exit`, `internal/{wg,egress,routing,netfw}` |
| Exit DNS filter: blocky container, override-config, ZT-only binds | ✅ | `internal/dnsfilter`, `internal/compose` |
| Master data plane: mihomo (proxies+LB+rules), NAT, custom config | ✅ | `internal/agent/master`, `internal/mihomo` |
| Master client AWG via wg-easy SQLite DB | ✅ | `internal/wgeasy` |
| Provisioner: SSH bootstrap (facts, preflight, plan) | ✅ | `internal/controller/provisioner` |
| Health checks → Ready/Degraded/Error | ✅ | `internal/agent/health` |
| Web UI: dashboard + drain/undrain/delete actions | ✅ | `internal/controller/web` |
| Prometheus `/metrics` (controller + agent) + wire/build version info | ✅ | `internal/metrics` |
| Node upgrade procedure (agent binary roll-forward via SSH) | ✅ | `internal/controller/provisioner`, `internal/controller/provmgr` |
| Wire-contract versioning (gRPC-metadata gate, auto-upgrade, store migrations) | ✅ | `internal/version`, `internal/api`, `internal/controller/grpcapi` |
| AmneziaWG parameter generator (S1-S4, H1-H4, per-end Jc/Jmin/Jmax/I1-I5) | ✅ | `internal/wg` |
| Secrets via SOPS/age (config.SOPSProvider, in-memory CA-key load) | ✅ | `internal/config` |
| Egress-block detection + censorship-adaptive failover (warp → direct chain) | ✅ | `internal/agent/egress`, `internal/agent/health` |
| Drift observability + live-kernel drift repair | ✅ | `internal/agent/reconcile`, `internal/routing` |
| Health-based LB (mihomo native wg-best check) | ✅ | `internal/mihomo` |
| Graceful drain (LB exclusion) | ✅ | store + keybroker + `internal/mihomo` |
| Staleness sweep (silent node → Degraded) | ✅ | `internal/controller/sweeper` |
| Master container lifecycle (compose up/restart) | ✅ | `internal/compose` + master planners |
| Node teardown / decommission (reverse reconcile) | ✅ | `internal/agent/{exit,master}` teardown |
| Provisioning from the UI (async) | ✅ | `internal/controller/provmgr` |

**MVP Phase 1 is complete.** **Phase 2 is complete** — drift auto-reconcile,
health-based balancing, AmneziaWG parameter generator (S1-S4, per-end decoy),
SOPS/age secrets, and auto-MTU calculator. **Phase 3 in progress** — egress-block
detection and censorship-adaptive failover done; traffic-noise remaining. **Stabilization
in progress** — upgrade procedure + wire-contract versioning (ADR-0019) complete.

> **Platform note:** apply-side exec actions (`nft -f`, `awg-quick`, `ip`,
> `wgcf`, `docker`) and live SSH are **validated on Linux** (live 2-VM Ubuntu 24.04
> ARM64 runs 2026-06-11/12; ~13 real bugs fixed). On the macOS dev box they render
> and unit-test via mocks but are not executed; an apply there reports `Error` at the
> first missing tool. All *rendering*, *dry-run*, PKI, transport, store, metrics and
> UI run fully cross-platform.

---

## 6. Repository layout

```
wgfleet/
├── cmd/
│   ├── wgfleet-controller/     control plane: API + UI + metrics + provisioner + PKI tooling
│   └── wgfleet-agent/          node agent: reconcile daemon (role from config)
├── internal/
│   ├── domain/                 core types: NodeSpec, AWG params, MasterSpec, CustomConfig …
│   ├── config/                 koanf/YAML config + secret references
│   ├── api/                    proto ⇄ domain conversion (+ generated pb)
│   ├── controller/
│   │   ├── store/              SQLite inventory / pubkey registry / status
│   │   ├── pki/                CA + per-node certs + mTLS configs
│   │   ├── keybroker/          pubkey registry + NodeSpec/topology rendering
│   │   ├── grpcapi/            NodeService gRPC server (mTLS)
│   │   ├── provisioner/        SSH bootstrap pipeline (facts, plan, runner+mock)
│   │   ├── provmgr/            provisioning orchestration (sync CLI + async UI)
│   │   ├── sweeper/            demotes silent nodes to Degraded
│   │   └── web/                dashboard + drain/undrain/delete actions
│   ├── agent/
│   │   ├── client/             agent mTLS gRPC client
│   │   ├── reconcile/          plan/apply engine (dry-run core)
│   │   ├── exit/               exit-role planners
│   │   ├── master/             master-role planners (mihomo + NAT + wg-easy AWG)
│   │   └── health/             self-checks → node lifecycle state
│   ├── wg/                     WG/AWG render, key gen, MTU math, AWG param generator
│   ├── netfw/                  nftables render (exit firewall + master NAT)
│   ├── routing/                policy-routing render (ip rule/route, fwmark)
│   ├── egress/                 wgcf / WARP config render
│   ├── dnsfilter/              blocky config render
│   ├── mihomo/                 mihomo config render (+ overrides deep-merge)
│   ├── compose/                master docker-compose render (wg-easy + mihomo)
│   ├── wgeasy/                 wg-easy SQLite AWG configuration
│   └── metrics/                Prometheus collectors (controller store + agent)
├── proto/wgfleet/v1/           gRPC contract
├── deploy/
│   ├── systemd/                unit templates
│   └── examples/               example controller.yaml / agent.yaml
├── internal/version/           build version (stamped via -ldflags at compile)
├── docs/
│   ├── DESIGN.md               full project context + conventions
│   ├── lessons.md              hard-won operational lessons baked into reconcile
│   ├── adr/                    architecture decision records (0001–0027)
│   ├── onboarding.md           node provisioning walkthrough
│   ├── colocated-controller-master.md  co-location on the master (default for small fleets)
│   ├── secrets-sops.md         SOPS/age secret provider setup
│   └── upgrade.md              agent binary upgrade procedure + wire-contract versioning
├── DISCLAIMER.md  ·  SECURITY.md  ·  CONTRIBUTING.md
```

---

## 7. Build & test

Requires **Go 1.26+**. Protobuf regeneration additionally needs `protoc` on PATH
(the Go plugins are pinned as `tool` directives in `go.mod`).

```sh
make build      # go build ./...
make test       # go test ./...
make race       # go test -race ./...
make vet        # go vet ./...
make fmt        # gofmt -w
make proto      # regenerate gRPC from proto/ (needs protoc)
make agent-linux ARCH=amd64     # agent binary for Linux (amd64 | arm64)
make controller-linux ARCH=amd64 # controller binary for Linux
```

The `agent-linux` / `controller-linux` targets produce versioned binaries in
`dist/` with build version, commit and timestamp stamped via `-ldflags`.

Or directly:

```sh
go build ./cmd/wgfleet-controller ./cmd/wgfleet-agent
go test -race ./...
```

No JS toolchain or codegen is needed for the Web UI (stdlib `html/template` +
embedded htmx).

---

## 8. Quick start (local dry-run)

This runs the whole control plane locally and shows what a node reconcile *would*
do, changing nothing. No root, no VPN tools required.

```sh
# 0. Build
go build -o bin/wgfleet-controller ./cmd/wgfleet-controller
go build -o bin/wgfleet-agent      ./cmd/wgfleet-agent

# 1. A minimal controller.yaml (loopback; file:// CA key for the CA tooling)
cat > controller.yaml <<'YAML'
controller:
  listen:  "127.0.0.1:8443"
  webui:   "127.0.0.1:9000"
  metrics: "127.0.0.1:9300"
  store:   "/tmp/wgfleet/state.db"
  pki:
    ca_cert: "/tmp/wgfleet/ca.crt"
    ca_key:  "file:///tmp/wgfleet/ca.key"
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

# 2. Bootstrap the CA and issue node mTLS bundles
bin/wgfleet-controller --config controller.yaml --init-pki
bin/wgfleet-controller --config controller.yaml --issue-node master-xa-1 --issue-out pki/master
bin/wgfleet-controller --config controller.yaml --issue-node exit-de-1   --issue-out pki/exit

# 3. Run the controller (serves gRPC + UI + metrics)
bin/wgfleet-controller --config controller.yaml &

# 4. The exit registers + publishes its WG public key so the master can peer it
cat > exit-agent.yaml <<'YAML'
agent:
  role: exit
  controller: "127.0.0.1:8443"
  node_id: "exit-de-1"
  identity: { cert: "pki/exit/node.crt", key: "pki/exit/node.key", ca: "pki/exit/ca.crt" }
YAML
bin/wgfleet-agent --config exit-agent.yaml --once \
  --public-ip 198.51.100.7 --mgmt-addr 10.20.0.5 --state-dir /tmp/wgfleet/exit

# 5. DRY-RUN the exit: prints the full rendered plan (awg0.conf, nftables,
#    routing, wgcf, blocky) and writes NOTHING.
bin/wgfleet-agent --config exit-agent.yaml --once --plan \
  --public-ip 198.51.100.7 --mgmt-addr 10.20.0.5 --state-dir /tmp/wgfleet/exit

# 6. DRY-RUN the master: mihomo config (exits as wireguard+amnezia-wg-option
#    proxies, load-balance group, RU-direct rules), direct-networks.yaml,
#    master NAT, and the wg-easy AWG SQL update.
cat > master-agent.yaml <<'YAML'
agent:
  role: master
  controller: "127.0.0.1:8443"
  node_id: "master-xa-1"
  identity: { cert: "pki/master/node.crt", key: "pki/master/node.key", ca: "pki/master/ca.crt" }
YAML
bin/wgfleet-agent --config master-agent.yaml --once --plan \
  --public-ip 203.0.113.1 --mgmt-addr 10.20.25.254 --state-dir /tmp/wgfleet/master

# 7. Look at the dashboard and metrics
open http://127.0.0.1:9000          # fleet list + node detail
curl -s http://127.0.0.1:9300/metrics | grep wgfleet_
```

Drop `--plan` to apply (only meaningful on a Linux node with `nft`, `awg-quick`,
`ip`, `wgcf`, `docker`). `--state-dir` roots managed files outside `/etc` for
non-root/dev runs.

---

## 9. Installation & deployment

### 9.0 Master bootstrap (fastest path)

**New here? Follow [`docs/QUICKSTART.md`](docs/QUICKSTART.md)** — two blank
Ubuntu servers to a working VPN in ~30 minutes, no prior knowledge assumed.

Each release ships **one archive per architecture**
(`wgfleet-linux-amd64.tar.gz` / `wgfleet-linux-arm64.tar.gz`) containing both
binaries, the installer, `INSTALL.md` (the quickstart), reference configs and
the systemd units. Unpack it on the master and run the installer — it installs
the host deps (AmneziaWG kernel module, ZeroTier, Docker), the binaries, the
systemd units and config templates, then prints the remaining operator steps:

```sh
tar xzf wgfleet-linux-amd64.tar.gz && cd wgfleet-linux-amd64
sudo ./install.sh
# or seed values up front:
sudo ZT_NETWORK=<id> PUBLIC_IP=<ip> ./install.sh
```

The same script also works standalone, downloading and checksum-verifying the
archive itself (needs a **public repo** and a **published release** — see
[CONTRIBUTING.md § Cutting a release](CONTRIBUTING.md#cutting-a-release)):

```sh
curl -fsSL https://raw.githubusercontent.com/shidoh/wgfleet/main/install.sh | sudo bash
```

It is idempotent and **does not start anything** — the master needs a filled-in
config and a locally-issued mTLS identity first; the installer prints those exact
steps. The manual, annotated equivalent is
[`docs/colocated-controller-master.md`](docs/colocated-controller-master.md).

### 9.1 Per-node prerequisites

The platform orchestrates existing tools; install them on the target VMs.

**Both roles**

- Ubuntu 24.04, root via SSH key (password auth disabled), public IP.
- ZeroTier (joined to the management network).
- **AmneziaWG kernel module** — a hard pre-flight requirement. The provisioner
  checks for it and aborts if absent (it does not build DKMS for you):
  ```sh
  git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
  cd amneziawg-linux-kernel-module && make && make install
  modprobe amneziawg && echo amneziawg >> /etc/modules
  ```
- `amneziawg-tools` (`awg`, `awg-quick`), `nftables`, `conntrack`.

**Exit nodes additionally:** `wgcf` (Cloudflare WARP), `blocky` (DNS filter).

**Master nodes additionally:** Docker (for `mihomo` and `wg-easy` containers).

### 9.2 Controller host

The controller can be co-located on the master or run on a separate host. It
needs the SQLite store path, the CA, and reachability to nodes over the mgmt
overlay (and SSH to blank VMs for provisioning).

```sh
# Bootstrap the CA once (cert is public; key is a secret — keep it 0600 / in a
# secret manager).
wgfleet-controller --config /etc/wgfleet/controller.yaml --init-pki

# Serve (gRPC API + Web UI + metrics). In production run under systemd.
wgfleet-controller --config /etc/wgfleet/controller.yaml
```

### 9.3 Provisioning a node (SSH bootstrap)

With the node's `ssh:` target set in the fleet manifest:

```sh
# Dry-run: collect facts over SSH, show the bootstrap plan, change nothing.
wgfleet-controller --config controller.yaml --provision exit-de-1 --plan

# Apply: harden sshd, baseline firewall, install deps, join ZeroTier, install
# the node's mTLS identity + the agent binary + a systemd unit, and start it.
wgfleet-controller --config controller.yaml --provision exit-de-1 \
  --agent-bin /usr/local/bin/wgfleet-agent
```

The bootstrap order is security-first: hardening + a drop-all-but-SSH/ZT/WG
baseline firewall are applied **before** the node accepts traffic; the agent's
own reconcile later replaces the baseline with the full per-role ruleset.

The same provisioning can be triggered **from the Web UI**: a node declared in
the manifest appears as `Pending`; the **Provision** button SSH-bootstraps it
asynchronously (set `controller.agent_bin` so the agent binary is installed).

### 9.4 Agent (already installed by the provisioner)

The provisioner writes `/etc/wgfleet/agent.yaml`, the node mTLS bundle, the
binary and a `wgfleet-agent.service` unit (see `deploy/systemd/`). The agent then
runs as a daemon, reconciling on its interval and on start.

---

## 10. Configuration reference

Two YAML files: the **controller config** (`controller.yaml`, which embeds the
**fleet manifest**) and the per-node **agent config** (`agent.yaml`). Flags
override file values; `WGFLEET_`-prefixed env vars override too (e.g.
`WGFLEET_CONTROLLER_LISTEN=...` → `controller.listen`).

### 10.1 `controller.yaml`

```yaml
controller:
  listen:  "10.20.25.254:8443"    # gRPC/mTLS API for agents — the mgmt/ZT address agents
                                   # dial; baked into agent configs and the server cert SAN.
  advertise: "10.20.25.254:8443"  # when listen differs from the dialable address (e.g. controller
                                   # behind NAT/gateway). becomes the default endpoint baked into
                                   # agents and seeds an extra SAN on the server cert.
  webui:   "10.20.25.254:9000"    # read-only dashboard; bind mgmt/ZT only (empty disables)
  metrics: "10.20.25.254:9300"    # Prometheus /metrics; bind mgmt/ZT only (empty disables)
  store:   "/var/lib/wgfleet/state.db"
  agent_bin: "/usr/local/bin/wgfleet-agent"  # agent binary installed during UI-triggered provisioning (optional)
  staleness_after: 3m              # silent Ready/Reconciling node → Degraded after this (0=default, <0 disables)
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key:  "file:///etc/wgfleet/ca.key"   # CA tooling needs a file:// path; keep 0600 / secret manager
  secrets:
    sops_file: "/etc/wgfleet/secrets.enc.yaml"  # enables SOPS/age provider (optional; omit for env:// default)

fleet:
  zerotier_network: "8056c2e21c000001"      # mgmt overlay nodes join at bootstrap
  reconcile_interval: 30s                    # fleet-wide agent reconcile/self-heal cadence
                                             #   (default 30s; baked into each agent.yaml)

  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254              # ZeroTier address
      client_awg:
        listen_port: 443                    # UDP; standard ports are less conspicuous
        address_pool: 10.80.0.0/24          # client WG subnet
      client_vless:                         # DPI-resistant client transport, alongside client_awg (ADR-0031)
        enabled: true                       # omit the block to leave it off
        # listen_port: 0 ⇒ per-master high port in [40000,60000] (443 is inspected; high ports pass)
        # empty_sni: true (default) — no-SNI ClientHello (RU-TSPU bypass)
        route_through_cidrs:                # internal nets clients route THROUGH the tunnel (else macOS bypasses them)
          - 172.29.0.0/16                   # e.g. the ZeroTier mgmt overlay
      routing:
        direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
        direct_geo:   [RU]                  # GEOSITE/GEOIP → DIRECT
        balance:      url-test              # round-robin | consistent-hashing (alias: health) | sticky-sessions | url-test | fallback
      mihomo:                               # master data-plane tuning + custom-config hooks
        health_interval: 30s                # how often mihomo health-checks exits to route around dead ones (default 60s)
        sniffer_skip: ["+.themoviedb.org", "+.cloudfront.net"]  # CDNs that break under sniffing
        dashboard_url: "https://mirror.example/zashboard"  # override mihomo web-dashboard URL (empty ⇒ default GitHub)
        dashboard_disabled: false           # set true to disable the web dashboard entirely
        overrides:                          # deep-merged into the rendered mihomo config.yaml
          log-level: info
        extra_files:                        # provisioned alongside config.yaml (mihomo include files)
          - path: direct-domains.yaml
            content: |
              payload:
                - mycompany.example
      compose:                              # master container stack; every image+tag is pin-able
        wg_easy_image: ghcr.io/wg-easy/wg-easy   # repository (default …:15)
        wg_easy_tag:   "15"                 # explicit tag overrides any tag in the image
        mihomo_image:  metacubex/mihomo
        mihomo_tag:    "v1.19.29"           # pin a version (NOT :latest, NOT Alpha — a moving
                                            #   tag defeats the pin) (#8). Default is v1.19.29.
      ssh:                                  # bootstrap target (Phase 0/1 only)
        host: 203.0.113.1
        port: 22                            # SSH port (optional; default 22)
        user: root
        key_path: /etc/wgfleet/bootstrap_ed25519
        # host_key: "ssh-ed25519 AA..."    # (optional) pin the server SSH host key (strongly recommended)
        # insecure_ignore_host_key: true   # skip host-key check for this node (or WGFLEET_SSH_INSECURE_HOST_KEY=1 fleet-wide)

  exits:
    - name: exit-de-1
      region: de
      egress: warp                          # preferred egress method: warp | direct
      egress_fallback: [direct]             # ordered fallbacks for censorship-adaptive failover (ADR-0017)
      warp_mtu: 0                           # WARP interface MTU; 0 ⇒ default 1380 + auto-probe (tracepath, capped, only lowers). Set if the real path is < that.
      address_pool: 10.81.0.0/24
      mgmt_addr: 10.20.0.5                 # ZeroTier address (admin/metrics/DNS bind)
      transports:                           # master↔exit transport(s), ADR-0025; omit ⇒ AWG-only
        awg: { enabled: true, listen_port: 0 }       # primary transport. WG UDP port; 0 ⇒ stable-random derived
        reality:                            # fallback transport (VLESS+REALITY+XHTTP, xray) for when AWG is DPI-blocked
          enabled: true
          listen_port: 443                  # default 443; must differ from the AWG port
          dest_domain: www.python.org       # camouflage dest — MUST support X25519MLKEM768 (verify `xray tls ping`); not Cloudflare-fronted
          dest_port: 443
          sni: www.python.org               # empty ⇒ = dest_domain
          mode: xhttp                       # xhttp (default; packet-up dodges volume-freeze) | vision (TCP + xtls-rprx-vision)
          mux: true                         # XMUX connection reuse — amortizes the per-connection handshake (xhttp only)
          fingerprint: chrome               # uTLS fingerprint: chrome | firefox | none
          empty_sni: false                  # true ⇒ no-SNI ClientHello (RU-TSPU heuristic bypass)
          allow_ipv6: false                 # false ⇒ pin xray resolution to IPv4 (IPv4-only data plane)
          # image: ghcr.io/xtls/xray-core:26.6.22   # unset ⇒ pinned default
      active_transport: awg                 # awg (default/primary) | reality-xhttp (fallback); flip live in the Web UI
      dns_filter: true                      # blocky (Docker); binds loopback + mgmt_addr ONLY
      dns:                                  # optional blocky tuning (ZT-only binds enforced regardless)
        image: spx01/blocky                 # repository …
        tag:   latest                       # … + tag (both pin-able; default spx01/blocky:latest)
        allowlist: ["*.example.net"]        # never-blocked domains (platform infra auto-added)
        overrides:                          # raw blocky YAML, deep-merged (denylists, conditional, caching)
          blocking:
            denylists:
              ads: [https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt]
            clientGroupsBlock:
              default: [ads]
      firewall:
        as_blacklist: true
        whitelist: [10.20.0.0/16]
      ssh:
        host: 198.51.100.7
        port: 22
        user: root
        key_path: /etc/wgfleet/bootstrap_ed25519
        # host_key: "ssh-ed25519 AA..."
```

Every dockerized component (wg-easy, mihomo, blocky) exposes an `image` +
`tag` pair so both can be pinned for reproducible/auditable deployments. An
explicit `tag` overrides any tag embedded in `image`; either may be omitted to
inherit the component's default.

### 10.2 `agent.yaml`

The agent is deliberately thin — identity + where the controller is. Everything
else comes from the `NodeSpec` it pulls.

```yaml
agent:
  role: exit                       # master | exit
  controller: "master-xa-1.mgmt:8443"
  node_id: "exit-de-1"
  mgmt_addr: "10.20.0.5"          # mgmt/ZT address; the agent binds /metrics to
                                   #   <mgmt_addr>:9301 by default (no flag needed)
  reconcile_interval: 30s          # default 30s; set fleet-wide via fleet.reconcile_interval
  identity:
    cert: "/etc/wgfleet/node.crt"  # issued at bootstrap
    key:  "/etc/wgfleet/node.key"  # generated on-node, 0600, never leaves the box
    ca:   "/etc/wgfleet/ca.crt"    # CA cert used to verify the controller
```

### 10.3 Secrets

Secrets (CA private key, WARP creds, etc.) **never** go in git. Config values
that are secret use a scheme reference:

| Scheme | Meaning |
|---|---|
| `env://NAME` | read from environment variable `NAME` |
| `file:///path` | read the (trimmed) contents of a `0600` file (group/other-readable files are rejected) |
| `secret://name` | via the configured secret provider: **SOPS/age** (when `controller.secrets.sops_file` is set) or env-backed `WGFLEET_SECRET_<NAME>` |
| bare value | inline literal (dev only) |

When `controller.secrets.sops_file` is set to a SOPS-encrypted YAML file (age/PGP/KMS),
`secret://NAME` is resolved by decrypting the file at startup and looking up the key.
**CA private keys can use `secret://` and are loaded in-memory** (never written to disk);
the CA cert still reads from a `file://` path. (See `docs/secrets-sops.md` for setup.)

WireGuard private keys are generated and persisted **on the node** (0600) and are
never sent to the controller. `--state-dir <dir>` relocates them (and all managed
files) for non-root/dev runs.

---

## 11. CLI reference

### `wgfleet-controller`

| Flag | Default | Description |
|---|---|---|
| `--version` | | print build version (Version, Commit, BuildDate) and exit |
| `--config` | `/etc/wgfleet/controller.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--store` | (from config) | override `controller.store` |
| `--init-pki` | | generate a CA at the configured pki paths, then exit |
| `--issue-node <id>` | | issue an mTLS bundle (`node.crt`/`node.key`/`ca.crt`) for a node, then exit |
| `--issue-out <dir>` | `pki/<id>` | output dir for `--issue-node` |
| `--provision <node>` | | SSH-bootstrap the named fleet node, then exit |
| `--plan` | | with `--provision` or `--upgrade-agent`: dry-run, change nothing |
| `--agent-bin <path>` | (from config) | with `--provision` or `--upgrade-agent`: agent binary to install |
| `--controller-endpoint <addr>` | (from config) | with `--provision`: endpoint the agent will dial |
| `--upgrade-agent <node>` | | roll the agent binary forward over SSH on the named node, then exit |
| `--backup <out>` | | snapshot controller (+co-located master) state to an age-encrypted archive at `<out>`, then exit |
| `--restore <in>` | | restore controller state from an age-encrypted archive `<in>`, then exit (controller must be stopped) |
| `--age-recipient <rcpt>` | | with `--backup`: encrypt to this age recipient instead of prompting for a passphrase |
| `--plan` | | with `--restore`: show what would be laid down, change nothing |

No subcommand flags ⇒ serve the API + UI + metrics until signalled.

### `wgfleet-agent`

| Flag | Default | Description |
|---|---|---|
| `--version` | | print build version (Version, Commit, BuildDate) and exit |
| `--config` | `/etc/wgfleet/agent.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--plan` | | dry-run: render the full plan, change nothing |
| `--once` | | run a single reconcile pass and exit |
| `--public-ip <ip>` | | this node's public IP to advertise (peer endpoint) |
| `--mgmt-addr <ip>` | (from `agent.yaml`) | mgmt/ZT address (metrics + admin + DNS bind); overrides `agent.mgmt_addr` |
| `--state-dir <dir>` | | root managed files under `<dir>` instead of `/etc` (non-root/dev) |
| `--metrics <addr>` | `<mgmt_addr>:9301` | override the agent `/metrics` bind (mgmt/ZT only); `off` disables |

No `--once` ⇒ run as a daemon, reconciling on the configured interval (default 30s).

---

## 12. Operations

### Dry-run everywhere

`--plan` (agent) and `--provision … --plan` (controller) render every config and
the exact change set and write nothing — the trust mechanism for autoprovisioning.
Plan output shows files (with secrets redacted), commands, and DB updates.

### Web dashboard

`controller.webui` serves a fleet view (bind the ZeroTier address):

- Fleet list with a per-state summary and live refresh (htmx), state badges.
- Per-node detail: inventory, latest status + health checks, rendered `NodeSpec` preview
  (AWG params, peers, routing, firewall, DNS, master data plane, etc.), and a version-skew badge
  (when agent's wire version is incompatible).
- **Actions** (all confirmed POSTs with CSRF + same-origin checks):
  - **Provision** — SSH-bootstrap a `Pending` node asynchronously (Pending → Provisioning → Ready).
  - **Upgrade** — roll the agent binary forward over SSH without tearing down the data plane.
  - **Drain** — keep the node as a configured proxy but remove it from load-balance;
    existing connections survive, no new traffic (ADR-0010).
  - **Undrain** — rejoin the load-balance group.
  - **Decommission** — tell the agent to tear down the data plane on next reconcile
    (stop services, clear routing/firewall, best-effort reverse reconcile; ADR-0012).
  - **Delete** — remove the node from inventory.
  - **Download backup** — export an age-encrypted archive of the controller (and co-located master) state.

### Client access (VLESS)

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
clients route through the tunnel. See `maintainer notes` #29 for the hard-won
client-side details (strict-route, DNS split, import formats).

### Backup & restore

One command captures the **irreplaceable** state and one restores it onto a fresh
node — for disaster recovery and migration. Everything else (nft, mihomo/xray/blocky
configs, compose files) is regenerated by the agent's reconcile loop and is not captured.

```bash
# Export (controller may stay live; the db snapshot is WAL-consistent).
wgfleet-controller --backup fleet.tar.age --age-recipient age1...
#   ...or without --age-recipient to be prompted for a passphrase.

# Restore onto a fresh node (controller MUST be stopped). --plan shows the change set.
wgfleet-controller --restore fleet.tar.age --plan
wgfleet-controller --restore fleet.tar.age
```

What is captured: the store db (consistent `VACUUM INTO` snapshot), the CA cert + key,
`controller.yaml`, the sops secrets file (verbatim, when configured), and — when this
node is also a master — the wg-easy client db, the wg-easy admin password, and the node
identity (`node.crt`/`node.key`/`agent.yaml`). The archive carries the CA key and every
client key, so the **age envelope is its only at-rest protection** — store it like a secret.

Restore moves any existing destination aside to `<path>.bak-<timestamp>` before writing,
and writes each file atomically. It refuses to run while a controller is still serving on
the configured endpoint.

**Migration.** Agents dial `controller: <mgmt>:8443`. The zero-touch path is to rejoin
ZeroTier on the new node as the **same mgmt address** — the CA, certs, and endpoint all
match and the fleet re-adopts itself. If the mgmt address changes, update every node's
`agent.yaml` `controller:` and re-issue the server cert SAN (restore prints this reminder).

### Metrics

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

### Node lifecycle & health

After each apply reconcile the agent runs role-specific self-checks and reports
the derived state:

- **Exit checks:** `wg-handshake` (freshest handshake under 3m — an earlier finding),
  `egress-reachability` (censorship signal: ok | degraded | blocked),
  `warp-egress` (egress via Cloudflare WARP, when `egress=warp`), `dns-filter`.
- **Master checks:** `client-wg` (interface up), `mihomo-api` (Clash API
  `/version`).

Aggregation: reconcile failed → **Error**; all checks pass → **Ready**; any check
fails → **Degraded**; no checks → **Reconciling**.

If an agent goes silent, the controller's **staleness sweep** demotes its node
(`Ready`/`Reconciling`) to **Degraded** after `controller.staleness_after`
(default 3m; `<0` disables) so the dashboard and metrics reflect a dead agent.
`Error` nodes are left as-is (they keep their failure reason); when the agent
recovers, its next report restores the state.

---

## 13. AmneziaWG parameter rules

These are enforced in code (`internal/domain/awg.go`) and **verified against the
upstream kernel module + tools sources**. Getting them wrong silently breaks
tunnels.

- **Must be identical on both ends of a tunnel:** `S1–S4` (junk prefix sizes) and **`H1–H4`** (packet junk header ranges).
- **May differ per end:** `Jc`, `Jmin`, `Jmax` (junk count, interval min/max) and **`I1–I5`** (per-end protocol-mimicry packets — see below).
- **`H1–H4` are ranges** (`min-max`, e.g. `15384729-145384729`); the four ranges
  **must not overlap** (kernel-enforced). Modelled as `AWGHeader{Min,Max}`.
- **All obfuscation parameters live in `[Interface]`, never `[Peer]`.**
- **`S1–S4` must be message-size collision-safe (ADR-0022).** The userspace
  `amneziawg-go` classifier (mihomo proxies, app clients) keys on packet size, so a data
  packet `32+S4+16k` must never equal a handshake size `{148+S1, 92+S2, 64+S3}` nor shadow
  an adjacent pair — otherwise ~50% of new TLS connections silently stall. The generator
  draws S1-S3 ∈ [15,64] and S4 ∈ [16,32] (Amnezia doc ranges, never `S4=0`) and **iterates
  until `awgSizesSafe` holds** (`deriveSafeS`). Kernel hard limits are far higher
  (`S ≤ 65535−base`) but are NOT sufficient — the kernel does not check this.
- Other limits: `1 ≤ Jc ≤ 10`; `Jmin < Jmax ≤ 1280`; **`S1+56 ≠ S2`** (anti-detection).
- **`I1–I5` mimic a real UDP protocol** (ADR-0022): each tunnel-end picks one cover
  protocol from its seed — **QUIC v1 Initial / STUN binding / DTLS ClientHello** — and
  fills all five slots with structurally-valid, per-slot-varied packets, so a DPI sees
  QUIC/WebRTC, not a VPN handshake. I1-I5 differ, the two ends differ, and templates vary
  fleet-wide. Built from the RFCs as `<b>/<r>/<rc>` literals; the `<c>/<t>` CPS tags are
  **not used** (they break userspace WireGuard-Go and would corrupt a protocol's layout),
  so kernel and userspace I-profiles are identical. `ValidateUserspace()` still gates
  operator overrides.
- Shared params are **derived deterministically** from a per-tunnel seed
  (`wg.DeriveAWGParams`), so both ends compute the identical set with no
  coordination. The reference example from the wg-easy docs is pinned as a golden
  test.

Per data plane:

- **Exit** (server) — `awg-quick` config (kernel module); all S1-S4, H1-H4 identical across peers.
- **Master ↔ exit** tunnels — `amnezia-wg-option` per mihomo `wireguard` proxy
  (userspace; each proxy gets derived S1-S4, H1-H4 plus its own Jc/Jmin/Jmax/I1-I5).
- **Master ↔ client** — wg-easy interface, set by writing the structural parameters (S1-S4, H1-H4)
  and the master's decoy params (Jc/Jmin/Jmax, I1-I5) into wg-easy's SQLite DB (it propagates
  the interface params to all client configs; clients may have their own decoy when they apply
  the config locally).

---

## 14. Security model

- Node WireGuard private keys are generated and stay **on the node**; the
  controller only ever stores public keys.
- **mTLS** between controller and agents; each node has its own client cert (CN =
  node ID) issued at bootstrap. Cert revocation = fleet removal.
- The Web UI, metrics and all node admin endpoints bind the **ZeroTier mgmt
  overlay only**, never the public interface.
- SSH is used only during bootstrap (key-based); afterwards management is mTLS and
  SSH is no longer required.
- A baseline firewall is installed in bootstrap **before** the node accepts
  traffic.
- Secrets go through a provider (env / `0600` file / SOPS-age hook); no keys or
  real IPs in git. `.gitignore` blocks `*.key`/`*.pem`/`*.crt`/`*.db`/local
  configs.

---

## 15. Design decisions (ADRs)

Full records in [`docs/adr/`](docs/adr/):

| ADR | Decision |
|---|---|
| 0001 | Controller↔agent transport is **gRPC over mTLS** (identity = cert CN) |
| 0002 | MVP starts API+CLI first; **SQLite** store; Web UI later (now done, html/template+htmx) |
| 0003 | Key-broker topology & deterministic tunnel addressing (single-master MVP) |
| 0004 | **Reconcile/dry-run** as a pervasive, first-class engine abstraction |
| 0005 | **AmneziaWG everywhere** for fleet tunnels; vanilla WG only for WARP (verified vs upstream) |
| 0006 | Provisioner is an SSH **bootstrap pipeline**, plan-first, mock-tested |
| 0007 | Master data plane is **mihomo**; config customization via overrides + extra files |
| 0008 | **Exits use pure awg-quick**; master wg-easy AWG via its **SQLite DB** |
| 0009 | Agent **self-checks drive the node lifecycle state** |
| 0010 | **Graceful drain** (keep proxy, leave LB group) + read-write UI actions |
| 0011 | **Master container lifecycle** via rendered docker-compose (wg-easy + mihomo) |
| 0012 | **Node teardown** via a decommission signal + best-effort reverse reconcile |
| 0013 | **Exit DNS filter as a managed blocky container**, override-driven config, ZT-only binds |
| 0014 | **Sequential per-hop MTU model** (not nested); auto-calculation from tunnel chain |
| 0015 | **Drift observability + idempotent routing + live-kernel drift repair** (health-based LB in mihomo) |
| 0016 | **Egress-block detection** (non-destructive active confirmation; censorship signal) |
| 0017 | **Censorship-adaptive egress failover** (agent auto-switches within egress chain, recover on grace) |
| 0018 | **Secrets via SOPS/age** (config.SOPSProvider shells out to `sops -d`; CA key in-memory) |
| 0019 | **Upgrade procedure + wire-contract versioning** (gRPC-metadata gate, reject+auto-upgrade, store migrations) |

`docs/DESIGN.md` holds the full project context, the hard-won operational lessons, and
the conventions. Behavior is verified against the upstream AmneziaWG sources
(kernel module, tools, and the wg-easy fork).

---

## 16. Roadmap

**Phase 1 ✅ complete** — full node lifecycle from provisioning to decommission
(dry-run first-class throughout).

**Phase 2 ✅ complete** — drift auto-reconcile, health-based LB in mihomo,
AmneziaWG parameter generator (collision-safe S1-S4, per-end decoy Jc/Jmin/Jmax + I1-I5
real-protocol mimicry QUIC/STUN/DTLS, per-end seeds — ADR-0022), auto-MTU sequential model,
SOPS/age secrets, live-kernel drift repair.

**Phase 3 (in progress)** — censorship-adaptive egress failover.
- ✅ egress-block detection (ADR-0016) — non-destructive active confirmation signal.
- ✅ auto-switch egress within chain (ADR-0017) — agent autonomous, controller sets chain.
- ⏳ traffic-noise to decorrelate volume.

**Stabilization (in progress)** — upgrade procedure + wire-contract versioning.
- ✅ upgrade procedure + wire-contract versioning (ADR-0019) — gRPC-metadata gate on
  Register/PullSpec, reject incompatible, auto-upgrade over SSH, versioned store migrations.

**Phase 4 (optional) — native data plane:** replace some orchestrated tools with
native Go (kernel WG via netlink, native nftables).

**Phase 5 (optional) — HA control plane:** multi-master with leader election,
raft/rqlite store, CA-key distribution model.

**Done (ADR-0025):** Reality/VLESS+XHTTP as a **fallback** master↔exit transport
for when AmneziaWG is blocked (not a WG replacement) — per-exit, switchable live
from the Web UI; AWG stays the default/primary. Shipped and validated on a censored
path where AWG was blocked but REALITY carried traffic; the camouflage `dest` must
support X25519MLKEM768. Per-exit knobs: `transports.reality.{dest_domain,
dest_port,sni,listen_port,mode,mux,fingerprint,empty_sni,allow_ipv6,image}`.
Switching is manual today; automatic AWG→REALITY failover (analogous to the
WARP→direct egress failover) is on the roadmap.
