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

> Working language: **all code, comments, identifiers, logs and commits are in
> English.** Project design notes (`docs/DESIGN.md`) and discussion are in Russian.

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
| Exit data plane: awg-quick, wgcf (Table=off/MTU), routing, nftables | ✅ render; ⏳ apply unverified | `internal/agent/exit`, `internal/{wg,egress,routing,netfw}` |
| Exit DNS filter: blocky container, override-config, ZT-only binds | ✅ | `internal/dnsfilter`, `internal/compose` |
| Master data plane: mihomo (proxies+LB+rules), NAT, custom config | ✅ render | `internal/agent/master`, `internal/mihomo` |
| Master client AWG via wg-easy SQLite DB | ✅ | `internal/wgeasy` |
| Provisioner: SSH bootstrap (facts, preflight, plan) | ✅ plan; ⏳ live SSH on Linux | `internal/controller/provisioner` |
| Health checks → Ready/Degraded/Error | ✅ | `internal/agent/health` |
| Web UI: dashboard + drain/undrain/delete actions | ✅ | `internal/controller/web` |
| Prometheus `/metrics` (controller + agent) | ✅ | `internal/metrics` |
| Graceful drain (LB exclusion) | ✅ | store + keybroker + `internal/mihomo` |
| Staleness sweep (silent node → Degraded) | ✅ | `internal/controller/sweeper` |
| Master container lifecycle (compose up/restart) | ✅ | `internal/compose` + master planners |
| Node teardown / decommission (reverse reconcile) | ✅ | `internal/agent/{exit,master}` teardown |
| Provisioning from the UI (async) | ✅ | `internal/controller/provmgr` |

**MVP Phase 1 is complete** — full node lifecycle from a blank VM to
decommission, with observability. **Not yet:** config wipe on teardown, then
Phase 2+ (drift auto-reconcile, health-based balancing, SOPS/age secrets,
Reality/VLESS transport, native data plane).

> **Dev-box caveat:** apply-side exec actions (`nft -f`, `awg-quick`, `ip`,
> `wgcf`, `docker`) and live SSH need a Linux/root node. On the macOS dev box they
> are rendered and unit-tested via mocks but not executed; an apply there honestly
> reports `Error` at the first missing tool. All *rendering*, *dry-run*, PKI,
> transport, store, metrics and UI run fully cross-platform.

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
└── docs/adr/                   architecture decision records (0001–0009)
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
```

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
  # advertise: "10.20.25.254:8443"  # only when listen is 0.0.0.0 (controller behind NAT/LB):
                                   # the address agents actually dial; its host seeds the SAN.
  webui:   "10.20.25.254:9000"    # read-only dashboard; bind mgmt/ZT only (empty disables)
  metrics: "10.20.25.254:9300"    # Prometheus /metrics; bind mgmt/ZT only (empty disables)
  store:   "/var/lib/wgfleet/state.db"
  staleness_after: 3m              # silent Ready/Reconciling node → Degraded after this (0=default, <0 disables)
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key:  "file:///etc/wgfleet/ca.key"   # CA tooling needs a file:// path; keep 0600 / secret manager

fleet:
  zerotier_network: "8056c2e21c000001"      # mgmt overlay nodes join at bootstrap

  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254              # ZeroTier address
      client_awg:
        listen_port: 443                    # UDP; standard ports are less conspicuous
        address_pool: 10.80.0.0/24          # client WG subnet
      routing:
        direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
        direct_geo:   [RU]                  # GEOSITE/GEOIP → DIRECT
        balance:      health                # round-robin | health
      mihomo:                               # master data-plane tuning + custom-config hooks
        sniffer_skip: ["+.themoviedb.org", "+.cloudfront.net"]  # CDNs that break under sniffing
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
        mihomo_tag:    latest
      ssh:                                  # bootstrap target (Phase 0/1 only)
        host: 203.0.113.1
        user: root
        key_path: /etc/wgfleet/bootstrap_ed25519

  exits:
    - name: exit-de-1
      region: de
      egress: warp                          # warp | direct
      listen_port: 51820                    # WG server port (0 ⇒ 51820)
      address_pool: 10.81.0.0/24
      mgmt_addr: 10.20.0.5                 # ZeroTier address (admin/metrics/DNS bind)
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
        user: root
        key_path: /etc/wgfleet/bootstrap_ed25519
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
  reconcile_interval: 60s          # default 60s
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
| `secret://name` | via the secret provider (MVP: `WGFLEET_SECRET_<NAME>` env; SOPS/age hook later) |
| bare value | inline literal (dev only) |

WireGuard private keys are generated and persisted **on the node** (0600) and are
never sent to the controller. `--state-dir <dir>` relocates them (and all managed
files) for non-root/dev runs.

---

## 11. CLI reference

### `wgfleet-controller`

| Flag | Default | Description |
|---|---|---|
| `--config` | `/etc/wgfleet/controller.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--store` | (from config) | override `controller.store` |
| `--init-pki` | | generate a CA at the configured pki paths, then exit |
| `--issue-node <id>` | | issue an mTLS bundle (`node.crt`/`node.key`/`ca.crt`) for a node, then exit |
| `--issue-out <dir>` | `pki/<id>` | output dir for `--issue-node` |
| `--provision <node>` | | SSH-bootstrap the named fleet node, then exit |
| `--plan` | | with `--provision`: dry-run the bootstrap plan |
| `--agent-bin <path>` | | with `--provision`: agent binary to install |
| `--controller-endpoint <addr>` | (from config) | with `--provision`: endpoint the agent will dial |

No subcommand flags ⇒ serve the API + UI + metrics until signalled.

### `wgfleet-agent`

| Flag | Default | Description |
|---|---|---|
| `--config` | `/etc/wgfleet/agent.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--plan` | | dry-run: render the full plan, change nothing |
| `--once` | | run a single reconcile pass and exit |
| `--public-ip <ip>` | | this node's public IP to advertise (peer endpoint) |
| `--mgmt-addr <ip>` | | mgmt/ZT address (admin + DNS bind) |
| `--state-dir <dir>` | | root managed files under `<dir>` instead of `/etc` (non-root/dev) |
| `--metrics <addr>` | | bind the agent `/metrics` endpoint (mgmt/ZT only; empty disables) |

No `--once` ⇒ run as a daemon, reconciling on the configured interval.

---

## 12. Operations

### Dry-run everywhere

`--plan` (agent) and `--provision … --plan` (controller) render every config and
the exact change set and write nothing — the trust mechanism for autoprovisioning.
Plan output shows files (with secrets redacted), commands, and DB updates.

### Web dashboard

`controller.webui` serves a read-only fleet view (bind the ZeroTier address):

- Fleet list with a per-state summary and live refresh (htmx), state badges.
- Per-node detail: inventory, latest status + health checks, and a preview of the
  rendered desired `NodeSpec`.
- **Provision** action (confirmed POST). Nodes declared in the manifest but not
  yet provisioned appear as `Pending`; the button SSH-bootstraps them
  asynchronously (the node goes `Provisioning` → the agent takes over → `Ready`).
- **Drain → Decommission → Delete** lifecycle (confirmed POSTs):
  - **Drain** keeps the node a configured proxy but removes it from the
    load-balance group — existing connections survive, no new traffic (ADR-0010).
  - **Decommission** tells the agent to tear down the data plane on its next
    reconcile (bring tunnels/containers down, clear routing/firewall) — a
    best-effort reverse reconcile (ADR-0012).
  - **Delete** removes the node from inventory.

### Metrics

`controller.metrics` and `wgfleet-agent --metrics` expose Prometheus text. Bind
the ZeroTier address only.

**Controller** (a scrape-time projection of the state store):

```
wgfleet_nodes{state="Ready"}                       # node count per lifecycle state
wgfleet_node_info{node,role,region,state}          # inventory info (=1)
wgfleet_node_last_report_age_seconds{node}         # since last status report
wgfleet_node_reconcile_failed{node}                # 1 if last reconcile errored
wgfleet_node_health_check{node,check}              # 1 ok / 0 failing
wgfleet_node_egress_info{node,egress_ip}           # observed egress IP (=1)
```

**Agent** (its own reconcile/health counters):

```
wgfleet_agent_reconcile_total{result}              # success | error
wgfleet_agent_reconcile_duration_seconds           # histogram
wgfleet_agent_state_info{state}                    # current lifecycle state (=1)
wgfleet_agent_health_check{check}                  # 1 ok / 0 failing
wgfleet_agent_start_time_seconds                   # for uptime
```

### Node lifecycle & health

After each apply reconcile the agent runs role-specific self-checks and reports
the derived state:

- **Exit checks:** `wg-handshake` (freshest handshake under 3m — an earlier finding),
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

- **Must be identical on both ends of a tunnel:** `S1–S4` and **`H1–H4`**.
- **May differ per end:** `Jc`, `Jmin`, `Jmax` and **`I1–I5`**.
- **`H1–H4` are ranges** (`min-max`, e.g. `15384729-145384729`); the four ranges
  **must not overlap** (kernel-enforced). Modelled as `AWGHeader{Min,Max}`.
- **All obfuscation parameters live in `[Interface]`, never `[Peer]`.**
- Limits: `1 ≤ Jc ≤ 128`; `Jmin < Jmax ≤ 1280`; `S1 ≤ 1132`; `S2 ≤ 1188`;
  **`S1+56 ≠ S2`** (anti-detection; docs-only, we enforce it); `I` values are hex
  blobs or CPS templates.
- **`<c>` / `<t>` CPS tags work in the kernel but break userspace WireGuard-Go**
  (mihomo proxies, Amnezia app clients) — so userspace configs use only
  `<b>/<r>/<rc>/<rd>`. Enforced via `ValidateUserspace()`.
- Shared params are **derived deterministically** from a per-tunnel seed
  (`wg.DeriveAWGParams`), so both ends compute the identical set with no
  coordination. The reference example from the wg-easy docs is pinned as a golden
  test.

Per data plane:

- **Exit** (server) — `awg-quick` config (kernel module).
- **Master ↔ exit** tunnels — `amnezia-wg-option` per mihomo `wireguard` proxy
  (userspace; per-proxy params).
- **Master ↔ client** — wg-easy interface, set by writing the obfuscation columns
  into wg-easy's SQLite DB (it has no env/API hook for them; it propagates the
  interface `S`/`H` to all client configs).

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

`docs/DESIGN.md` holds the full project context, the hard-won operational lessons, and
the conventions. Upstream AmneziaWG sources used for verification live at
`the upstream AmneziaWG sources` (kernel module, tools, and the wg-easy
fork).

---

## 16. Roadmap

**MVP (Phase 1) — remaining:**

- Provisioning *from* the Web UI (async, long-running — currently CLI-only).
- Teardown / wipe of a drained node (stop services, remove WG state) — `delete`
  currently only removes it from inventory.
- Container lifecycle (mihomo / wg-easy up/restart as a thin exec wrapper).
- Controller-side staleness sweep (no report in N intervals → Degraded).

**Phase 2 — resilience & convenience:** drift-triggered auto-reconcile,
health-based balancing, graceful drain, AWG parameter generator with validation,
SOPS/age secrets, auto-MTU calculator along the tunnel chain.

**Phase 3 — transport/obfuscation:** Reality/VLESS transport between master and
exit; traffic-noise to break volume correlation.

**Phase 4 (optional) — native data plane:** replace some orchestrated tools with
native Go (kernel WG via netlink, native nftables).
