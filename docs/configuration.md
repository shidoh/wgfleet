# wgfleet — configuration reference

Every configurable key, its default and its meaning. Complete: if a key is not on
this page, it is not a key.

| File | Read by | Written by |
|---|---|---|
| `controller.yaml` | `wgfleet-controller` | **you** — this is the fleet manifest |
| `agent.yaml` | `wgfleet-agent`, one per node | the controller, at provisioning |

You normally only edit `controller.yaml`; the agent file is generated on each node
and documented here for recovery. Annotated, test-validated examples ship in `examples/`:

- `controller.yaml` — full reference manifest, every key present, commented
- `controller-split-ru.yaml` — RU split-tunnel + DNS filter, with `<placeholders>` to fill in
- `agent.yaml` — what the controller writes on a node

---

## 1. How values resolve

Precedence, lowest to highest:

1. **Built-in default** — listed per key below.
2. **`controller.yaml` / `agent.yaml`** value.
3. **Environment override** — a `WGFLEET_`-prefixed env var: uppercase the path,
   dots to underscores (`controller.listen` → `WGFLEET_CONTROLLER_LISTEN`). Reaches
   only keys whose every path segment is a single word: a two-word key
   (`WGFLEET_CONTROLLER_STALENESS_AFTER`) matches nothing and is **silently ignored**,
   and anything under `fleet.masters[]` / `fleet.exits[]` is unreachable this way.
4. **CLI flag**, where one exists (`--config`, `--store`, `--metrics`, …). There is no
   `--listen`: the controller's listen addresses come from the manifest only.

Durations are Go duration strings (`30s`, `5m`, `168h`); sizes and ports are plain
integers; lists accept a YAML sequence or a comma-separated string.

### Secret values

`controller.pki.ca_key` is a `Secret` — never write key material inline in a committed
file. It accepts a scheme:

| Form | Resolves to |
|---|---|
| `env://NAME` | environment variable `NAME` |
| `file:///path/to/key` | contents of the file (must be mode `0600`) |
| `secret://name` | the configured secret provider — SOPS/age when `controller.secrets.sops_file` is set, otherwise env var `WGFLEET_SECRET_<NAME>` |
| bare string | inline literal — local development only |

SOPS/age setup: `secrets-sops.md`.

### Environment variables that are not config keys

| Variable | Effect |
|---|---|
| `WGFLEET_SECRET_<NAME>` | backs `secret://name` when no SOPS file is configured |
| `WGFLEET_ALLOW_PUBLIC_BIND=1` | permits a non-mgmt bind for the Web UI / metrics. The Web UI has destructive actions and no transport auth of its own — only set this behind your own reverse proxy |
| `WGFLEET_SSH_INSECURE_HOST_KEY=1` | disables SSH host-key verification fleet-wide during bootstrap (see `fleet.exits[].ssh.host_key`) |
| `WGFLEET_ADMIN_PASSWORD` | non-interactive Web UI admin password for `--set-admin-password` |

---

## 2. `controller` — the controller process

| Key | Type | Default | Meaning |
|---|---|---|---|
| `controller.listen` | string | **required** | gRPC/mTLS endpoint agents connect to. Bind the mgmt/overlay address, e.g. `10.20.25.254:8443` — agents dial exactly what is written here, so `0.0.0.0` works only together with `controller.advertise` |
| `controller.advertise` | string | = `listen` | Address agents dial when it differs from the bind — behind NAT, a gateway, or a load balancer. Also adds a SAN to the server certificate |
| `controller.store` | string | **required** | Path to the SQLite state database |
| `controller.log_level` | string | `info` | `trace` \| `debug` \| `info` \| `warn` \| `error`. `debug` prints every spec render decision; `trace` adds one line per agent RPC. `--log-level` overrides it. On a running process `SIGUSR1` steps one level more verbose and `SIGUSR2` returns to this value |
| `controller.webui` | string | disabled | Web UI bind. **Must be a mgmt/overlay address** unless `WGFLEET_ALLOW_PUBLIC_BIND=1` |
| `controller.metrics` | string | disabled | Prometheus `/metrics` bind (conventionally `<mgmt>:9300`). Same mgmt-only restriction |
| `controller.client_portal_url` | string | — | Base URL clients reach the portal on, e.g. `https://vpn.example.org`. Required together with `client_portal` |
| `controller.client_portal` | string | disabled | Bind for the client self-service portal (per-client profile and QR). Bind it on the master's **mgmt address** and list its port in `fleet.masters[].client_admin_ports`; a bind on the client-pool gateway address does not work, and a public bind is refused |
| `controller.agent_bin` | string | — | Path to the `wgfleet-agent` binary installed during UI-triggered provisioning. Also the rolling upgrade's target: nodes are compared against **this binary's** version, not the controller's |
| `controller.staleness_after` | duration | `3m` | Mark a node Degraded after this long with no status report. Negative disables the sweep |
| `controller.session_ttl` | duration | `168h` (7d) | Web panel sliding session lifetime |
| `controller.pki.ca_cert` | string | **required** | Path to the fleet CA certificate (public) |
| `controller.pki.ca_key` | secret | **required** | Reference to the CA private key — see [Secret values](#secret-values). Every start except `--init-pki` loads it and refuses to run without it |
| `controller.secrets.sops_file` | string | env provider | Path to a SOPS-encrypted YAML file backing `secret://` lookups |

---

## 3. `fleet` — fleet-wide settings

Applies to every node. Keys marked **baked** are written into each `agent.yaml` at
provisioning, so changing them requires re-provisioning the node.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.zerotier_network` | string | — | ZeroTier network ID (exactly 16 hex chars) every node joins during bootstrap. Validated strictly: it is interpolated into a root shell command |
| `fleet.mgmt_subnet` | CIDR | derived | The management overlay's CIDR. When set, exits route it DIRECT (never through WARP) and accept it in the firewall without per-node listing. Empty ⇒ derived from each node's `mgmt_addr` as /32s |
| `fleet.mgmt_overlay_mss` | int | `0` (off) | **baked.** TCP MSS clamp on the ZeroTier interface, both directions. Recommended `1240` (a 1280 overlay); valid `536`–`1460` |
| `fleet.reconcile_interval` | duration | `30s` | **baked.** How often every agent reconciles. Valid `5s`–`1h`. A node's own `agent.reconcile_interval` still wins |
| `fleet.min_egress_throughput_kbytes` | int | `250` | Egress throughput floor in KiB/s below which an exit is pulled from the load balancer. Negative disables the watchdog fleet-wide |
| `fleet.egress_throughput_probe_url` | URL | three targets | What each exit downloads to measure its own throughput. Unset, the agent tries three independent targets in order — Cloudflare's speed endpoint, then CacheFly, then OVH — and stops at the first that clears the floor. Setting the key **replaces** that list with the single URL you name |
| `fleet.as_blacklist_v4_url` | URL | C24Be AS_Network_List v4 | **baked.** Source feed of scanner ASNs the exit firewall drops. Per-exit enable is `fleet.exits[].firewall.as_blacklist` |
| `fleet.as_blacklist_v6_url` | URL | C24Be AS_Network_List v6 | **baked.** IPv6 half of the same feed |
| `fleet.as_blacklist_interval` | duration | `24h` | **baked.** Feed refresh cadence. Valid `1m`–`168h`. A failed refresh keeps the last-good list |
| `fleet.reality_default_sni` | string | `www.python.org` | Fleet-wide REALITY camouflage SNI. **The target must support X25519MLKEM768** or the handshake fails silently — verify with `xray tls ping <host>` |
| `fleet.reality_default_dest` | string | = SNI | Fleet-wide camouflage `host:port` the REALITY inbound borrows its certificate from |
| `fleet.hardening.sshd` | bool | `true` | **Fleet default.** Manage the sshd drop-in (`/etc/ssh/sshd_config.d/10-wgfleet-hardening.conf`: key-only auth, no root password, no X11 forwarding), reconciled every pass |
| `fleet.hardening.fail2ban` | bool | `true` | **Fleet default.** Manage the fail2ban sshd jail (`/etc/fail2ban/jail.d/wgfleet.conf`) |
| `fleet.awg3` | bool | `false` | **Fleet default.** Run the master↔exit AmneziaWG tunnels on **AmneziaWG 3.0** (header protection + randomised timers) — see [AmneziaWG 3.0](#amneziawg-30) |
| `fleet.awg3_key` | secret ref | — | The fleet secret the 3.x header-protection key is derived from — 32+ random bytes. **Required whenever header protection is on** (`fleet.awg3`, `fleet.exits[].awg3`, or `client_awg.awg3: full`); the controller refuses to start without it. Prefer `file:///etc/wgfleet/awg3.key`: only a file travels in `--backup`, and losing the key invalidates every client config in the field. `secret://` and `env://` also work. The 3.x timers need no secret |

### Turning hardening off

Precedence is node → fleet → `true`. An omitted key on a node means *inherit*, not
*disable*; an explicit `true` on a node beats a fleet-wide `false`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].hardening.sshd` | bool | inherit fleet | Override the fleet default for this master |
| `fleet.masters[].hardening.fail2ban` | bool | inherit fleet | Override the fleet default for this master |
| `fleet.exits[].hardening.sshd` | bool | inherit fleet | Override the fleet default for this exit |
| `fleet.exits[].hardening.fail2ban` | bool | inherit fleet | Override the fleet default for this exit |
| `fleet.exits[].awg3` | bool | inherit fleet | Override `fleet.awg3` for this exit |

`false` deletes the drop-in (or jail) wgfleet installed and reloads the service;
`true` rewrites it whenever its content drifts, within one reconcile interval. The
opt-out requires an agent on wire contract **v6** or later — deploy the controller
first, see [upgrade.md](upgrade.md).

---

## 4. `fleet.masters[]` — master nodes

> Exactly one master is supported; a manifest with more than one is rejected.

### Identity and exposure

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].name` | string | **required** | Stable node name. This is the node's identity — renaming means re-issuing its certificate |
| `fleet.masters[].mgmt_addr` | string | — | ZeroTier/overlay address. Binds admin surfaces and is trusted by construction |
| `fleet.masters[].public_ip` | string | = `ssh.host` | Public IP clients and peers reach this node at |
| `fleet.masters[].client_admin_ports` | []int | none | Admin ports (Web UI, mihomo dashboard, client portal) opened **to the VPN client pool** on the mgmt address. Default keeps admin reachable only over the overlay |
| `fleet.masters[].public_tcp_ports` | []int | none | TCP ports opened **to the whole internet** — e.g. `80` for a decoy web listener. Unscoped: keep it to genuinely public services |
| `fleet.masters[].public_udp_ports` | []int | none | UDP ports opened **to the whole internet** — e.g. a second ZeroTier instance on a non-default port |
| `fleet.masters[].whitelist` | []CIDR | mgmt scope | Additional source CIDRs the input firewall always accepts, regardless of port. The management overlay is merged in automatically |

### `client_awg` — the client-facing AmneziaWG listener

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].client_awg.listen_port` | int | `443` | UDP port VPN clients connect to |
| `fleet.masters[].client_awg.address_pool` | CIDR | — | Address pool handed to clients. Required when `managed` is on. Must not overlap any other pool in the fleet; the controller refuses to start on an overlap |
| `fleet.masters[].client_awg.managed` | bool | `false` | Hand the interface to the agent instead of wg-easy: the controller owns the client credentials and the agent renders and raises the interface. Unset keeps wg-easy |
| `fleet.masters[].client_awg.backend` | `kernel` \| `userspace` | `kernel` | What carries a **managed** interface. `userspace` is a fallback, not an override: on a node with a kernel module, the module carries the interface regardless. `userspace` with an AmneziaWG 3.x profile is refused unless the node has no usable module and the `amneziawg-go` daemon is installed. Ignored while unmanaged |
| `fleet.masters[].client_awg.awg3` | `off` \| `timers` \| `full` | `off` | AmneziaWG 3.x on the client leg. `timers` randomises the 3.x timers only — existing client configs keep working. `full` adds header protection — **every client must re-import**. Requires `managed: true` and a 3.x kernel module on the master; without the module the agent keeps the last-good config |
| `fleet.masters[].client_awg.ipv6` | `off` \| `block` | `off` | What a client is told about IPv6. `off` says nothing, so a dual-stack client keeps its own IPv6 route. `block` hands the client `::/0` and answers forwarded IPv6 with ICMPv6 administratively-prohibited, so the device falls back to IPv4. The data plane stays IPv4-only. Requires `managed: true` and an agent on wire v9; the controller refuses to render the route for an older agent |
| `fleet.masters[].client_awg.mtu` | int | derived | Override the client interface MTU. Unset derives it from the hop chain |
| `fleet.masters[].client_awg.keepalive` | int or `min-max` | `25` | `PersistentKeepalive` in generated client configs. A bare number pins one interval; a band gives each credential its own stable value. Keep it under the shortest NAT UDP timeout on the path (commonly 30s). Range 5-120 |
| `fleet.masters[].client_awg.exclude_from_tunnel` | []CIDR | none | Networks a client must NOT send into the tunnel (its own LAN, for example). The controller expands "everything except these" into the explicit `AllowedIPs` list. Empty leaves the default route alone. Ignored when `allowed_ips` is set |
| `fleet.masters[].client_awg.route_through_cidrs` | []CIDR | none | Networks put back into the tunnel after `exclude_from_tunnel` — a work subnet inside an excluded range, or the management overlay. Rejected without `exclude_from_tunnel` |
| `fleet.masters[].client_awg.dns` | list | `compose.client_dns` | Resolvers written into generated client configs |
| `fleet.masters[].client_awg.allowed_ips` | list | `compose.client_allowed_ips` | What client configs route into the tunnel. An IPv6 default route is rejected: the data plane is IPv4-only |

### `client_vless` — DPI-resistant client transport

A VLESS+REALITY+XHTTP inbound running **alongside** client AmneziaWG; traffic
converges into mihomo. Per-client credentials are issued and revoked in the Web UI.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].client_vless.enabled` | bool | `false` | Turn the inbound on |
| `fleet.masters[].client_vless.listen_port` | int | derived `40000`–`60000` | TCP port, derived stably from the master name when unset |
| `fleet.masters[].client_vless.dest_domain` | string | fleet default | Camouflage target host |
| `fleet.masters[].client_vless.dest_port` | int | `443` | Camouflage target port |
| `fleet.masters[].client_vless.sni` | string | = `dest_domain` | SNI the ClientHello impersonates |
| `fleet.masters[].client_vless.mode` | string | `xhttp` | `xhttp` (packet-up) or `vision` (classic TCP + xtls-rprx-vision) |
| `fleet.masters[].client_vless.empty_sni` | bool | **`true`** | Accept/send a ClientHello with no SNI extension. Set `false` to force off |
| `fleet.masters[].client_vless.fingerprint` | string | `firefox` | uTLS ClientHello fingerprint: `firefox` \| `chrome` \| `safari` \| `none` |
| `fleet.masters[].client_vless.mux` | bool | **`true`** | XMUX (XHTTP connection reuse) in the generated client profile. `xhttp` mode only |
| `fleet.masters[].client_vless.allow_ipv6` | bool | `false` | Let xray resolve the camouflage dest over IPv6. Leave off unless this node has IPv6 egress |
| `fleet.masters[].client_vless.xhttp_path` | string | `/` | XHTTP path |
| `fleet.masters[].client_vless.route_through_cidrs` | []CIDR | none | Internal networks a client must route **through** the tunnel (clients send RFC1918 direct by default). Served in the subscription's `routing` header |
| `fleet.masters[].client_vless.image` | string | pinned xray | Container image |
| `fleet.masters[].client_vless.tag` | string | — | Explicit tag, overriding any tag in `image` |

### `routing` — geo-routing and exit selection

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].routing.direct_cidrs` | []CIDR | none | Destinations routed DIRECT, never through an exit. Each consumes a routing priority; there is a hard cap. Strictly parsed: values are interpolated into the nft ruleset |
| `fleet.masters[].routing.direct_geo` | []string | none | Geo codes routed DIRECT, e.g. `["RU"]` |
| `fleet.masters[].routing.balance` | string | `round-robin` | How the exit group picks: `round-robin`, `consistent-hashing` (same dst → same exit; alias `health`), `sticky-sessions` (same src+dst → same exit), `url-test` (lowest latency wins), `fallback` (primary, fail over on timeout) |
| `fleet.masters[].routing.reserve_exits` | []string | none | Exits kept as a **second tier**, used only when every primary is down. Everything not listed is primary. Use manifest exit names, not rendered proxy names |

### `mihomo` — the master data plane

Passthrough surface: [§9 third-party configuration](#9-third-party-configuration).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].mihomo.redir_port` | int | `7895` | Transparent-proxy redirect port |
| `fleet.masters[].mihomo.health_interval` | duration | `60s` | How often mihomo health-checks exits. Valid `5s`–`1h` |
| `fleet.masters[].mihomo.max_failed_times` | int | `5` | Consecutive failures that force an out-of-band health check. Raise it where some traffic legitimately fails |
| `fleet.masters[].mihomo.sniffer_skip` | []string | none | Domains the sniffer must not rewrite |
| `fleet.masters[].mihomo.dashboard_url` | URL | metacubexd release | Where to fetch the web dashboard. Point at a mirror where GitHub is blocked |
| `fleet.masters[].mihomo.dashboard_disabled` | bool | `false` | Skip the dashboard entirely — mihomo then never attempts the download |
| `fleet.masters[].mihomo.client_via_netns` | string | `auto` | Where client traffic is intercepted. `off` — on the host. `auto` — inside mihomo's own network namespace once the agent has proved the namespace works, reverted automatically if the client path breaks. A CIDR or any other value is refused |
| `fleet.masters[].mihomo.netns_cidr` | string | `100.127.255.0/30` | The point-to-point link between the host and that namespace (a /30, host `.1`, namespace `.2`) |
| `fleet.masters[].mihomo.overrides` | map | none | **Deep-merged into the rendered mihomo `config.yaml`.** The escape hatch for anything wgfleet does not model |
| `fleet.masters[].mihomo.extra_files[].path` | string | — | Additional managed file written alongside the config, e.g. a rule-provider list. Every `type: file` rule provider added under `mihomo.overrides` must ship its file here, or the provider is silently empty |
| `fleet.masters[].mihomo.extra_files[].content` | string | — | Its literal contents |
| `fleet.masters[].mihomo.extra_files[].secret` | bool | `false` | Write mode `0600` and redact from logs and dry-run output |

### `compose` — the master container stack

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].compose.wg_easy_image` | string | pinned wg-easy 15 | Repository, optionally with a tag |
| `fleet.masters[].compose.wg_easy_tag` | string | — | Explicit tag, overriding any tag in the image |
| `fleet.masters[].compose.wg_easy_web_port` | int | `44423` | wg-easy admin UI port |
| `fleet.masters[].compose.mihomo_image` | string | `metacubex/mihomo` | Repository, optionally with a tag |
| `fleet.masters[].compose.mihomo_tag` | string | pinned | Explicit tag. **Pin a specific version**, never `latest` or `Alpha` |
| `fleet.masters[].compose.client_dns` | []string | exit mgmt addrs | DNS servers handed to clients |
| `fleet.masters[].compose.client_allowed_ips` | string | `0.0.0.0/0` | `AllowedIPs` written into client configs. IPv4-only: `::/0` is rejected |
| `fleet.masters[].compose.netns_holder_image` | string | built-in | Image for the container that owns mihomo's network namespace. It only has to exist and sleep |

### Master DNS

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].dns_filter` | bool | `false` | Run a master-tier blocky resolver clients use directly: filters, forwards local zones internally, and forwards the rest to the active exit resolvers |
| `fleet.masters[].dns.*` | — | — | Same shape as the exit resolver — see [§6 DNS](#6-dns-blocky) |

---

## 5. `fleet.exits[]` — exit nodes

### Identity and egress

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].name` | string | **required** | Stable node name; also seeds derived ports |
| `fleet.exits[].region` | string | — | Free-form label: `de`, `nl`, `fi` |
| `fleet.exits[].mgmt_addr` | string | — | ZeroTier/overlay address (admin, metrics, DNS bind) |
| `fleet.exits[].public_ip` | string | = `ssh.host` | Public IP the master dials for the AmneziaWG endpoint. Set it explicitly whenever SSH and the tunnel should take different paths. Must be an IP literal |
| `fleet.exits[].address_pool` | CIDR | — | Address pool for this exit's tunnel |
| `fleet.exits[].egress` | string | — | Preferred egress: `warp` or `direct` |
| `fleet.exits[].drain` | bool | `false` | Keep the exit out of the load balancer by declaration. The tunnel stays up and the node keeps reconciling; the console shows *drained by config* and Undrain is refused — remove the line and restart the controller instead |
| `fleet.exits[].egress_fallback` | []string | none | Ordered fallbacks for censorship-adaptive failover, e.g. `[direct]`. Empty disables failover. `direct` exposes the node's own IP |
| `fleet.exits[].min_egress_throughput_kbytes` | int | fleet value | Per-exit throughput floor. `>0` custom, `0` inherit, negative disables the watchdog here |
| `fleet.exits[].listen_port` | int | derived `20000`–`32000` | Legacy top-level AmneziaWG port. Prefer `fleet.exits[].transports.awg.listen_port` |

### MTU

Both keys accept `1280`–`1500`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].warp_mtu` | int | `1380` | MTU of the WARP interface. Set it when the real WARP path is smaller (typically 1320–1420). Unset, the agent probes the path daily |
| `fleet.exits[].link_mtu` | int | `1500` | Physical path MTU of the master↔exit link. Measure with `ping -M do -s N <exit-ip>` from the master: path MTU = largest passing N + 28. Lowers **both** tunnel ends and the client interface |

### `transports` — master↔exit transport selection

Two independently enabled sections. Neither enabled ⇒ AWG-only. Both enabled ⇒ both
run warm and the live path can be switched instantly.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].active_transport` | string | first enabled | Which transport the master routes through: `awg` or `reality-xhttp`. Also switchable live from the Web UI |
| `fleet.exits[].transports.awg.enabled` | bool | `true` when neither is set | Run the kernel AmneziaWG server |
| `fleet.exits[].transports.awg.listen_port` | int | derived from name | UDP port. Derived per exit so the fleet does not share one port |
| `fleet.exits[].transports.reality.enabled` | bool | `false` | Run the VLESS+REALITY+XHTTP inbound |
| `fleet.exits[].transports.reality.listen_port` | int | `443` | TCP port. Must differ from the AWG port |
| `fleet.exits[].transports.reality.dest_domain` | string | fleet default | Camouflage target host. **Must support X25519MLKEM768** — check with `xray tls ping <host>` |
| `fleet.exits[].transports.reality.dest_port` | int | `443` | Camouflage target port |
| `fleet.exits[].transports.reality.sni` | string | = `dest_domain` | Camouflage SNI |
| `fleet.exits[].transports.reality.mode` | string | `xhttp` | `xhttp` or `vision` |
| `fleet.exits[].transports.reality.fingerprint` | string | `chrome` | Master-side uTLS fingerprint: `chrome` \| `firefox` \| `none` |
| `fleet.exits[].transports.reality.empty_sni` | bool | `false` | Accept a ClientHello with no SNI extension |
| `fleet.exits[].transports.reality.mux` | bool | `false` | XMUX connection reuse on the master's proxy. `xhttp` mode only. This is XMUX, **not** sing-mux/smux |
| `fleet.exits[].transports.reality.allow_ipv6` | bool | `false` | Let xray resolve over IPv6. Leave off: a dest that resolves AAAA-only black-holes on an IPv4-only exit |
| `fleet.exits[].transports.reality.xhttp_path` | string | `/<short-id>` | XHTTP path |
| `fleet.exits[].transports.reality.image` | string | pinned xray | Container image |

### `firewall`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].firewall.as_blacklist` | bool | `false` | Drop traffic from known scanner ASNs, hiding the AmneziaWG port and SSH from active VPN scanning. Feed URLs are fleet-wide |
| `fleet.exits[].firewall.whitelist` | []CIDR | mgmt scope | Additional sources always accepted. The management overlay is merged in automatically |
| `fleet.exits[].firewall.public_tcp_ports` | []int | none | TCP ports opened to the whole internet |
| `fleet.exits[].firewall.public_udp_ports` | []int | none | UDP ports opened to the whole internet |

### Migration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].per_tunnel_key` | string | `off` | Staged migration from the master's single shared AmneziaWG identity to a per-tunnel one, **for this exit only**. Phases in order: `off` → `dual` → `switch` → `on`. Each step moves one side of the tunnel. Roll one node at a time and verify between steps |

### Exit DNS

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].dns_filter` | bool | `false` | Run the blocky resolver container on this exit |

### Lifeline

Reserve client interface `awgl0` on an exit: peers are the master's credentials (same
client keys, same host offset in this pool, per-exit preshared key), one reserve config
per credential per lifeline exit. Requires `masters[].client_awg.managed: true`; exit
name `[A-Za-z0-9._-]`, max 64. A reserve config routes everything (`0.0.0.0/0`)
regardless of the master's `exclude_from_tunnel`, so it has no split tunnel and no
IPv6 route.
Checks and hand-out: [operations.md](operations.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].lifeline.listen_port` | int | **required** | UDP port for the reserve interface. Must differ from the exit's own AmneziaWG port and from any `firewall.public_udp_ports` entry. Opened in the firewall automatically |
| `fleet.exits[].lifeline.address_pool` | CIDR | **required** | Client address pool for the reserve interface. Must be at least as large as the master's `client_awg.address_pool` and must not overlap any other pool in the fleet |
| `fleet.exits[].lifeline.egress` | string | `direct` | `direct` or `warp`. `warp` requires WARP to already be in this exit's egress chain (`egress` or `egress_fallback`) |
| `fleet.exits[].lifeline.dns` | []string | this exit's blocky | Resolvers in reserve configs. Unset + `dns_filter: true` ⇒ the interface gateway (blocky binds it). **Required** when `dns_filter` is off |
| `fleet.exits[].lifeline.allowed_ips` | []string | `0.0.0.0/0` | What a reserve config routes into the tunnel. IPv4 only; IPv6 entries are dropped. Override only if you know you need a split list here — `wg-quick`/`awg-quick` installs its endpoint-exclusion rules **only** for a literal `0.0.0.0/0`, so a split list there routes the exit's own address into its own tunnel and adds one route per prefix to the main table, where any prefix the client already holds aborts the bring-up |
| `fleet.exits[].lifeline.mtu` | int | derived | MTU override. Derived: link MTU minus one AmneziaWG layer; with `egress: warp` also capped by the WARP interface MTU |

---

## 6. DNS (blocky)

Identical shape on masters and exits. The renderer enforces the bind addresses
regardless of what you write here: loopback and `mgmt_addr`, plus — on an exit that
carries a `lifeline` — that interface's pool gateway, which is the resolver reserve
clients are handed. Verify with `ss -lunp | grep ':53'` on the node: two addresses on
a plain exit, three on a lifeline exit.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].dns.image` / `fleet.masters[].dns.image` | string | `spx01/blocky:latest` | Container repository |
| `fleet.exits[].dns.tag` / `fleet.masters[].dns.tag` | string | — | Explicit tag, overriding any tag in the image |
| `fleet.exits[].dns.upstreams` / `fleet.masters[].dns.upstreams` | []string | safe defaults | Default upstream resolver group. On a master these default to the active exit resolvers |
| `fleet.exits[].dns.allowlist` / `fleet.masters[].dns.allowlist` | []string | — | Domains never blocked. Platform infrastructure is added automatically |
| `fleet.exits[].dns.prometheus` / `fleet.masters[].dns.prometheus` | bool | `true` | Expose blocky's own `/metrics` |
| `fleet.exits[].dns.ports.dns` / `fleet.masters[].dns.ports.dns` | int | `53` | Plain DNS port |
| `fleet.exits[].dns.ports.tls` / `fleet.masters[].dns.ports.tls` | int | `853` | DNS-over-TLS port |
| `fleet.exits[].dns.ports.https` / `fleet.masters[].dns.ports.https` | int | disabled | DNS-over-HTTPS port |
| `fleet.exits[].dns.ports.http` / `fleet.masters[].dns.ports.http` | int | `4000` | HTTP port (metrics, query log UI) |
| `fleet.exits[].dns.overrides` / `fleet.masters[].dns.overrides` | map | none | **Deep-merged into the rendered blocky config.** Denylists, conditional local-zone mappings and caching go here |
| `fleet.exits[].dns.extra_files[].path` / `fleet.masters[].dns.extra_files[].path` | string | — | Additional managed file, e.g. a custom blocklist |
| `fleet.exits[].dns.extra_files[].content` / `fleet.masters[].dns.extra_files[].content` | string | — | Its literal contents |
| `fleet.exits[].dns.extra_files[].secret` / `fleet.masters[].dns.extra_files[].secret` | bool | `false` | Write mode `0600` and redact from logs |

---

## 7. SSH bootstrap

Bootstrap only; afterwards SSH is used again only for binary upgrades. Identical
shape on masters and exits.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].ssh.host` / `fleet.masters[].ssh.host` | string | — | Address the controller connects to. **Prefer the overlay address** where the public path is slow or throttled — the agent upload is ~28 MB |
| `fleet.exits[].ssh.port` / `fleet.masters[].ssh.port` | int | `22` | SSH port |
| `fleet.exits[].ssh.user` / `fleet.masters[].ssh.user` | string | — | Login user (needs root or passwordless sudo) |
| `fleet.exits[].ssh.key_path` / `fleet.masters[].ssh.key_path` | string | — | Private key on the **controller** host. `~` is expanded |
| `fleet.exits[].ssh.host_key` / `fleet.masters[].ssh.host_key` | string | trust-on-first-use | Pinned server host key, in `known_hosts` public-key form. **Strongly recommended:** bootstrap ships the node's mTLS private key over this channel |
| `fleet.exits[].ssh.insecure_ignore_host_key` / `fleet.masters[].ssh.insecure_ignore_host_key` | bool | `false` | Disable host-key verification for this node |

---

## 8. `agent.yaml` — per-node agent

Written by the controller at provisioning; documented for recovery and manual
patching. Everything else the agent needs arrives in the spec it pulls.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `agent.role` | string | **required** | `master` or `exit` |
| `agent.node_id` | string | **required** | Stable node identifier. Must match the certificate CN |
| `agent.controller` | string | **required** | Controller mTLS endpoint |
| `agent.mgmt_addr` | string | — | This node's overlay address. Binds `/metrics` at `<mgmt_addr>:9301` by default. Overridden by `--mgmt-addr` |
| `agent.reconcile_interval` | duration | `30s` | This node's reconcile cadence; overrides the fleet value |
| `agent.log_level` | string | `info` | `trace` \| `debug` \| `info` \| `warn` \| `error`. `debug` prints every planner's conclusion and self-check each pass; `trace` adds one line per planned action. `--log-level` overrides it. `systemctl kill -s USR1 wgfleet-agent` steps a running agent one level more verbose, `USR2` returns to this value |
| `agent.identity.cert` | string | **required** | Node client certificate |
| `agent.identity.key` | string | **required** | Node private key, mode `0600`, generated on the node and never transmitted |
| `agent.identity.ca` | string | **required** | CA certificate used to verify the controller |
| `agent.mgmt_overlay_mss` | int | `0` (off) | TCP MSS clamp on the overlay interface, both directions (see `fleet.mgmt_overlay_mss`). Valid `536`–`1460` |
| `agent.mgmt_ignore_cidrs` | []CIDR | none | Management scopes fail2ban must never ban (loopback always included). **Empty leaves the jail unmanaged** |
| `agent.as_blacklist_v4_url` | URL | C24Be v4 | Scanner-ASN feed source |
| `agent.as_blacklist_v6_url` | URL | C24Be v6 | IPv6 half of the feed |
| `agent.as_blacklist_interval` | duration | `24h` | Feed refresh cadence. Valid `1m`–`168h` |

---

## 9. Third-party configuration

If wgfleet models a setting, set the wgfleet key; otherwise use `overrides`
(deep-merged into the rendered config) or `extra_files` (arbitrary managed files).

| Tool | Role | Configured through | Upstream documentation |
|---|---|---|---|
| **mihomo** (Clash.Meta) | Master data plane: transparent proxy, geo-routing, exit load balancing | `fleet.masters[].mihomo.overrides` merged into `config.yaml` | <https://wiki.metacubex.one/en/config/> |
| **blocky** | DNS filtering and forwarding on masters and exits | `fleet.masters[].dns.overrides` / `fleet.exits[].dns.overrides` | <https://0xerr0r.github.io/blocky/latest/configuration/> |
| **xray-core** | REALITY/VLESS/XHTTP inbounds, both master↔exit and client-facing | Modelled keys only; the rendered config is not user-merged | <https://xtls.github.io/en/config/> · REALITY: <https://github.com/XTLS/REALITY> |
| **AmneziaWG** | Obfuscated WireGuard on all tunnels | Not user-tunable: obfuscation parameters are **generated** per tunnel. Hand-editing breaks the pairing | <https://docs.amnezia.org/documentation/amnezia-wg/> |
| **wg-easy** | Client management UI and client-facing AmneziaWG server on the master | `fleet.masters[].compose.*`; state lives in its SQLite DB, which wgfleet writes directly | <https://github.com/wg-easy/wg-easy/wiki> |
| **wgcf / Cloudflare WARP** | Exit egress | `fleet.exits[].warp_mtu`, `fleet.exits[].egress` | <https://github.com/ViRb3/wgcf> |
| **ZeroTier** | Management overlay | `fleet.zerotier_network` | <https://docs.zerotier.com/> |
| **nftables** | Node firewall | `fleet.exits[].firewall.*`; the ruleset itself is rendered, not user-supplied | <https://wiki.nftables.org/> |
| **fail2ban** | SSH brute-force protection | `agent.mgmt_ignore_cidrs`; the jail is rendered and continuously reconciled | <https://github.com/fail2ban/fail2ban/wiki> |
| **SOPS / age** | Secret storage behind `secret://` | `controller.secrets.sops_file` | <https://github.com/getsops/sops> |

### Using `overrides` safely

- Deep merge, not replacement: write only the nested path you want changed, not the
  whole parent block.
- Lists are replaced wholesale, not concatenated: supply the full list.
- An override survives a release that changes the rendered defaults, and is yours to
  maintain. Validate after any change:

```sh
wgfleet-controller --config controller.yaml --check-config
```

---

## 10. Validation

Both files are validated at startup and the process refuses to run on a bad value:

- `fleet.zerotier_network` must be exactly 16 hex characters.
- `fleet.masters[].routing.direct_cidrs` and `fleet.exits[].firewall.whitelist`
  entries must parse as CIDRs.
- `controller.webui` and `controller.metrics` must bind a management address unless
  `WGFLEET_ALLOW_PUBLIC_BIND=1`.
- More than one entry in `fleet.masters[]` is rejected.
- Durations, MTUs and MSS values are range-checked; the error names the key and the
  accepted band.

`--check-config` validates a manifest without touching the fleet: it parses the file,
prints its digest and the master/exit counts, then makes the checks a restart makes —
the secret provider, the CA, `fleet.awg3_key` resolved rather than merely referenced,
and whether the store is one this binary can open. It does not create the store, run
migrations or change permissions.

`--plan` is a modifier for the subcommands that have a dry run (`--provision`,
`--upgrade-agent`, `--rolling-upgrade`, `--restore`, `--import-wg-easy`); on its own,
or with `--backup` or `--certs`, it is refused.

## AmneziaWG 3.0

`fleet.awg3` (and its per-exit override) switches the **master↔exit** tunnels to
AmneziaWG 3.0: chacha20 header protection plus randomised rekey/keepalive timers. Off
by default: enabling it changes the wire format of a live tunnel. The client leg has
its own switch, `fleet.masters[].client_awg.awg3`; both need `fleet.awg3_key`.

### Before you turn it on

Two gates apply. A premature flip degrades to "stays on 2.0", not to a dead tunnel.

| Gate | Requirement | When it fires |
|---|---|---|
| Controller | Both ends of the tunnel on wire **v7** or later — the master is the end that lags, since the rolling upgrade never touches masters | Renders 2.0 for that tunnel |
| Agent | The node's own kernel module is 3.x and on the same generation as `amneziawg-tools` (a mismatch fails `awg setconf` with `attribute type 14 has an invalid length`) | Refuses the 3.x config, keeps the last good one. Fires on **any** 3.x field, so it also gates `client_awg.awg3: timers` on the master's module |

Check what a node runs before flipping the key — the master too:

```sh
modinfo amneziawg | grep ^version   # kernel module generation
awg --version                       # userspace tools generation
```
