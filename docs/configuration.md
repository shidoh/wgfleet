# wgfleet — configuration reference

Every configurable key, what it does, its default, and where the underlying
third-party tool documents the passthrough surface.

There are exactly two config files:

| File | Read by | Written by |
|---|---|---|
| `controller.yaml` | `wgfleet-controller` | **you** — this is the fleet manifest |
| `agent.yaml` | `wgfleet-agent`, one per node | the controller, at provisioning |

You normally only ever edit `controller.yaml`. The agent file is generated on each
node during bootstrap and is documented here because you may need to read or
hand-patch it during recovery.

Annotated starting points ship in `examples/` next to this file (in the source
repository: `deploy/examples/`):

- `controller.yaml` — full reference manifest, every key present, commented
- `controller-split-ru.yaml` — production RU split-tunnel + DNS filter, with
  `<placeholders>` to fill in
- `agent.yaml` — what the controller writes on a node

Both example manifests are loaded and validated by the test suite, so a shipped
example always parses.

> **Completeness is enforced.** `internal/config/reference_test.go` walks the config
> structs by reflection and fails the build if a key exists in code but is missing
> here, or if this file documents a key that no longer exists. If a key is not on
> this page, it is not a key.

---

## 1. How values resolve

Precedence, lowest to highest:

1. **Built-in default** — what you get by omitting the key. Listed per key below.
2. **`controller.yaml` / `agent.yaml`** value.
3. **Environment override** — any key can be overridden with a `WGFLEET_`-prefixed
   env var: uppercase the path and replace dots with underscores.
   `controller.listen` → `WGFLEET_CONTROLLER_LISTEN=0.0.0.0:9443`.
4. **CLI flag**, where one exists (`--listen`, `--metrics`, `--config`, …).

Durations are Go duration strings: `30s`, `5m`, `24h`, `168h`. Sizes and ports are
plain integers. Lists accept YAML sequences or a comma-separated string.

### Secret values

`controller.pki.ca_key` is a `Secret`: never write the key material inline in a
file you commit. It accepts a scheme:

| Form | Resolves to |
|---|---|
| `env://NAME` | environment variable `NAME` |
| `file:///path/to/key` | contents of the file (must be mode `0600`) |
| `secret://name` | the configured secret provider — SOPS/age when `controller.secrets.sops_file` is set, otherwise env var `WGFLEET_SECRET_<NAME>` |
| bare string | inline literal — local development only |

SOPS setup is covered in `docs/secrets-sops.md` in the source repository.

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
| `controller.listen` | string | **required** | gRPC/mTLS endpoint agents connect to, e.g. `0.0.0.0:9443` |
| `controller.advertise` | string | = `listen` | Address agents should dial when it differs from the bind — behind NAT, a gateway, or a published load balancer. Also adds a SAN to the server certificate so TLS validates the dialed name |
| `controller.store` | string | **required** | Path to the SQLite state database |
| `controller.webui` | string | disabled | Web UI bind. **Must be a mgmt/overlay address** unless `WGFLEET_ALLOW_PUBLIC_BIND=1` |
| `controller.metrics` | string | disabled | Prometheus `/metrics` bind (conventionally `<mgmt>:9300`). Same mgmt-only restriction |
| `controller.agent_bin` | string | — | Path to the `wgfleet-agent` binary the controller installs during UI-triggered provisioning |
| `controller.staleness_after` | duration | `3m` | Mark a node Degraded after this long with no status report. Negative disables the sweep |
| `controller.session_ttl` | duration | `168h` (7d) | Web panel sliding session lifetime |
| `controller.pki.ca_cert` | string | **required** | Path to the fleet CA certificate (public) |
| `controller.pki.ca_key` | secret | — | Reference to the CA private key — see [Secret values](#secret-values) |
| `controller.secrets.sops_file` | string | env provider | Path to a SOPS-encrypted YAML file backing `secret://` lookups |

---

## 3. `fleet` — fleet-wide settings

These apply to every node. Several are *baked into each `agent.yaml`* at
provisioning time, which means **changing them requires re-provisioning the node**
(or hand-editing its agent file) — they are marked **baked**.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.zerotier_network` | string | — | ZeroTier network ID (exactly 16 hex chars) every node joins during bootstrap. Validated strictly: it is interpolated into a root shell command |
| `fleet.mgmt_subnet` | CIDR | derived | The management overlay's CIDR. When set, this is the authoritative trust scope: exits route it DIRECT (never through WARP) and accept it in the firewall, without you listing it per node. Empty ⇒ derived from each node's `mgmt_addr` as /32s |
| `fleet.mgmt_overlay_mss` | int | `0` (off) | **baked.** TCP MSS clamp on the ZeroTier interface. Control-plane insurance: keeps the agent↔controller TLS handshake alive if the overlay MTU is larger than the real path. Recommended `1240`; valid `536`–`1460` |
| `fleet.reconcile_interval` | duration | `30s` | **baked.** How often every agent reconciles — governs drift repair and self-heal latency. Valid `5s`–`1h`. A node's own `agent.reconcile_interval` still wins |
| `fleet.min_egress_throughput_kbytes` | int | `250` | Egress throughput floor in KiB/s below which an exit is pulled from the load balancer. mihomo's latency-only health check cannot see a throttled-but-responsive exit. Negative disables the watchdog fleet-wide |
| `fleet.egress_throughput_probe_url` | URL | Cloudflare speed endpoint | What each exit downloads to measure its own throughput |
| `fleet.as_blacklist_v4_url` | URL | C24Be AS_Network_List v4 | **baked.** Source feed of scanner ASNs the exit firewall drops. Per-exit enable is `fleet.exits[].firewall.as_blacklist` |
| `fleet.as_blacklist_v6_url` | URL | C24Be AS_Network_List v6 | **baked.** IPv6 half of the same feed |
| `fleet.as_blacklist_interval` | duration | `24h` | **baked.** Feed refresh cadence. Valid `1m`–`168h`. A failed refresh keeps the last-good list |
| `fleet.reality_default_sni` | string | `www.python.org` | Fleet-wide REALITY camouflage SNI. **The target must support X25519MLKEM768** or the handshake fails silently — verify a candidate with `xray tls ping <host>` |
| `fleet.reality_default_dest` | string | = SNI | Fleet-wide camouflage `host:port` the REALITY inbound borrows its certificate from |

---

## 4. `fleet.masters[]` — master nodes

> Exactly one master is supported today. The controller rejects a manifest with
> more than one: the key broker peers every exit to the first master only, so a
> second would render specs that silently never connect. Multi-master is planned but not yet implemented.

### Identity and exposure

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].name` | string | **required** | Stable node name. This is the node's identity — renaming means re-issuing its certificate |
| `fleet.masters[].mgmt_addr` | string | — | ZeroTier/overlay address. Binds admin surfaces and is trusted by construction |
| `fleet.masters[].public_ip` | string | = `ssh.host` | Public IP clients and peers reach this node at |
| `fleet.masters[].client_admin_ports` | []int | none | Admin ports (Web UI, mihomo dashboard) opened **to the VPN client pool** on the mgmt address. Opt-in; default keeps admin reachable only over the overlay |
| `fleet.masters[].public_tcp_ports` | []int | none | TCP ports opened **to the whole internet** — e.g. `80` for a decoy web listener. Unlike the previous key this is unscoped, so keep it to genuinely public services |

### `client_awg` — the client-facing WireGuard listener

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].client_awg.listen_port` | int | `443` | UDP port real VPN clients connect to. 443 blends with HTTPS traffic |
| `fleet.masters[].client_awg.address_pool` | CIDR | — | Address pool handed to clients |

### `client_vless` — DPI-resistant client transport

A VLESS+REALITY+XHTTP inbound that runs **alongside** client AmneziaWG, for clients
whose AWG is throttled by DPI. Traffic converges into mihomo, so VLESS clients get
the same geo-routing, load balancing, exits and DNS. Per-client credentials
(UUID + short-id) are issued and revoked in the Web UI, not here.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].client_vless.enabled` | bool | `false` | Turn the inbound on |
| `fleet.masters[].client_vless.listen_port` | int | derived `40000`–`60000` | TCP port. High ports deliberately: 443 is deeply inspected by RU TSPU. Derived stably from the master name when unset |
| `fleet.masters[].client_vless.dest_domain` | string | fleet default | Camouflage target host |
| `fleet.masters[].client_vless.dest_port` | int | `443` | Camouflage target port |
| `fleet.masters[].client_vless.sni` | string | = `dest_domain` | SNI the ClientHello impersonates |
| `fleet.masters[].client_vless.mode` | string | `xhttp` | `xhttp` (packet-up; addresses the volume-based throttling of persistent TLS flows) or `vision` (classic TCP + xtls-rprx-vision) |
| `fleet.masters[].client_vless.empty_sni` | bool | **`true`** | Accept/send a ClientHello with no SNI extension. The strongest reported RU TSPU bypass on the client leg — set `false` to force off |
| `fleet.masters[].client_vless.fingerprint` | string | `firefox` | uTLS ClientHello fingerprint. `firefox` is off the chrome signature DPI flags first. `none` omits it |
| `fleet.masters[].client_vless.mux` | bool | **`true`** | XMUX (XHTTP connection reuse) in the generated client profile — amortizes the REALITY handshake across streams. `xhttp` mode only |
| `fleet.masters[].client_vless.allow_ipv6` | bool | `false` | Let xray resolve the camouflage dest over IPv6. The data plane is IPv4-only, so leave off unless this node genuinely has IPv6 egress |
| `fleet.masters[].client_vless.xhttp_path` | string | `/` | XHTTP path |
| `fleet.masters[].client_vless.route_through_cidrs` | []CIDR | none | Internal networks a client must route **through** the tunnel. Most clients send RFC1918 direct by default, so the overlay and any work nets behind the master are otherwise unreachable. Becomes the v2rayTun routing object shown in the UI and served in the subscription's `routing` header |
| `fleet.masters[].client_vless.image` | string | pinned xray | Container image |
| `fleet.masters[].client_vless.tag` | string | — | Explicit tag, overriding any tag in `image` |

### `routing` — geo-routing and exit selection

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].routing.direct_cidrs` | []CIDR | none | Destinations routed DIRECT, never through an exit. Each consumes a routing priority; there is a hard cap. Values are interpolated into the nft ruleset and are strictly parsed |
| `fleet.masters[].routing.direct_geo` | []string | none | Geo codes routed DIRECT, e.g. `["RU"]` |
| `fleet.masters[].routing.balance` | string | `round-robin` | How the exit group picks: `round-robin`, `consistent-hashing` (same dst → same exit; alias `health`), `sticky-sessions` (same src+dst → same exit), `url-test` (lowest latency wins), `fallback` (primary, fail over on timeout) |
| `fleet.masters[].routing.reserve_exits` | []string | none | Exits kept as a **second tier**, used only when every primary is down. Everything not listed is primary, so a newly added exit defaults to primary. Use manifest exit names, not rendered proxy names |

### `mihomo` — the master data plane

See [§9 third-party configuration](#9-third-party-configuration) for the passthrough surface.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].mihomo.redir_port` | int | `7895` | Transparent-proxy redirect port |
| `fleet.masters[].mihomo.health_interval` | duration | `60s` | How often mihomo health-checks exits. Lower it to fail off a dead exit faster. Valid `5s`–`1h` |
| `fleet.masters[].mihomo.max_failed_times` | int | `5` | Consecutive failures that force an out-of-band health check. Raise it where some traffic legitimately fails and the re-check is noise |
| `fleet.masters[].mihomo.sniffer_skip` | []string | none | Domains the sniffer must not rewrite. Needed when destination override breaks a protocol |
| `fleet.masters[].mihomo.dashboard_url` | URL | metacubexd release | Where to fetch the web dashboard. Point at a mirror where GitHub is blocked |
| `fleet.masters[].mihomo.dashboard_disabled` | bool | `false` | Skip the dashboard entirely — mihomo then never attempts the download |
| `fleet.masters[].mihomo.overrides` | map | none | **Deep-merged into the rendered mihomo `config.yaml`.** The escape hatch for anything wgfleet does not model |
| `fleet.masters[].mihomo.extra_files[].path` | string | — | Additional managed file written alongside the config, e.g. a rule-provider list |
| `fleet.masters[].mihomo.extra_files[].content` | string | — | Its literal contents |
| `fleet.masters[].mihomo.extra_files[].secret` | bool | `false` | Write mode `0600` and redact from logs and dry-run output |

### `compose` — the master container stack

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].compose.wg_easy_image` | string | pinned wg-easy 15 | Repository, optionally with a tag |
| `fleet.masters[].compose.wg_easy_tag` | string | — | Explicit tag, overriding any tag in the image |
| `fleet.masters[].compose.wg_easy_web_port` | int | `44423` | wg-easy admin UI port |
| `fleet.masters[].compose.mihomo_image` | string | `metacubex/mihomo` | Repository, optionally with a tag |
| `fleet.masters[].compose.mihomo_tag` | string | pinned | Explicit tag. **Pin this deliberately** — some releases crash-loop on AmneziaWG 2.0 parameters |
| `fleet.masters[].compose.client_dns` | []string | exit mgmt addrs | DNS servers handed to clients |
| `fleet.masters[].compose.client_allowed_ips` | string | `0.0.0.0/0` | `AllowedIPs` written into client configs. IPv4-only by default: the data plane has no IPv6, and offering `::/0` black-holes dual-stack clients |

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
| `fleet.exits[].public_ip` | string | = `ssh.host` | Public IP the master dials for the WireGuard endpoint |
| `fleet.exits[].address_pool` | CIDR | — | Address pool for this exit's tunnel |
| `fleet.exits[].egress` | string | — | Preferred egress: `warp` or `direct` |
| `fleet.exits[].egress_fallback` | []string | none | Ordered fallbacks for censorship-adaptive failover, e.g. `[direct]`. Empty disables failover |
| `fleet.exits[].min_egress_throughput_kbytes` | int | fleet value | Per-exit throughput floor. `>0` custom, `0` inherit, negative disables the watchdog here |
| `fleet.exits[].listen_port` | int | derived `20000`–`32000` | Legacy top-level WireGuard port. Prefer `fleet.exits[].transports.awg.listen_port` |

### MTU

Both keys accept `1280`–`1500`. Getting these wrong produces the worst failure mode
in this system: a tunnel that establishes and then intermittently hangs.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].warp_mtu` | int | `1380` | MTU of the WARP interface. Set it when the real WARP path is smaller (typically 1320–1420). Unset, the agent probes the path daily |
| `fleet.exits[].link_mtu` | int | `1500` | Physical path MTU of the master↔exit link. Measure with `ping -M do -s N <exit-ip>` from the master: path MTU = largest passing N + 28. Lowers **both** tunnel ends and the client interface, so client payloads never exceed what survives the narrowest exit |

### `transports` — master↔exit transport selection

Two independently enabled sections. Neither enabled ⇒ AWG-only. Both enabled ⇒ both
run warm and you can switch the live path instantly.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].active_transport` | string | first enabled | Which transport the master actually routes through: `awg` or `reality-xhttp`. Also switchable live from the Web UI |
| `fleet.exits[].transports.awg.enabled` | bool | `true` when neither is set | Run the kernel AmneziaWG server |
| `fleet.exits[].transports.awg.listen_port` | int | derived from name | UDP port. Derived per exit so the fleet is not fingerprintable by one shared port |
| `fleet.exits[].transports.reality.enabled` | bool | `false` | Run the VLESS+REALITY+XHTTP inbound |
| `fleet.exits[].transports.reality.listen_port` | int | `443` | TCP port. Must differ from the AWG port so both can run warm |
| `fleet.exits[].transports.reality.dest_domain` | string | fleet default | Camouflage target host. **Must support X25519MLKEM768** — check with `xray tls ping <host>` |
| `fleet.exits[].transports.reality.dest_port` | int | `443` | Camouflage target port |
| `fleet.exits[].transports.reality.sni` | string | = `dest_domain` | Camouflage SNI |
| `fleet.exits[].transports.reality.mode` | string | `xhttp` | `xhttp` or `vision`. Flip to isolate XHTTP interop problems |
| `fleet.exits[].transports.reality.fingerprint` | string | `chrome` | Master-side uTLS fingerprint. Against heuristic DPI, `firefox` or `none` survive where `chrome` is flagged |
| `fleet.exits[].transports.reality.empty_sni` | bool | `false` | Accept a ClientHello with no SNI extension |
| `fleet.exits[].transports.reality.mux` | bool | `false` | XMUX connection reuse on the master's proxy. `xhttp` mode only. Note this is XMUX, **not** sing-mux/smux, which xray rejects |
| `fleet.exits[].transports.reality.allow_ipv6` | bool | `false` | Let xray resolve over IPv6. Leave off: a dest that resolves AAAA-only black-holes on an IPv4-only exit |
| `fleet.exits[].transports.reality.xhttp_path` | string | `/<short-id>` | XHTTP path |
| `fleet.exits[].transports.reality.image` | string | pinned xray | Container image |

### `firewall`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].firewall.as_blacklist` | bool | `false` | Drop traffic from known scanner ASNs, hiding the WireGuard port and SSH from active VPN scanning. Feed URLs are fleet-wide |
| `fleet.exits[].firewall.whitelist` | []CIDR | mgmt scope | Additional sources always accepted. The management overlay is merged in automatically |
| `fleet.exits[].firewall.public_tcp_ports` | []int | none | TCP ports opened to the whole internet |

### Migration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].per_tunnel_key` | string | `off` | Staged migration from the master's single shared WireGuard identity to a per-tunnel one, **for this exit only**. Phases in order: `off` → `dual` → `switch` → `on`. Each step moves exactly one side of the tunnel, which is what makes it rollback-safe. Deliberately manual — roll one node at a time and verify between steps |

### Exit DNS

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].dns_filter` | bool | `false` | Run the blocky resolver container on this exit |

---

## 6. DNS (blocky)

Identical shape on masters and exits. Safety — loopback and mgmt-only binds — is
enforced by the renderer regardless of what you write here.

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
| `fleet.exits[].dns.overrides` / `fleet.masters[].dns.overrides` | map | none | **Deep-merged into the rendered blocky config.** This is where denylists, conditional local-zone mappings and caching go |
| `fleet.exits[].dns.extra_files[].path` / `fleet.masters[].dns.extra_files[].path` | string | — | Additional managed file, e.g. a custom blocklist |
| `fleet.exits[].dns.extra_files[].content` / `fleet.masters[].dns.extra_files[].content` | string | — | Its literal contents |
| `fleet.exits[].dns.extra_files[].secret` / `fleet.masters[].dns.extra_files[].secret` | bool | `false` | Write mode `0600` and redact from logs |

---

## 7. SSH bootstrap

Bootstrap only. Once the agent is installed, management moves to mTLS and SSH is
used again only for binary upgrades. Identical shape on masters and exits.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].ssh.host` / `fleet.masters[].ssh.host` | string | — | Address the controller connects to. **Prefer the overlay address** where the public path is slow or throttled — a 28 MB agent upload over a throttled path can take tens of minutes |
| `fleet.exits[].ssh.port` / `fleet.masters[].ssh.port` | int | `22` | SSH port |
| `fleet.exits[].ssh.user` / `fleet.masters[].ssh.user` | string | — | Login user (needs root or passwordless sudo) |
| `fleet.exits[].ssh.key_path` / `fleet.masters[].ssh.key_path` | string | — | Private key on the **controller** host. `~` is expanded |
| `fleet.exits[].ssh.host_key` / `fleet.masters[].ssh.host_key` | string | trust-on-first-use | Pinned server host key, in `known_hosts` public-key form. **Strongly recommended:** bootstrap ships the node's mTLS private key over this channel, so an unpinned MITM captures the node's identity |
| `fleet.exits[].ssh.insecure_ignore_host_key` / `fleet.masters[].ssh.insecure_ignore_host_key` | bool | `false` | Disable host-key verification for this node. Trades away MITM protection on the channel carrying the node's key |

---

## 8. `agent.yaml` — per-node agent

Written by the controller at provisioning. Documented for recovery and manual
patching. The agent is deliberately thin: it needs to know who it is and where the
controller is; everything else arrives in the spec it pulls.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `agent.role` | string | **required** | `master` or `exit` |
| `agent.node_id` | string | **required** | Stable node identifier. Must match the certificate CN — the certificate is the real identity, this key only mirrors it |
| `agent.controller` | string | **required** | Controller mTLS endpoint |
| `agent.mgmt_addr` | string | — | This node's overlay address. Binds `/metrics` at `<mgmt_addr>:9301` by default. Overridden by `--mgmt-addr` |
| `agent.reconcile_interval` | duration | `30s` | This node's reconcile cadence; overrides the fleet value |
| `agent.identity.cert` | string | **required** | Node client certificate |
| `agent.identity.key` | string | **required** | Node private key, mode `0600`, generated on the node and never transmitted |
| `agent.identity.ca` | string | **required** | CA certificate used to verify the controller |
| `agent.mgmt_overlay_mss` | int | `0` (off) | TCP MSS clamp on the overlay interface. Agent-local by design: it must not depend on the channel it protects. Valid `536`–`1460` |
| `agent.mgmt_ignore_cidrs` | []CIDR | none | Management scopes fail2ban must never ban (loopback always included). **Empty leaves the jail unmanaged**, so a node provisioned before this key existed is never regressed to a narrower `ignoreip` |
| `agent.as_blacklist_v4_url` | URL | C24Be v4 | Scanner-ASN feed source |
| `agent.as_blacklist_v6_url` | URL | C24Be v6 | IPv6 half of the feed |
| `agent.as_blacklist_interval` | duration | `24h` | Feed refresh cadence. Valid `1m`–`168h` |

---

## 9. Third-party configuration

wgfleet orchestrates existing tools rather than reimplementing them. It models the
settings that must be fleet-consistent, and hands you the full upstream surface
through **`overrides`** (deep-merged into the rendered config) and **`extra_files`**
(arbitrary managed files).

The pattern to remember: *if wgfleet models it, set the wgfleet key — it keeps the
renderer, firewall and routing consistent. If wgfleet does not model it, use
`overrides` and consult the upstream documentation below.*

| Tool | Role | Configured through | Upstream documentation |
|---|---|---|---|
| **mihomo** (Clash.Meta) | Master data plane: transparent proxy, geo-routing, exit load balancing | `fleet.masters[].mihomo.overrides` merged into `config.yaml` | <https://wiki.metacubex.one/en/config/> |
| **blocky** | DNS filtering and forwarding on masters and exits | `fleet.masters[].dns.overrides` / `fleet.exits[].dns.overrides` | <https://0xerr0r.github.io/blocky/latest/configuration/> |
| **xray-core** | REALITY/VLESS/XHTTP inbounds, both master↔exit and client-facing | Modelled keys only; the rendered config is not user-merged | <https://xtls.github.io/en/config/> · REALITY: <https://github.com/XTLS/REALITY> |
| **AmneziaWG** | Obfuscated WireGuard on all tunnels | Not user-tunable: obfuscation parameters are **generated** per tunnel, collision-safe. Hand-editing breaks the pairing | <https://docs.amnezia.org/documentation/amnezia-wg/> |
| **wg-easy** | Client management UI and client WireGuard server on the master | `fleet.masters[].compose.*`; state lives in its SQLite DB, which wgfleet writes directly | <https://github.com/wg-easy/wg-easy/wiki> |
| **wgcf / Cloudflare WARP** | Exit egress | `fleet.exits[].warp_mtu`, `fleet.exits[].egress` | <https://github.com/ViRb3/wgcf> |
| **ZeroTier** | Management overlay | `fleet.zerotier_network` | <https://docs.zerotier.com/> |
| **nftables** | Node firewall | `fleet.exits[].firewall.*`; the ruleset itself is rendered, not user-supplied | <https://wiki.nftables.org/> |
| **fail2ban** | SSH brute-force protection | `agent.mgmt_ignore_cidrs`; the jail is rendered and continuously reconciled | <https://github.com/fail2ban/fail2ban/wiki> |
| **SOPS / age** | Secret storage behind `secret://` | `controller.secrets.sops_file` | <https://github.com/getsops/sops> |

### Using `overrides` safely

`overrides` is a **deep merge**, not a replacement: your keys are merged into the
rendered tree, and only the leaves you name are affected. Two consequences:

- To change one nested value you write only that path, not the whole parent block.
- To **replace** a rendered list (rather than have wgfleet's entries stay), supply
  the full list — lists are replaced wholesale, not concatenated.

Anything you override is yours to maintain: wgfleet will not correct it, and a
future release that changes the rendered defaults will still apply your override on
top. Check dry-run output after any override change:

```sh
wgfleet-controller --config controller.yaml --plan
```

---

## 10. Validation

Both files are validated at startup and the process refuses to run on a bad value.
Checks worth knowing about:

- `fleet.zerotier_network` must be exactly 16 hex characters — it is interpolated
  into a root shell command on every node.
- `fleet.masters[].routing.direct_cidrs` and `fleet.exits[].firewall.whitelist`
  entries must parse as CIDRs — they are interpolated into the rendered nft ruleset.
- `controller.webui` and `controller.metrics` must bind a management address unless
  `WGFLEET_ALLOW_PUBLIC_BIND=1`.
- More than one entry in `fleet.masters[]` is rejected outright.
- Durations, MTUs and MSS values are range-checked; the error names the key and the
  accepted band.

To check a manifest without touching the fleet, run the controller in plan mode —
it loads, validates and renders every node's desired state, changing nothing.
