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
3. **Environment override** — a `WGFLEET_`-prefixed env var: uppercase the path and
   replace dots with underscores. `controller.listen` → `WGFLEET_CONTROLLER_LISTEN`.

   **This reaches only keys whose every path segment is a single word.** The loader
   turns *every* underscore back into a dot, so it cannot tell a separator from a
   word: a variable naming a two-word key resolves to a dotted path with an extra
   level in it, matches nothing, and is **silently ignored** — no error, no warning.
   (`WGFLEET_CONTROLLER_STALENESS_AFTER` is the shape that fails.) Anything
   under `fleet.masters[]` / `fleet.exits[]` is unreachable regardless, having no
   scalar path. Use the manifest for those; the env override is for the handful of
   single-word keys, and for secrets referenced as `env://`.
4. **CLI flag**, where one exists (`--config`, `--store`, `--metrics`, …). There is no
   `--listen`: the controller's listen addresses come from the manifest only.

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
| `controller.listen` | string | **required** | gRPC/mTLS endpoint agents connect to. Bind the mgmt/ZT address, e.g. `10.20.25.254:8443` — agents dial exactly what is written here, so `0.0.0.0` works only together with `controller.advertise` |
| `controller.advertise` | string | = `listen` | Address agents should dial when it differs from the bind — behind NAT, a gateway, or a published load balancer. Also adds a SAN to the server certificate so TLS validates the dialed name |
| `controller.store` | string | **required** | Path to the SQLite state database |
| `controller.webui` | string | disabled | Web UI bind. **Must be a mgmt/overlay address** unless `WGFLEET_ALLOW_PUBLIC_BIND=1` |
| `controller.metrics` | string | disabled | Prometheus `/metrics` bind (conventionally `<mgmt>:9300`). Same mgmt-only restriction |
| `controller.client_portal_url` | string | — | Base URL clients reach the portal on — the address a phone types, e.g. `https://vpn.example.org`. The controller knows its bind, not the address a phone types, so without this it cannot show you the per-client link to hand out |
| `controller.client_portal` | string | disabled | Bind for the client self-service portal: a person opens their own link and gets their own profile and QR — nothing else. Deliberately a separate listener from `webui`, which can provision, decommission and drain nodes and export a fleet backup; bind it on the master's **mgmt address** and list its port in `client_admin_ports` — that is how a client-facing service on the master is reached, and it is where the wg-easy UI lived. Binding it on the gateway address inside the client pool does not work: the master's NAT and input firewall are built around the mgmt address. A public bind is refused outright, since the portal serves private keys over plain HTTP |
| `controller.agent_bin` | string | — | Path to the `wgfleet-agent` binary the controller installs during UI-triggered provisioning. Also the rolling upgrade's target: nodes are selected by comparing against **this binary's** version, not the controller's, so upgrading only the controller does not make the fleet look outdated |
| `controller.staleness_after` | duration | `3m` | Mark a node Degraded after this long with no status report. Negative disables the sweep |
| `controller.session_ttl` | duration | `168h` (7d) | Web panel sliding session lifetime |
| `controller.pki.ca_cert` | string | **required** | Path to the fleet CA certificate (public) |
| `controller.pki.ca_key` | secret | **required** | Reference to the CA private key — see [Secret values](#secret-values). Every start except `--init-pki` loads it and refuses to run without it |
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
| `fleet.mgmt_overlay_mss` | int | `0` (off) | **baked.** TCP MSS clamp on the ZeroTier interface, **both directions**. Two jobs: control-plane insurance (keeps the agent↔controller TLS handshake alive if the overlay MTU is larger than the real path) and the clamp for traffic a node FORWARDS into the overlay — a client reaching a host behind a ZeroTier member, where neither end can see the narrow middle. ZeroTier cannot do this itself: it pushes interface MTU, and MTU governs only locally-originated flows. Recommended `1240` (a 1280 overlay); valid `536`–`1460` |
| `fleet.reconcile_interval` | duration | `30s` | **baked.** How often every agent reconciles — governs drift repair and self-heal latency. Valid `5s`–`1h`. A node's own `agent.reconcile_interval` still wins |
| `fleet.min_egress_throughput_kbytes` | int | `250` | Egress throughput floor in KiB/s below which an exit is pulled from the load balancer. mihomo's latency-only health check cannot see a throttled-but-responsive exit. Negative disables the watchdog fleet-wide |
| `fleet.egress_throughput_probe_url` | URL | Cloudflare speed endpoint | What each exit downloads to measure its own throughput |
| `fleet.as_blacklist_v4_url` | URL | C24Be AS_Network_List v4 | **baked.** Source feed of scanner ASNs the exit firewall drops. Per-exit enable is `fleet.exits[].firewall.as_blacklist` |
| `fleet.as_blacklist_v6_url` | URL | C24Be AS_Network_List v6 | **baked.** IPv6 half of the same feed |
| `fleet.as_blacklist_interval` | duration | `24h` | **baked.** Feed refresh cadence. Valid `1m`–`168h`. A failed refresh keeps the last-good list |
| `fleet.reality_default_sni` | string | `www.python.org` | Fleet-wide REALITY camouflage SNI. **The target must support X25519MLKEM768** or the handshake fails silently — verify a candidate with `xray tls ping <host>` |
| `fleet.reality_default_dest` | string | = SNI | Fleet-wide camouflage `host:port` the REALITY inbound borrows its certificate from |
| `fleet.hardening.sshd` | bool | `true` | **Fleet default.** Manage the sshd drop-in (`/etc/ssh/sshd_config.d/10-wgfleet-hardening.conf`: key-only auth, no root password, no X11 forwarding), reconciled every pass. Set `false` to hand sshd back to you — see below |
| `fleet.hardening.fail2ban` | bool | `true` | **Fleet default.** Manage the fail2ban sshd jail (`/etc/fail2ban/jail.d/wgfleet.conf`) |
| `fleet.awg3` | bool | `false` | **Fleet default.** Run the master↔exit AmneziaWG tunnels on **AmneziaWG 3.0** (header protection + randomised timers). Opt-in, unlike the hardening keys above — see [AmneziaWG 3.0](#amneziawg-30) |
| `fleet.awg3_key` | secret ref | — | **Required whenever header protection is on** (`fleet.awg3`, `fleet.exits[].awg3`, or `client_awg.awg3: full`). The fleet secret the 3.x chacha20 header-protection key is derived from. Every other AmneziaWG parameter comes from a public, versioned salt — they resist DPI by being non-default, not by being unknown — but this one is a key whose whole purpose is that an observer does not have it, so it may not come from anything in this repository. Write it to a FILE and reference it as `file:///etc/wgfleet/awg3.key` (32+ random
bytes). A `secret://` or `env://` reference works too, but only a file travels in
`--backup` — every other form is reported as missing from the archive, and losing
this key invalidates every client config in the field at once. Whatever form you
choose, the controller refuses to start if header protection is enabled without it. The 3.x **timers** need no secret |

### Turning hardening off

Both subsystems are on unless you write the key. Omitting the block entirely gives
you the fully hardened fleet earlier versions applied unconditionally.

**It is per-node, with a fleet-wide default.** Hardening is a property of a
particular machine: the box you hand-tune is usually *one* box — typically the
master, where the controller runs and where you actually log in — while the exits
are cattle. So each node may override the fleet:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].hardening.sshd` | bool | inherit fleet | Override the fleet default for this master |
| `fleet.masters[].hardening.fail2ban` | bool | inherit fleet | Override the fleet default for this master |
| `fleet.exits[].hardening.sshd` | bool | inherit fleet | Override the fleet default for this exit |
| `fleet.exits[].hardening.fail2ban` | bool | inherit fleet | Override the fleet default for this exit |
| `fleet.exits[].awg3` | bool | inherit fleet | Override `fleet.awg3` for this exit. Per-exit because the fleet's exits need not share a kernel-module generation |

Precedence is node → fleet → `true`. An omitted key on a node means *inherit*, not
*disable*, and an explicit `true` on a node beats a fleet-wide `false` — so the
override can re-harden one node as well as relax one.

```yaml
fleet:
  # the fleet stays hardened…
  masters:
    - name: master-xa-1
      hardening:
        sshd: false     # …except sshd on the box I administer by hand
```

Prefer that to switching it off fleet-wide. A fleet-only opt-out would force you to
un-harden every public-facing exit just to keep your own `sshd_config` on the
master — the opposite of what you wanted. Weigh an opt-out on an *exit* more
carefully still: its SSH port faces the same scanners the AS-blacklist feed exists
to hide from.

Two things to know before you flip it:

**`false` removes the file, it does not merely stop watching it.** wgfleet deletes
the drop-in (or jail) it installed and reloads the service, so *your* configuration
takes effect. Stopping reconciliation without removing the file would leave a
drop-in that overrides your `sshd_config` forever with nothing maintaining it —
"off" that turns nothing off. The delete is an ordinary plan action, so
`wgfleet-agent --plan` shows it before it happens.

**Leaving it on is not passive.** With `sshd: true` the planner rewrites the
drop-in and reloads sshd whenever its content drifts. If you hand-edit that file,
it is reverted within one reconcile interval. That is deliberate — a partial
overwrite once silently re-enabled password auth fleet-wide — but it means the knob,
not the editor, is how you opt out.

This knob rides the wire contract (**v6**), so agents must be at a build that
understands it. An older agent drops the field, reads "unset", and keeps hardening
the node — a fail-safe outcome, but your opt-out is ignored until it is upgraded.
Deploy the controller first; see [upgrade.md](upgrade.md).

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
| `fleet.masters[].public_udp_ports` | []int | none | UDP ports opened **to the whole internet** — the UDP sibling of the previous key. Its motivating case is a ZeroTier controller co-located with the node's own member instance, which must listen on a non-default port because the member holds 9993 |
| `fleet.masters[].whitelist` | []CIDR | mgmt scope | Additional source CIDRs the input firewall always accepts, regardless of port — the master-side sibling of `fleet.exits[].firewall.whitelist`. The management overlay is merged in automatically and cannot be dropped by this key. Prefer it over `public_tcp_ports` when a service must be reachable from a known source (e.g. a local docker bridge) rather than from the whole internet |

### `client_awg` — the client-facing AmneziaWG listener

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.masters[].client_awg.listen_port` | int | `443` | UDP port real VPN clients connect to. 443 blends with HTTPS traffic |
| `fleet.masters[].client_awg.address_pool` | CIDR | — | Address pool handed to clients. Required when `managed` is on. Must not overlap ANY other pool in the fleet — another master's client pool or any exit's `address_pool` — and the controller refuses to start on an overlap. Two nodes sharing a pool do not fail loudly: they hand the master the same tunnel address, and the second is silently misrouted per-destination |
| `fleet.masters[].client_awg.managed` | bool | `false` | Hand the interface to the agent instead of wg-easy: the controller owns the client credentials and the agent renders and raises the interface. Unset means "keep wg-easy" — taking over the client leg is always explicit |
| `fleet.masters[].client_awg.backend` | `kernel` \| `userspace` | `kernel` | What carries a **managed** interface. `userspace` is a FALLBACK, not an override: `awg-quick` reaches for the `amneziawg-go` daemon only when the kernel `ip link add` fails, so on a node that has a kernel module the module carries the interface whatever this says. Selecting `userspace` for an AmneziaWG 3.x profile is refused outright unless the node has no usable module and the daemon is installed. Ignored while unmanaged |
| `fleet.masters[].client_awg.awg3` | `off` \| `timers` \| `full` | `off` | AmneziaWG 3.x on the leg your users dial. Not a bool, because the two halves cost different things. `timers` randomises the 3.x timers only — every config already in a user's hands keeps working, and this is the half that removes the timing fingerprint a fixed keepalive leaves. `full` adds header protection, which no 2.0 peer survives: every client must re-import before it works again. Requires `managed: true` — wg-easy has no place to put these parameters, so the setting would silently do nothing. The master's kernel module must be 3.x; the agent keeps the last-good config rather than take the leg down if it is not |
| `fleet.masters[].client_awg.ipv6` | `off` \| `block` | `off` | What a client is told about IPv6. `off` says nothing, which is what the fleet has always done — and means a phone with working carrier IPv6 keeps its own v6 route, so every dual-stack destination happy eyeballs prefers (Google, Cloudflare, most CDNs) leaves the tunnel while the app reads "connected". `block` hands the client `::/0` and has the master answer forwarded IPv6 with ICMPv6 administratively-prohibited, so the device stops preferring v6 and falls back to IPv4 in milliseconds. This is NOT carrying IPv6: the data plane is IPv4-only and that is a separate project. The only thing separating `block` from a black hole is that ICMP: hand a client `::/0` over a data plane that drops IPv6 silently and pages start loading then stall, video plays then freezes, and it reads as an MTU or flaky-link fault for days. Rehearse it before turning it on. Requires `managed: true` (wg-easy cannot answer the route it would hand out) and an agent on wire v9 — the controller refuses to render the route for an older one rather than create the black hole |
| `fleet.masters[].client_awg.mtu` | int | derived | Override the client interface MTU. Unset lets the controller derive it from the hop chain, which is the right answer in almost every case |
| `fleet.masters[].client_awg.keepalive` | int or `min-max` | `25` | `PersistentKeepalive` written into generated client configs. A bare number pins one interval for everybody; a band gives each credential its own stable value, which removes the fleet-wide lockstep an observer could otherwise use to join your clients to one another — the beacon itself stays visible either way. Must remain under the shortest NAT UDP timeout on the path (commonly 30s, which is why 25 is the default) or the master loses reachability to idle clients. Range 5-120 |
| `fleet.masters[].client_awg.exclude_from_tunnel` | []CIDR | none | Networks a client must NOT send into the tunnel, so they stay on its own local network. The default `0.0.0.0/0` swallows every private range, which is why a client at home cannot reach a service on another subnet of its own LAN while connected. The controller expands "everything except these" into the explicit list `AllowedIPs` requires — the protocol has no way to say "except". Nothing is assumed about which ranges are private: you name them, and the expanded list is shown in the plan and in the Web UI. Empty leaves the default route alone. Ignored when `allowed_ips` is set |
| `fleet.masters[].client_awg.route_through_cidrs` | []CIDR | none | Networks put back into the tunnel after `exclude_from_tunnel` — a work subnet inside an excluded range, or the management overlay. Same name and meaning as the `client_vless` knob. Rejected without `exclude_from_tunnel`, where it would do nothing |
| `fleet.masters[].client_awg.dns` | list | `compose.client_dns` | Resolvers written into generated client configs |
| `fleet.masters[].client_awg.allowed_ips` | list | `compose.client_allowed_ips` | What client configs route into the tunnel. An IPv6 default route is rejected: the data plane is IPv4-only and `::/0` black-holes dual-stack clients |

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
| `fleet.masters[].mihomo.client_via_netns` | string | `auto` | Where client traffic is intercepted. `off` — on the host, as always. `auto` — inside mihomo's own network namespace once the agent has proved the namespace works, reverted automatically if the client path breaks after. A client CIDR — canary: only those sources take the new path. Any other value is refused, so a typo cannot enable a data-plane migration |
| `fleet.masters[].mihomo.netns_cidr` | string | `100.127.255.0/30` | The point-to-point link between the host and that namespace (a /30, host `.1`, namespace `.2`). RFC 6598 by default because 10/8 on this fleet is routed into the corporate tunnel |
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
| `fleet.masters[].compose.netns_holder_image` | string | built-in | Image for the container that owns mihomo's network namespace. It only has to exist and sleep, so any image already on the node will do — which is the point on a master that cannot reach a registry |

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
| `fleet.exits[].public_ip` | string | = `ssh.host` | Public IP the master dials for the AmneziaWG endpoint |
| `fleet.exits[].address_pool` | CIDR | — | Address pool for this exit's tunnel |
| `fleet.exits[].egress` | string | — | Preferred egress: `warp` or `direct` |
| `fleet.exits[].egress_fallback` | []string | none | Ordered fallbacks for censorship-adaptive failover, e.g. `[direct]`. Empty disables failover |
| `fleet.exits[].min_egress_throughput_kbytes` | int | fleet value | Per-exit throughput floor. `>0` custom, `0` inherit, negative disables the watchdog here |
| `fleet.exits[].listen_port` | int | derived `20000`–`32000` | Legacy top-level AmneziaWG port. Prefer `fleet.exits[].transports.awg.listen_port` |

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
| `fleet.exits[].firewall.as_blacklist` | bool | `false` | Drop traffic from known scanner ASNs, hiding the AmneziaWG port and SSH from active VPN scanning. Feed URLs are fleet-wide |
| `fleet.exits[].firewall.whitelist` | []CIDR | mgmt scope | Additional sources always accepted. The management overlay is merged in automatically |
| `fleet.exits[].firewall.public_tcp_ports` | []int | none | TCP ports opened to the whole internet |
| `fleet.exits[].firewall.public_udp_ports` | []int | none | UDP ports opened to the whole internet |

### Migration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `fleet.exits[].per_tunnel_key` | string | `off` | Staged migration from the master's single shared AmneziaWG identity to a per-tunnel one, **for this exit only**. Phases in order: `off` → `dual` → `switch` → `on`. Each step moves exactly one side of the tunnel, which is what makes it rollback-safe. Deliberately manual — roll one node at a time and verify between steps |

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
| `agent.mgmt_overlay_mss` | int | `0` (off) | TCP MSS clamp on the overlay interface, both directions (see `fleet.mgmt_overlay_mss`). Agent-local by design: it must not depend on the channel it protects. Valid `536`–`1460` |
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
| **wg-easy** | Client management UI and client-facing AmneziaWG server on the master | `fleet.masters[].compose.*`; state lives in its SQLite DB, which wgfleet writes directly | <https://github.com/wg-easy/wg-easy/wiki> |
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
top. Validate the manifest after any override change:

```sh
wgfleet-controller --config controller.yaml --check-config
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

To check a manifest without touching the fleet, run `--check-config`. It parses and
validates the file, prints its digest and the master/exit counts, and then makes the
checks a restart makes before it serves — the secret provider, the CA, `fleet.awg3_key`
resolved rather than merely referenced, and whether the store is one this binary can
open. It changes nothing: it does not create the store, run migrations or tighten the
manifest's permissions.

There is no "plan mode" for serving. `--plan` is a modifier for the subcommands that
have a dry run (`--provision`, `--upgrade-agent`, `--rolling-upgrade`, `--restore`,
`--import-wg-easy`); on its own, or with `--backup` or `--certs`, it is refused rather
than ignored.

## AmneziaWG 3.0

`fleet.awg3` (and its per-exit override) switches the **master↔exit** tunnels to
AmneziaWG 3.0: chacha20 header protection plus randomised rekey/keepalive timers.
The timers matter as much as the header protection — a fixed 25-second keepalive
is a timing signature that survives every payload-level obfuscation, and a censor
that classifies by traffic shape rather than by packet contents sees straight
through the rest.

It is **off by default**, and deliberately so. Every other safety default in this
file fails towards "more protection"; this one fails towards "keep speaking what
the nodes already speak", because enabling it changes the wire format of a live
tunnel.

**It governs the master↔exit tunnels only.** The client leg has its own switch —
`masters[].client_awg.awg3` — with three settings rather than a bool, because its
two halves cost different things: `timers` keeps every config already in a user's
hands working, `full` adds header protection and requires every client to
re-import. See that key, and `fleet.awg3_key`, which both of them need.

### Before you turn it on

Two different gates, in two different places — a premature flip degrades to "stays
on 2.0" rather than to a dead tunnel, but only the first is the controller's.

**The controller's gate: BOTH ends of the tunnel speak wire v7 or later.** Not just
the exit — the master too. An older agent drops the 3.0 fields and brings its
interface up as 2.0, while the other end, rendered from the same decision, emits
`version: 3`; the two disagree about the wire format and never handshake. The
master is the end people forget, and it lags its exits as a matter of routine:
the rolling upgrade walks the exits and never touches masters. Enabling
`fleet.awg3` while the master is behind would put every exit on 3.x and leave the
master's mihomo on 2.0 — the whole data plane, not one node. So the controller
checks the master's wire version as well, and renders 2.0 for that tunnel until
both ends are ready.

**The agent's gate: the node's own kernel module is 3.x.** The controller cannot
check this — a module generation is a local fact that never travels on the wire —
so it is enforced on the node, by the agent, on every pass. AmneziaWG 3.0 changed
the netlink attribute layout, so the module and `amneziawg-tools` must be on the
same generation; a mismatch fails `awg setconf` outright with `attribute type 14
has an invalid length` and the interface never comes up. Rather than let that
happen, the agent refuses the 3.x config and keeps the previous good one running.
This gate fires on **any** 3.x field, timers included — so it also gates
`client_awg.awg3: timers` on the master's module, not only header protection.

Check what a node actually runs before flipping the key — and check the master,
not only the exits:

```sh
modinfo amneziawg | grep ^version   # kernel module generation
awg --version                       # userspace tools generation
```

`tools/check-awg3-status.sh` (in the source repository) tracks the upstream readiness gates, including a
watch-list of open defects in the kernel module itself.

[wg-easy#2728]: https://github.com/wg-easy/wg-easy/issues/2728
