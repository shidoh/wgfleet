# Fleet manifest — annotated reference

Two YAML files: the **controller config** (`controller.yaml`, which embeds the
**fleet manifest**) and the per-node **agent config** (`agent.yaml`). Flags
override file values; `WGFLEET_`-prefixed env vars override too (e.g.
`WGFLEET_CONTROLLER_LISTEN=...` -> `controller.listen`) — but only for keys whose
every path segment is a single word. Anything under `masters[]` / `exits[]` is
unreachable that way. See [configuration.md](configuration.md) §1.

This page is the *annotated example*. For the **exhaustive, per-key** list (type,
default, meaning) see [configuration.md](configuration.md).

For a specific outcome — RU sites direct, everything else abroad, ads filtered on
DNS — start from [recipes/ru-split-tunnel-dns-filter.md](recipes/ru-split-tunnel-dns-filter.md)
and its ready-to-adapt [controller-split-ru.yaml](../deploy/examples/controller-split-ru.yaml).

---

## `controller.yaml`

```yaml
controller:
  listen:  "10.20.25.254:8443"    # gRPC/mTLS API agents dial: the mgmt/ZT address;
                                   # baked into agent configs and the server cert SAN
  advertise: "10.20.25.254:8443"  # address agents dial when it differs from listen (NAT/gateway);
                                   # seeds an extra SAN on the server cert
  webui:   "10.20.25.254:9000"    # admin dashboard (provision/decommission/delete/backup); mgmt/ZT only (empty disables)
  metrics: "10.20.25.254:9300"    # Prometheus /metrics; mgmt/ZT only (empty disables)
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
  hardening:                                 # host hardening — FLEET DEFAULT; each node can override
    sshd: true                               #   default true; false REMOVES the drop-in and reloads sshd
    fail2ban: true                           #   default true; false REMOVES the jail. Needs wire v6.
  awg3: false                                # AmneziaWG 3.0 on the master↔exit tunnels — FLEET DEFAULT,
                                             #   each exit can override. Omitted ⇒ OFF. Clients have
                                             #   their own knob (masters[].client_awg.awg3). Needs
                                             #   wire v7 on BOTH ends and a 3.x kernel module; if
                                             #   either gate fails, that exit stays on 2.0.

  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254              # ZeroTier address
      public_ip: 203.0.113.10               # endpoint clients dial, written into every client
                                            # config. May be a DNS name. Does NOT fall back to
                                            # ssh.host (that is often the mgmt overlay).
      client_awg:
        managed: true                       # the AGENT owns the client interface; credentials
                                            # live in the controller's store and are managed in
                                            # the console. Omit ⇒ wg-easy (legacy path).
        listen_port: 443                    # UDP
        address_pool: 10.80.0.0/24          # client WG subnet
        # ipv6: block                       # hand clients ::/0 AND refuse forwarded v6 with
                                            # ICMPv6, so dual-stack devices fall back to IPv4
        # mtu: 1360                         # client interface MTU; leave unset to derive
        # keepalive: 25                     # one number, or a min-max band per credential
        # backend: kernel                   # kernel (default) | userspace
        # allowed_ips: [0.0.0.0/0]          # what the client routes INTO the tunnel
        # exclude_from_tunnel: [192.168.0.0/16]   # carved back OUT of allowed_ips
        # awg3: timers                      # off (default) | timers | full. `full` requires
                                            # every client config to be reissued. Needs fleet.awg3_key.
      client_vless:                         # DPI-resistant client transport, alongside client_awg
        enabled: true                       # omit the block to leave it off
        # listen_port: 0 ⇒ per-master high port in [40000,60000]
        # empty_sni: true (default) — no-SNI ClientHello
        route_through_cidrs:                # internal nets clients route THROUGH the tunnel
          - 10.20.0.0/16                    # e.g. the ZeroTier mgmt overlay
      routing:
        direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
        direct_geo:   [RU]                  # GEOSITE/GEOIP → DIRECT
        balance:      url-test              # round-robin | consistent-hashing (alias: health) | sticky-sessions | url-test | fallback
      hardening:                            # per-node override of fleet.hardening above
        sshd: false                         #   omitted key ⇒ inherit fleet; explicit true beats a
                                            #   fleet-wide false
      mihomo:                               # master data-plane tuning + custom-config hooks
        health_interval: 30s                # how often mihomo health-checks exits (default 60s)
        sniffer_skip: ["+.themoviedb.org", "+.cloudfront.net"]  # CDNs that break under sniffing
        dashboard_url: "https://mirror.example/zashboard"  # override mihomo web-dashboard URL (empty ⇒ default GitHub)
        dashboard_disabled: false           # set true to disable the web dashboard entirely
        overrides:                          # deep-merged into the rendered mihomo config.yaml
          log-level: info
          # do not override dns.nameserver: with dns_filter on, the rendered config already resolves via the master's blocky
        extra_files:                        # provisioned alongside config.yaml (mihomo include files)
          - path: direct-domains.yaml
            content: |
              payload:
                - mycompany.example
      compose:                              # master container stack; every image+tag is pin-able
        wg_easy_image: ghcr.io/wg-easy/wg-easy   # repository (default …:15)
        wg_easy_tag:   "15"                 # explicit tag overrides any tag in the image
        mihomo_image:  metacubex/mihomo
        mihomo_tag:    "v1.19.32"           # pin a version (NOT :latest, NOT Alpha). Default v1.19.32.
      ssh:                                  # bootstrap target
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
      egress_fallback: [direct]             # ordered fallbacks for censorship-adaptive failover
      warp_mtu: 0                           # WARP interface MTU; 0 ⇒ default 1380 + auto-probe (only lowers)
      address_pool: 10.81.0.0/24
      mgmt_addr: 10.20.0.5                 # ZeroTier address (admin/metrics/DNS bind)
      # public_ip: 198.51.100.7             # THE ENDPOINT THE MASTER DIALS. Unset ⇒ ssh.host,
                                            # so repointing ssh at the overlay moves the tunnel
                                            # too. Set it whenever ssh and the tunnel should go
                                            # different ways. Also seeds a /32 DIRECT route.
                                            # Wins over the address stored at provisioning: edit,
                                            # restart the controller, and the endpoint moves.
                                            # Must be an IP literal.
      transports:                           # master↔exit transport(s); omit ⇒ AWG-only
        awg: { enabled: true, listen_port: 0 }       # primary transport. WG UDP port; 0 ⇒ stable-random derived
        reality:                            # fallback transport (VLESS+REALITY+XHTTP, xray) for when AWG is DPI-blocked
          enabled: true
          listen_port: 443                  # default 443; must differ from the AWG port
          dest_domain: www.python.org       # camouflage dest — MUST support X25519MLKEM768 (verify `xray tls ping`); not Cloudflare-fronted
          dest_port: 443
          sni: www.python.org               # empty ⇒ = dest_domain
          mode: xhttp                       # xhttp (default) | vision (TCP + xtls-rprx-vision)
          mux: true                         # XMUX connection reuse (xhttp only)
          fingerprint: chrome               # uTLS fingerprint: chrome | firefox | safari (none/random rejected)
          empty_sni: false                  # true ⇒ no-SNI ClientHello
          allow_ipv6: false                 # false ⇒ pin xray resolution to IPv4 (IPv4-only data plane)
          # image: ghcr.io/xtls/xray-core:26.6.22   # unset ⇒ pinned default
      active_transport: awg                 # awg (default/primary) | reality-xhttp (fallback); flip live in the Web UI
      dns_filter: true                      # blocky (Docker); binds loopback + mgmt_addr (+ the lifeline
                                            #   pool gateway on an exit that carries one)
      dns:                                  # optional blocky tuning (ZT-only binds enforced regardless)
        image: spx01/blocky                 # repository …
        tag:   v0.35.0                      # … + tag (both pin-able; default spx01/blocky:v0.35.0)
        allowlist: ["*.example.net"]        # never-blocked domains (platform infra auto-added)
        overrides:                          # raw blocky YAML, deep-merged (denylists, conditional, caching)
          blocking:
            denylists:
              ads: [https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt]
            clientGroupsBlock:
              default: [ads]
      lifeline:                             # reserve client interface awgl0: every issued
        listen_port: 41827                  #   credential gets a reserve profile against this exit
        address_pool: 10.98.77.0/24         #   at least as large as the master's client pool; no overlaps
        egress: direct                      # direct (default) | warp (WARP must be in this exit's chain)
        # dns: [10.98.77.1]                 # required when dns_filter is off (the master's resolvers are gone)
        # allowed_ips: [0.0.0.0/0]          # default; a split list here is the one shape wg-quick cannot install
      firewall:
        as_blacklist: true
        whitelist: [10.20.0.0/16]
        # public_tcp_ports: [80]           # TCP ports opened to the WORLD (no interface scope);
                                            #   keep to genuinely public services
        # public_udp_ports: [9994]         # UDP ports opened to the WORLD, e.g. a second
                                            #   ZeroTier instance on a non-default port
      ssh:
        host: 198.51.100.7
        port: 22
        user: root
        key_path: /etc/wgfleet/bootstrap_ed25519
        # host_key: "ssh-ed25519 AA..."
```

Every dockerized component (wg-easy, mihomo, blocky) exposes an `image` +
`tag` pair so both can be pinned. An explicit `tag` overrides any tag embedded in
`image`; either may be omitted to inherit the component's default.

### Several masters

One master needs neither key below. From the second master on:

```yaml
fleet:
  interface_anchor: master-xa-1        # = the name of the master in slot 0; never change it
  mgmt_subnet: 10.20.0.0/16            # set before adding a master
  master_dns:                          # resolver settings of every master; replaces masters[].dns
    allowlist: ["*.example.net"]
    overrides:
      conditional:
        mapping:
          corp.example: 10.20.0.53
  masters:
    - name: master-xa-1
      slot: 0
      public_ip: 203.0.113.10
    - name: master-eu-1
      slot: 1
      public_ip: 198.51.100.20
```

| Key | Level | Type | Default | Meaning |
|---|---|---|---|---|
| `interface_anchor` | fleet | string | name of the master in slot 0 | Label every exit's interface parameters are derived from. Required with two or more masters, and when no master holds slot 0. Not `clients` or `lifeline`; no whitespace, no `\|`. Never change it on a running fleet |
| `master_dns` | fleet | map | none | Resolver settings (`image`, `allowlist`, `upstreams`, `ports`, `overrides`, `extra_files`) rendered on every master with `dns_filter: true`. Same keys as `masters[].dns` |
| `slot` | master | int 0-63 | `0` | The master's addresses inside every exit pool. Unique per master. Never reuse a slot for a different master while the old one's keys are still on exits |

| Rule | Detail |
|---|---|
| Exit `address_pool` size | Must hold host `3 + 2 × (highest slot)` |
| Reserved node names | `clients` and `lifeline` |
| `masters[].dns` | Rejected with two or more masters, and alongside `fleet.master_dns`. Move the block to `fleet.master_dns` |
| Two masters with one WireGuard key | The master that registers the key second is refused at registration. With both keys already stored, the exits peer the earlier master in manifest order; the other gets no peer and no AmneziaWG tunnel. A master built from a copy of another's disk needs a new key |
| Direct rules per exit | `direct_cidrs` of the master in slot 0 + management CIDRs + one per other master. Over 80: a warning from `--check-config` and at startup; an exit with WARP egress cannot apply its routing |
| `transports.awg.exit_initiated` | Needs a public IPv4 on every master |
| `transports.awg.master_port` | Applies to the master in slot 0 |
| Master in slot 0 | The one whose clients a lifeline carries and whose `routing.direct_cidrs` exits inherit |
| `mgmt_subnet` unset | Adding or removing any node, a master included, changes the direct routes and the firewall whitelist on every exit |
| Exit on an older agent | Serves the master in slot 0 only |

Procedures: [operations.md](operations.md#several-masters).

## `agent.yaml`

The agent only needs its identity and where the controller is. Everything else
comes from the spec it pulls.

```yaml
agent:
  role: exit                       # master | exit
  controller: "10.20.25.254:8443"  # the controller's mgmt/ZT IP — the one its certificate SAN covers
  node_id: "exit-de-1"
  mgmt_addr: "10.20.0.5"          # mgmt/ZT address; the agent binds /metrics to
                                   #   <mgmt_addr>:9301 by default (no flag needed)
  reconcile_interval: 30s          # default 30s; set fleet-wide via fleet.reconcile_interval
  identity:
    cert: "/etc/wgfleet/node.crt"  # issued at bootstrap
    key:  "/etc/wgfleet/node.key"  # generated on-node, 0600, never leaves the box
    ca:   "/etc/wgfleet/ca.crt"    # CA cert used to verify the controller
```

## Secrets

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
the CA cert still reads from a `file://` path. Setup steps are in the `secrets-sops.md` guide.

AmneziaWG private keys are generated and persisted **on the node** (0600) and are
never sent to the controller. `--state-dir <dir>` relocates them (and all managed
files) for non-root/dev runs.
