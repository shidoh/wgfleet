# Fleet manifest — annotated reference

Two YAML files: the **controller config** (`controller.yaml`, which embeds the
**fleet manifest**) and the per-node **agent config** (`agent.yaml`). Flags
override file values; `WGFLEET_`-prefixed env vars override too (e.g.
`WGFLEET_CONTROLLER_LISTEN=...` -> `controller.listen`).

This page is the *annotated example* — every block with the reasoning next to it.
For the **exhaustive, per-key** list (type, default, meaning) see
[configuration.md](configuration.md); a test fails the build if a key exists in
code but is missing there, so it cannot drift.

For a specific outcome — RU sites direct, everything else abroad, ads filtered on
DNS — start from [recipes/ru-split-tunnel-dns-filter.md](recipes/ru-split-tunnel-dns-filter.md)
and its ready-to-adapt [controller-split-ru.yaml](../deploy/examples/controller-split-ru.yaml).

---

## `controller.yaml`

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
  hardening:                                 # host hardening — FLEET DEFAULT; each master/exit
    sshd: true                               #   can override it (see master-xa-1 below).
    fail2ban: true                           # BOTH DEFAULT TO true — omit the block for the
                                             #   hardened defaults. false ⇒ the agent REMOVES the
                                             #   file it installed and reloads the service, handing
                                             #   the subsystem back to you (leaving it in place
                                             #   would shadow your own config with nothing
                                             #   maintaining it). Needs wire v6.

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
      hardening:                            # per-node override of fleet.hardening above
        sshd: false                         #   omitted key ⇒ inherit fleet; explicit true beats a
                                            #   fleet-wide false. Prefer this to switching the fleet
                                            #   off: relaxing the whole fleet to suit the one box you
                                            #   hand-tune un-hardens every public-facing exit too.
      mihomo:                               # master data-plane tuning + custom-config hooks
        health_interval: 30s                # how often mihomo health-checks exits to route around dead ones (default 60s)
        sniffer_skip: ["+.themoviedb.org", "+.cloudfront.net"]  # CDNs that break under sniffing
        dashboard_url: "https://mirror.example/zashboard"  # override mihomo web-dashboard URL (empty ⇒ default GitHub)
        dashboard_disabled: false           # set true to disable the web dashboard entirely
        overrides:                          # deep-merged into the rendered mihomo config.yaml
          log-level: info
          # Resolve via the master's blocky so private/internal domains resolve for proxied
          # clients (the sniffer rewrites dst to the SNI domain and mihomo re-resolves it; public
          # DNS doesn't know blocky's split → ERR_CONNECTION_CLOSED, an earlier finding). Needs dns_filter.
          # dns: { nameserver: [127.0.0.1:53] }
        extra_files:                        # provisioned alongside config.yaml (mihomo include files)
          - path: direct-domains.yaml
            content: |
              payload:
                - mycompany.example
      compose:                              # master container stack; every image+tag is pin-able
        wg_easy_image: ghcr.io/wg-easy/wg-easy   # repository (default …:15)
        wg_easy_tag:   "15"                 # explicit tag overrides any tag in the image
        mihomo_image:  metacubex/mihomo
        mihomo_tag:    "v1.19.30"           # pin a version (NOT :latest, NOT Alpha — a moving
                                            #   tag defeats the pin) (#8). Default is v1.19.30.
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
        # public_tcp_ports: [80]           # TCP ports opened to the WORLD (no interface scope),
                                            #   e.g. a decoy web listener on 80 — keep to genuinely
                                            #   public services (bypasses the default drop policy)
        # public_udp_ports: [9994]         # UDP ports opened to the WORLD — the UDP sibling
                                            #   of public_tcp_ports, e.g. a ZeroTier controller
                                            #   on a non-default port (9993 is held by the
                                            #   node's own member instance)
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

## `agent.yaml`

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
the CA cert still reads from a `file://` path. (See `docs/secrets-sops.md` for setup.)

AmneziaWG private keys are generated and persisted **on the node** (0600) and are
never sent to the controller. `--state-dir <dir>` relocates them (and all managed
files) for non-root/dev runs.

