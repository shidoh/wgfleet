# Recipe: RU / non-RU split tunnel + DNS filtering

**Goal.** Stand up a fleet where your devices reach **Russian** sites directly
(local IP, no foreign hop, full speed) while **everything else** leaves through
an exit abroad — and where ads/trackers are filtered at the DNS layer for every
client. This is the most common wgfleet setup; this page shows the exact keys
that produce it, the hardening that makes it survive real RU network conditions,
and how to verify each piece.

It assumes you have already read [INSTALL.md](../INSTALL.md) or
[colocated-controller-master.md](../colocated-controller-master.md) and can
bring a master + one exit to `Ready`. This recipe only changes **what goes in
`controller.yaml`** — the bring-up steps are identical.

Ready-to-adapt config: [`deploy/examples/controller-split-ru.yaml`](../../deploy/examples/controller-split-ru.yaml)
(also copied to `/etc/wgfleet/examples/` by `install.sh`).

The doc is layered:

1. **[The mental model](#the-mental-model)** — how the split is decided.
2. **[Minimum working config](#minimum-working-config)** — copy-paste, and it works.
3. **[Hardening for RU masters](#hardening-for-ru-masters)** — the parts that make
   it *keep* working: fresh geo data, resilient blocklist loading, private-zone
   DNS, sniffer exceptions. These come straight from a production fleet.
4. **[Apply & verify](#apply-it)**, then **[adjustments](#common-adjustments)**.

---

## The mental model

```
 your phone/laptop ──AmneziaWG──► MASTER (near you) ──AmneziaWG──► EXIT (abroad) ──► internet
                                     │
                                     └─ RU sites/IPs egress DIRECTLY from the master
```

The master runs mihomo, which decides **per connection** whether traffic goes
out locally (DIRECT) or through an exit. It evaluates rules top-to-bottom:

| Order | Rule (rendered by mihomo) | Source | Effect |
|------:|---------------------------|--------|--------|
| 1 | `IP-CIDR,<redir-bind>,REJECT` | auto-injected guard | never proxy mihomo's own port |
| 2 | `RULE-SET,direct-networks,DIRECT` | `routing.direct_cidrs` (+ `fleet.mgmt_subnet`) | private/LAN nets never enter the tunnel |
| 3 | `GEOSITE,category-ru,DIRECT` | `routing.direct_geo: [RU]` | `.ru` and known-Russian **domains** stay local |
| 3 | `GEOIP,RU,DIRECT,no-resolve` | `routing.direct_geo: [RU]` | Russian **IP ranges** stay local |
| 4 | `MATCH,wg-best` | (always last) | **everything else** → the exit(s) abroad |

So `direct_geo: [RU]` *is* the split. Nothing else is needed to divide RU from
non-RU. Add regions to keep more local — `direct_geo: [RU, BY]` keeps Belarus
local too. (Geo codes are the MetaCubeX geosite/geoip categories.)

## The DNS filter

Two independent layers, both `blocky`:

- **Master `dns_filter: true`** — the master becomes your devices' single DNS.
  A blocked domain simply doesn't resolve, so the client never even opens the
  connection. This is what filters ads/trackers for end users. It forwards
  everything it doesn't block to the exits' resolvers, and local zones to your
  internal DNS.
- **Exit `dns_filter: true`** — a clean upstream resolver (DoT) that the master
  forwards to. Required so the master's filter has an upstream to point at;
  filtering here too adds defense in depth.

Denylists and the allowlist live under `dns.overrides.blocking` /
`dns.allowlist`. The allowlist always wins — use it the moment a list breaks a
site you need (banking, a government portal, etc.).

---

## Minimum working config

These are the keys that create the behavior; everything else in the example is
ordinary fleet setup.

```yaml
fleet:
  masters:
    - name: master-1
      routing:
        direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
        direct_geo:   [RU]                 # ← RU stays local, the rest goes abroad
        balance:      consistent-hashing   # ← each destination keeps one exit / egress country
      dns_filter: true                     # ← master = clients' filtering DNS
      dns:
        allowlist: ["*.example.ru"]     # your own never-block domains (wins over denylists)
        overrides:
          blocking:
            denylists:
              ads:      [https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt]
              trackers: [https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.apple.txt]
            clientGroupsBlock: { default: [ads, trackers] }
          caching: { minTime: 5m, prefetching: true }
  exits:
    - name: exit-1
      dns_filter: true                     # ← clean upstream resolver for the master
      dns:
        overrides:
          blocking:
            denylists:
              ads: [https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt]
            clientGroupsBlock: { default: [ads] }
```

### Denylist groups

Split lists into named groups so you can enable/tune them independently. A
practical production set (all [hagezi](https://github.com/hagezi/dns-blocklists)):

```yaml
denylists:
  ads:
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads.txt
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock.txt
  trackers:
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.amazon.txt
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.apple.txt
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.tiktok.extended.txt
    - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.winoffice.txt
clientGroupsBlock:
  default: [ads, trackers]
```

`native.*` lists strip the telemetry that Amazon/Apple/Microsoft/TikTok devices
phone home — often the single biggest source of background noise on a phone.

### Why `consistent-hashing`

With multiple exits, `consistent-hashing` sends the same destination through the
same exit every time, so a site keeps one egress IP and country (no captchas
from a country that flip-flops mid-session), while different destinations spread
across all exits. The alternatives (`round-robin`, `sticky-sessions`,
`fallback`, `url-test`) and their trade-offs are documented in
[`deploy/examples/controller.yaml`](../../deploy/examples/controller.yaml).
`url-test` in particular is a trap here — a config reload recreates the proxy
group and the first pick after a reset ignores `tolerance`, so the exit (and
your apparent country) flaps on events unrelated to latency.

---

## Hardening for RU masters

The minimum config works, but on a real Russian network three things bite. Each
fix below is drawn from a production fleet and is generic — no internal detail.

### 1. Keep RU geo data fresh (important)

`direct_geo: [RU]` emits `GEOSITE`/`GEOIP` rules that need the geoip/geosite
`.dat` databases. wgfleet configures mihomo to auto-update them — **but mihomo's
`.dat` updater has no DIRECT detour**, so on an RU master it tries to fetch them
*through the exit* (or fails at startup before the exit is even up): TLS
handshake timeouts and error spam, and stale geo data drifting your split.

The robust fix is to route RU geo via **`.mrs` rule-providers**, which *do*
honour `proxy: DIRECT`, and turn the `.dat` auto-update off. Put this under the
master's `mihomo.overrides`:

```yaml
mihomo:
  overrides:
    geo-auto-update: false          # silence the detour-less .dat updater
    rule-providers:
      geoip-ru:
        type: http
        behavior: ipcidr
        format: mrs
        proxy: DIRECT               # ← fetched over the master's direct path (<1s to GitHub)
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.mrs"
        path: ./rules/geoip-ru.mrs
        interval: 86400
      geosite-ru:
        type: http
        behavior: domain
        format: mrs
        proxy: DIRECT
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.mrs"
        path: ./rules/geosite-ru.mrs
        interval: 86400
    # Overriding `rules` REPLACES the rendered list — mihomo's list-merge is replace,
    # not append. The self-dial REJECT guard is re-injected as the first rule for you.
    rules:
      - RULE-SET,direct-networks,DIRECT
      - RULE-SET,geosite-ru,DIRECT
      - RULE-SET,geoip-ru,DIRECT,no-resolve
      - MATCH,wg-best
```

> If the master's own network can't reach GitHub directly either, point the two
> `url:`s at a mirror you *can* reach directly. The whole point is a source the
> master fetches without going through the exit.

### 2. Serve DNS immediately, load blocklists in the background

If blocky tries to download blocklists synchronously at startup and GitHub is
slow/blocked from RU, DNS resolution itself stalls until the download
succeeds — the whole fleet feels down. `loading.strategy: fast` serves DNS
right away and refreshes lists in the background; blocking just stays empty
until a refresh lands. Put it under the master's `dns.overrides.blocking`:

```yaml
blocking:
  loading:
    strategy: fast
    refreshPeriod: 24h
    downloads: { timeout: 30s, attempts: 5, cooldown: 30s }
  denylists: { ... }
  clientGroupsBlock: { ... }
```

### 3. Resolve internal / private domains for proxied clients

With sniffing on, mihomo rewrites a connection's destination to its SNI and
**re-resolves** it. Public DNS doesn't know your internal zones, so private
domains fail with `ERR_CONNECTION_CLOSED`. mihomo already points at the master's own
blocky (which knows the split) — you only need to map the zones:

> ⚠️ **No longer needed (2026-08-28), and now harmful.** The agent supplies the
> resolver list and the renderer sets the fleet resolver *exclusively* — a public
> fallback beside it was a concurrent pool, not a fallback, so mihomo raced the two
> and leaked queries. Overriding `dns.nameserver` REPLACES the rendered list, so
> setting it by hand re-creates the very problem it used to solve. Leave it out.

```yaml
dns:
  overrides:
    conditional:
      fallbackUpstream: true
      mapping:
        corp.internal: 10.0.0.53             # your internal DNS, reachable over the mgmt overlay
        corp.lan:      10.0.0.53
```

### 4. Don't sniff CDNs / metadata services

Sniffing rewrites a connection's destination to its SNI; a handful of
SNI-fronted CDNs and metadata APIs break when you do. Exempt them:

```yaml
mihomo:
  sniffer_skip:
    - "+.cloudfront.net"      # AWS CloudFront
    - "+.akamaized.net"       # Akamai
    - "+.fastly.net"          # Fastly
    # + any SNI-fronted API/metadata service whose first requests break under sniffing
```

### 5. Lock down the mihomo API

The mihomo Clash API / dashboard binds the mgmt overlay, but anyone on that
overlay can otherwise drive mihomo. Set a strong secret:

```yaml
mihomo:
  overrides:
    secret: "<generate-a-long-random-string>"   # NEVER commit a real value
```

---

## Apply it

Same flow as any config change — no special steps:

```sh
# edit /etc/wgfleet/controller.yaml (or start from the example), then:
wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
systemctl restart wgfleet-controller
```

**That is the whole change.** The agents pick it up on their next reconcile
(default 30s) and hot-reload mihomo/blocky — routing and denylist tweaks never
need a re-provision.

Provisioning is for a node that is not in the fleet yet, and it is exits only:

```sh
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1 --plan
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1
```

The co-located master is not SSH-provisioned — it is installed by `install.sh` and
upgraded with `./deploy-master.sh`, so it has no `ssh:` block to provision through.

## Verify

Connect a device (see QUICKSTART step 8), then:

**1. Non-RU traffic exits abroad.** Open an IP-geolocation site (e.g.
`https://ipinfo.io`). It should show the **exit's** country, not yours.

**2. RU traffic stays local.** Check a Russian service's view of your IP — a
`.ru` "what's my IP" page, or your bank's page — it should show **your local /
master** IP, not the exit's. On the master you can watch the decision live:

```sh
# on the master — mihomo logs the chosen rule per connection
docker logs -f mihomo 2>&1 | grep -Ei 'DIRECT|wg-best'
# a .ru destination should log a DIRECT match; a foreign one → wg-best
```

**3. RU geo providers loaded** (if you applied the hardening):

```sh
docker logs mihomo 2>&1 | grep -Ei 'geoip-ru|geosite-ru|provider'   # fetched, no proxy errors
```

**4. DNS filtering works.** From the connected device:

```sh
nslookup doubleclick.net      # blocked → NXDOMAIN / NXDOMAIN
nslookup example.com          # resolves
```

Or on the master, confirm blocky is answering and counting blocks:

```sh
docker logs blocky 2>&1 | grep -i blocked | tail
```

**5. An allowlisted site is never blocked.** Anything under `dns.allowlist`
resolves normally even if a denylist would otherwise catch it.

## Common adjustments

| Want | Change |
|------|--------|
| Keep more countries local | `direct_geo: [RU, BY, KZ]` (add matching `.mrs` providers if you use the hardened geo) |
| A specific domain always local | add it to `mihomo.extra_files` `direct-domains.yaml` + a `RULE-SET,direct-domains,DIRECT` rule (see the example config) |
| Force a specific IP through the exit | `IP-CIDR,<ip>/32,wg-best,no-resolve` in the `rules` override (e.g. an app that must not be geo-DIRECTed) |
| Stricter / lighter filtering | swap the hagezi list (`pro.txt` ↔ `light.txt` / `pro.plus.txt`), or add/remove groups |
| A site a blocklist breaks | add it to `dns.allowlist` (wins over every denylist) |
| Keep a slow exit as a warm spare | `routing.reserve_exits: [exit-slow]` — used only when every primary exit is down |
| More exits sharing the load | add another `exits[]` entry (unique `name` + `address_pool`); `consistent-hashing` spreads across all of them |

## Gotchas

- **Use the AmneziaWG app, not plain WireGuard** on clients — the obfuscation is
  AmneziaWG-specific.
- **The master must reach GitHub (or a mirror) *directly*** for both geo data and
  blocklists. That's the whole reason for `proxy: DIRECT` providers and
  `loading: fast` — see the hardening section. Without it, geo drifts and
  blocklists load through the exit or not at all.
- **`dns_filter` on the master requires at least one exit with `dns_filter: true`**
  as its upstream; the example sets both.
- **Filtering is client-facing only when the master is the client DNS**, which
  `dns_filter: true` arranges automatically (it binds the client-pool gateway).
  Don't override clients' DNS to a public resolver, or you bypass the filter.
- **Overriding `rules` or a list REPLACES it** (mihomo merges lists by replace).
  Include every rule you still want — the example's hardened block is complete.
