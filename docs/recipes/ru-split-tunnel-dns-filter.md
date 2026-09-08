# Recipe: RU / non-RU split tunnel + DNS filtering

**Goal.** Devices reach **Russian** sites directly (local IP, full speed),
**everything else** leaves through an exit abroad, and ads/trackers are filtered
at the DNS layer for every client.

Prerequisite: a master + one exit at `Ready` ([Quickstart](../QUICKSTART.md) or
[colocated-controller-master.md](../colocated-controller-master.md)). This recipe
only changes **what goes in `controller.yaml`**.

Ready-to-adapt config: [`deploy/examples/controller-split-ru.yaml`](../../deploy/examples/controller-split-ru.yaml)
(also copied to `/etc/wgfleet/examples/` by `install.sh`).

1. **[The mental model](#the-mental-model)** — how the split is decided.
2. **[Minimum working config](#minimum-working-config)** — copy-paste, and it works.
3. **[Hardening for RU masters](#hardening-for-ru-masters)** — fresh geo data,
   resilient blocklist loading, private-zone DNS, sniffer exceptions.
4. **[Apply & verify](#apply-it)**, then **[adjustments](#common-adjustments)**.

---

## The mental model

```
 your phone/laptop ──AmneziaWG──► MASTER (near you) ──AmneziaWG──► EXIT (abroad) ──► internet
                                     │
                                     └─ RU sites/IPs egress DIRECTLY from the master
```

The master's mihomo decides **per connection**, top-to-bottom:

| Order | Rule (rendered by mihomo) | Source | Effect |
|------:|---------------------------|--------|--------|
| 1 | `IP-CIDR,<redir-bind>,REJECT` | auto-injected guard | never proxy mihomo's own port |
| 2 | `RULE-SET,direct-networks,DIRECT` | `routing.direct_cidrs` (+ `fleet.mgmt_subnet`) | private/LAN nets never enter the tunnel |
| 3 | `GEOSITE,category-ru,DIRECT` | `routing.direct_geo: [RU]` | `.ru` and known-Russian **domains** stay local |
| 3 | `GEOIP,RU,DIRECT,no-resolve` | `routing.direct_geo: [RU]` | Russian **IP ranges** stay local |
| 4 | `MATCH,wg-best` | (always last) | **everything else** → the exit(s) abroad |

`direct_geo: [RU]` *is* the split. Add regions to keep more local:
`direct_geo: [RU, BY]`. Geo codes are the MetaCubeX geosite/geoip categories.

## The DNS filter

Two layers, both `blocky`:

- **Master `dns_filter: true`** — the master becomes your devices' single DNS; a
  blocked domain does not resolve. Unblocked queries go to the exits' resolvers,
  local zones to your internal DNS.
- **Exit `dns_filter: true`** — the clean upstream resolver (DoT) the master
  forwards to. Required.

Denylists and the allowlist live under `dns.overrides.blocking` /
`dns.allowlist`. The allowlist always wins.

---

## Minimum working config

The keys that create the behaviour:

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

Named groups can be enabled/tuned independently. A practical set (all
[hagezi](https://github.com/hagezi/dns-blocklists)):

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

`native.*` lists strip vendor telemetry from Amazon/Apple/Microsoft/TikTok devices.

### Balance mode

`consistent-hashing` keeps one exit (one egress IP and country) per destination
while spreading destinations across all exits. The other modes (`round-robin`,
`sticky-sessions`, `fallback`, `url-test`) are documented in
[`deploy/examples/controller.yaml`](../../deploy/examples/controller.yaml).
Avoid `url-test` here: a config reload recreates the proxy group and the first
pick ignores `tolerance`, so the exit flaps on events unrelated to latency.

---

## Hardening for RU masters

### 1. Keep RU geo data fresh (important)

`direct_geo: [RU]` emits `GEOSITE`/`GEOIP` rules backed by `.dat` databases whose
updater has no DIRECT detour: on an RU master it fetches them *through the exit*
(or fails at startup before the exit is up), leaving stale geo data.

Serve RU geo via **`.mrs` rule-providers**, which honour `proxy: DIRECT`, and turn
the `.dat` auto-update off. Under the master's `mihomo.overrides`:

```yaml
mihomo:
  overrides:
    geo-auto-update: false          # silence the detour-less .dat updater
    rule-providers:
      geoip-ru:
        type: http
        behavior: ipcidr
        format: mrs
        proxy: DIRECT               # ← fetched over the master's direct path
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

> If the master cannot reach GitHub directly, point the two `url:`s at a mirror
> it can reach without the exit.

### 2. Serve DNS immediately, load blocklists in the background

With synchronous blocklist loading, DNS itself stalls until the download
succeeds. `loading.strategy: fast` serves DNS right away and refreshes lists in
the background (blocking stays empty until a refresh lands). Under the master's
`dns.overrides.blocking`:

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
**re-resolves** it, so private domains fail with `ERR_CONNECTION_CLOSED` unless
the master's blocky knows the zones. Map them:

```yaml
dns:
  overrides:
    conditional:
      fallbackUpstream: true
      mapping:
        corp.internal: 10.0.0.53             # your internal DNS, reachable over the mgmt overlay
        corp.lan:      10.0.0.53
```

> **Do not override `dns.nameserver`.** It replaces the rendered resolver list,
> and a public resolver beside the fleet one is a concurrent pool that races and
> leaks queries.

### 4. Don't sniff CDNs / metadata services

Some SNI-fronted CDNs and metadata APIs break under sniffing. Exempt them:

```yaml
mihomo:
  sniffer_skip:
    - "+.cloudfront.net"      # AWS CloudFront
    - "+.akamaized.net"       # Akamai
    - "+.fastly.net"          # Fastly
    # + any SNI-fronted API/metadata service whose first requests break under sniffing
```

### 5. Lock down the mihomo API

The mihomo Clash API / dashboard binds the mgmt overlay; without a secret anyone
on that overlay can drive mihomo:

```yaml
mihomo:
  overrides:
    secret: "<generate-a-long-random-string>"   # NEVER commit a real value
```

---

## Apply it

Same flow as any config change:

```sh
# edit /etc/wgfleet/controller.yaml (or start from the example), then:
wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
systemctl restart wgfleet-controller
```

Agents pick it up on their next reconcile (default 30s) and hot-reload
mihomo/blocky; routing and denylist changes never need a re-provision.

Provisioning is only for a node not yet in the fleet, and only for exits (the
co-located master has no `ssh:` block; `install.sh` installs it and
`./deploy-master.sh` upgrades it):

```sh
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1 --plan
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1
```

## Verify

Connect a device (see the Quickstart), then:

**1. Non-RU traffic exits abroad.** An IP-geolocation site (e.g.
`https://ipinfo.io`) shows the **exit's** country.

**2. RU traffic stays local.** A `.ru` "what's my IP" page shows **your local /
master** IP. On the master, watch the decision live:

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
nslookup doubleclick.net      # blocked → NXDOMAIN
nslookup example.com          # resolves
```

Or on the master:

```sh
docker logs blocky 2>&1 | grep -i blocked | tail
```

**5. An allowlisted site resolves** even if a denylist would otherwise catch it.

## Common adjustments

| Want | Change |
|------|--------|
| Keep more countries local | `direct_geo: [RU, BY, KZ]` (add matching `.mrs` providers if you use the hardened geo) |
| A specific domain always local | add it to `mihomo.extra_files` `direct-domains.yaml` + a `RULE-SET,direct-domains,DIRECT` rule (see the example config) |
| Force a specific IP through the exit | `IP-CIDR,<ip>/32,wg-best,no-resolve` in the `rules` override |
| Stricter / lighter filtering | swap the hagezi list (`pro.txt` ↔ `light.txt` / `pro.plus.txt`), or add/remove groups |
| A site a blocklist breaks | add it to `dns.allowlist` (wins over every denylist) |
| Keep a slow exit as a warm spare | `routing.reserve_exits: [exit-slow]` — used only when every primary exit is down |
| More exits sharing the load | add another `exits[]` entry (unique `name` + `address_pool`); `consistent-hashing` spreads across all of them |

## Gotchas

- **Use the AmneziaWG app, not plain WireGuard** on clients.
- **The master must reach GitHub (or a mirror) *directly*** for geo data and
  blocklists.
- **`dns_filter` on the master requires at least one exit with `dns_filter: true`.**
- **Do not point clients at a public resolver** — that bypasses the filter.
  `dns_filter: true` makes the master the client DNS (it binds the client-pool gateway).
- **Overriding `rules` or any list REPLACES it.** Include every rule you still
  want; the hardened block above is complete.
