# Recipe: RU / non-RU split tunnel + DNS filtering

**Goal.** Stand up a fleet where your devices reach **Russian** sites directly
(local IP, no foreign hop, full speed) while **everything else** leaves through
an exit abroad — and where ads/trackers are filtered at the DNS layer for every
client. This is the most common wgfleet setup; this page shows the exact keys
that produce it and how to verify each one.

It assumes you have already read [QUICKSTART.md](../QUICKSTART.md) or
[colocated-controller-master.md](../colocated-controller-master.md) and can
bring a master + one exit to `Ready`. This recipe only changes **what goes in
`controller.yaml`** — the bring-up steps are identical.

Ready-to-adapt config: [`deploy/examples/controller-split-ru.yaml`](../../deploy/examples/controller-split-ru.yaml)
(also copied to `/etc/wgfleet/examples/` by `install.sh`).

---

## The mental model

```
 your phone/laptop ──AmneziaWG──► MASTER (near you) ──AmneziaWG──► EXIT (abroad) ──► internet
                                     │
                                     └─ RU sites/IPs egress DIRECTLY from the master
```

The master runs mihomo, which decides **per connection** whether traffic goes
out locally (DIRECT) or through an exit. It evaluates rules top-to-bottom:

| Order | Rule (rendered by mihomo) | Source key | Effect |
|------:|---------------------------|------------|--------|
| 1 | `RULE-SET,direct-networks,DIRECT` | `routing.direct_cidrs` (+ `fleet.mgmt_subnet`) | private/LAN nets never enter the tunnel |
| 2 | `GEOSITE,category-ru,DIRECT` | `routing.direct_geo: [RU]` | `.ru` and known-Russian **domains** stay local |
| 2 | `GEOIP,RU,DIRECT,no-resolve` | `routing.direct_geo: [RU]` | Russian **IP ranges** stay local |
| 3 | `MATCH,wg-best` | (always last) | **everything else** → the exit(s) abroad |

So `direct_geo: [RU]` *is* the split. Nothing else is needed to divide RU from
non-RU. Add regions to keep more local — `direct_geo: [RU, BY]` keeps Belarus
local too. (Geo codes are the MetaCubeX geosite/geoip categories.)

> mihomo downloads the geoip/geosite databases on first run to evaluate these
> rules; the master fetches them through a DIRECT detour from a jsdelivr mirror
> automatically when `direct_geo` is set.

## The DNS filter

Two independent layers, both `blocky`:

- **Master `dns_filter: true`** — the master becomes your devices' single DNS.
  A blocked domain simply doesn't resolve, so the client never even opens the
  connection. This is what filters ads/trackers for end users. It forwards
  everything it doesn't block to the exits' resolvers.
- **Exit `dns_filter: true`** — a clean upstream resolver (DoT) that the master
  forwards to. Required so the master's filter has an upstream to point at;
  filtering here too adds defense in depth.

Denylists and the allowlist live under `dns.overrides.blocking` /
`dns.allowlist`. The allowlist always wins — use it the moment a list breaks a
site you need (banking, gosuslugi, etc.).

## The three keys that matter

Everything else in the example is ordinary fleet setup. These are the ones that
create the behavior:

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
        allowlist: ["*.gosuslugi.ru"]
        overrides:
          blocking:
            denylists:
              ads: [https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt]
            clientGroupsBlock: { default: [ads] }
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

### Why `consistent-hashing`

With multiple exits, `consistent-hashing` sends the same destination through the
same exit every time, so a site keeps one egress IP and country (no captchas
from a country that flip-flops mid-session), while different destinations spread
across all exits. The alternatives (`round-robin`, `sticky-sessions`,
`fallback`, `url-test`) and their trade-offs are documented in
[`deploy/examples/controller.yaml`](../../deploy/examples/controller.yaml).

## Apply it

Same flow as any config change — no special steps:

```sh
# edit /etc/wgfleet/controller.yaml (or start from the example)
systemctl restart wgfleet-controller
# preview, then apply, per node:
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision master-1 --plan
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision master-1
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1 --plan
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1
```

On an already-running fleet, the agent picks the change up on its next reconcile
(default 30s) and hot-reloads mihomo/blocky; you don't have to re-provision for
a routing or denylist tweak.

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

**3. DNS filtering works.** From the connected device:

```sh
# a known ad host should NOT resolve (0.0.0.0 / NXDOMAIN); a normal one should
nslookup doubleclick.net      # blocked
nslookup example.com          # resolves
```

Or on the master, confirm blocky is answering and counting blocks:

```sh
docker logs blocky 2>&1 | grep -i blocked | tail
```

**4. An allowlisted site is never blocked.** Anything under `dns.allowlist`
resolves normally even if a denylist would otherwise catch it.

## Common adjustments

| Want | Change |
|------|--------|
| Keep more countries local | `direct_geo: [RU, BY, KZ]` |
| A specific domain always local | add it to `mihomo.extra_files` `direct-domains.yaml` (see reference config) |
| Stricter / lighter filtering | swap the hagezi list (`pro.txt` → `light.txt` / `pro.plus.txt`), or add categories under `denylists` |
| A site that a blocklist breaks | add it to `dns.allowlist` (wins over every denylist) |
| Resolve internal/work domains | add `dns.overrides.conditional.mapping` + set mihomo `dns.nameserver: [127.0.0.1:53]` (an earlier finding — see reference config) |
| More exits sharing the load | add another `exits[]` entry (unique `name` + `address_pool`); `consistent-hashing` spreads across all of them |

## Gotchas

- **Use the AmneziaWG app, not plain WireGuard** on clients — the obfuscation is
  AmneziaWG-specific.
- **The master needs the geo databases.** If mihomo can't fetch them (GitHub /
  jsdelivr blocked on the master's network), `direct_geo` rules can't evaluate
  and everything falls through to `wg-best` (all traffic via the exit). Point it
  at a reachable mirror if needed.
- **`dns_filter` on the master requires at least one exit with `dns_filter: true`**
  as its upstream; the example sets both.
- **Filtering is client-facing only when the master is the client DNS**, which
  `dns_filter: true` arranges automatically (it binds the client-pool gateway).
  Don't override clients' DNS to a public resolver, or you bypass the filter.
