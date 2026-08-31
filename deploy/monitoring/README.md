# wgfleet — monitoring

Prometheus + Grafana for the fleet. The controller and every agent expose a
Prometheus `/metrics` endpoint **bound to the mgmt/ZeroTier address only** (never
the public interface — the code refuses a public bind).

## Files

| File | What |
|---|---|
| `grafana-dashboard.json` | Grafana dashboard — import it. |
| `servicemonitor.yaml` | Prometheus-Operator `ServiceMonitor` + headless `Service`/`Endpoints` for the controller and the agents. Edit the ZT addresses. |
| `scrapeconfig.yaml` | Prometheus-Operator `ScrapeConfig` CRD (operator ≥ v0.65) — static targets, no Service plumbing. |
| `vmstaticscrape.yaml` | VictoriaMetrics-Operator `VMStaticScrape` CRD — for a `vmagent`. Edit the ZT addresses. |
| `vmrule.yaml` | VictoriaMetrics-Operator `VMRule` — alerts over the fleet metrics. No addresses to edit. |
| `prometheusrule.yaml` | Prometheus-Operator `PrometheusRule` — the same alerts. |

Pick the one that matches your stack: `ServiceMonitor`/`ScrapeConfig` +
`PrometheusRule` for Prometheus-Operator, `VMStaticScrape` + `VMRule` for
VictoriaMetrics-Operator.

## Metrics ports

| Component | Endpoint | Set by |
|---|---|---|
| controller | `<mgmt-addr>:9300` | `controller.metrics` in `controller.yaml` |
| agent | `<mgmt-addr>:9301` | `--metrics <mgmt-addr>:9301` agent flag |

## 1. The agent `/metrics` endpoint

**It is on by default** at `<mgmt_addr>:9301` — the agent binds it to the same
management address it already knows, never a public interface. There is nothing to
enable and no systemd drop-in to write; earlier revisions of this file described one
and it is obsolete.

`--metrics` is an *override*, not a switch: pass an explicit `host:port` to move it,
or `off` to disable it entirely.

```bash
# where it is listening right now
ss -lntp | grep 9301
curl -s http://<mgmt_addr>:9301/metrics | head
```

The controller's `/metrics` is on `controller.metrics` (9300) and is likewise bound
to the management address only.

## 2. Scrape from Kubernetes

The Prometheus pods must be able to **reach the ZT addresses** — join the cluster
to the ZeroTier network, or route the ZT subnet to the Prometheus pods. Then:

```sh
kubectl apply -f servicemonitor.yaml     # Prometheus-Operator (Service/Endpoints)
kubectl apply -f scrapeconfig.yaml       # Prometheus-Operator (ScrapeConfig CRD)
kubectl apply -f vmstaticscrape.yaml     # VictoriaMetrics-Operator (vmagent)
```

Then the alert rules — the same pick, and **do not skip this step**: scraping
metrics nobody alerts on tells you what went wrong only after somebody has already
told you that something did.

```bash
kubectl apply -f prometheusrule.yaml     # Prometheus-Operator
# or
kubectl apply -f vmrule.yaml             # VictoriaMetrics-Operator
```

Edit before applying:
- the **ZT addresses** in the `Endpoints` / `staticConfigs.targets` / `targetEndpoints.targets`,
- the **namespace** (defaults to `monitoring`),
- the discovery selector label so your scraper picks it up:
  - Prometheus-Operator: the **`release` label** must match
    `serviceMonitorSelector` / `scrapeConfigSelector` (kube-prometheus-stack uses
    the Helm release name).
  - VictoriaMetrics-Operator: the VMStaticScrape label must match the vmagent's
    **`staticScrapeSelector`** (or set the vmagent `selectAllByDefault: true`).

Verify targets are `UP` under Prometheus → Status → Targets.

## 3. Import the dashboard

Grafana → Dashboards → New → Import → upload `grafana-dashboard.json`, pick your
Prometheus data source. The dashboard variable `$node` is populated from
`wgfleet_node_info` (controller metrics), so the controller alone already drives
the overview, inventory and health rows; the egress-throughput and reconcile rows
need the agent `/metrics` (step 1).

## Metric reference

**Controller** (`wgfleet_*`, projected from the state store at scrape time):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_nodes` | `state` | node count per lifecycle state |
| `wgfleet_node_info` | `node,role,region,state` | inventory (=1) |
| `wgfleet_node_last_report_age_seconds` | `node` | staleness of the last status report |
| `wgfleet_node_reconcile_failed` | `node` | 1 if last reconcile errored |
| `wgfleet_node_health_check` | `node,check` | 1 ok / 0 failing (incl. `egress-throughput`, `egress-reachability`, `client-vless`) |
| `wgfleet_node_egress_info` | `node,egress_ip` | observed egress IP (=1) |
| `wgfleet_node_agent_info` | `node,agent_version,wire_version` | reported agent build (=1) |
| `wgfleet_node_drain` / `wgfleet_node_decommission` | `node` | admin intent (0/1) |
| `wgfleet_node_client_vless_clients` | `node` | VLESS/REALITY clients issued for a master's client-facing inbound; masters only |
| `wgfleet_build_info` | `component,version,commit` | controller build (=1) |

**Agent** (`wgfleet_agent_*`, every series carries `node` + `role`):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_agent_reconcile_total` | `result` | passes by success/error |
| `wgfleet_agent_reconcile_duration_seconds` | (histogram) | pass duration |
| `wgfleet_agent_reconcile_changes` | | resources changed last pass |
| `wgfleet_agent_state_info` | `state` | current lifecycle state (=1) |
| `wgfleet_agent_health_check` / `_latency_seconds` | `check` | self-check result / probe latency |
| `wgfleet_agent_drift_total` / `_resources` | `component` | config-drift repairs |
| `wgfleet_agent_egress_reachability` | `state` | ok/degraded/blocked |
| `wgfleet_agent_egress_active` | `method` | active egress, warp/direct |
| `wgfleet_agent_egress_throughput_bytes` | | measured egress bandwidth |
| `wgfleet_agent_start_time_seconds` | | process start (for uptime) |
| `wgfleet_agent_cert_expiry_timestamp_seconds` | | when this node's mTLS certificate expires; **read at every scrape, not at boot** |
| `wgfleet_agent_cert_expiry_read_errors_total` | | scrapes at which that certificate could not be read or parsed |

**Watching the certificate.** Agents renew their own mTLS certificate in place,
between 70% and 90% of its life, with no restart — so on a healthy node the expiry
steps forward roughly once a year and otherwise sits still. A node whose remaining
time **stops going up** is one whose renewal is failing, and by the time
`WgfleetNodeCertExpiring` fires it has been failing for at least forty days. The
gauge is re-read on every scrape for exactly this reason: an earlier version read
the file once at process start, so a node that renewed cleanly and a node whose
renewal had been broken for months published the identical series.

**WireGuard / AmneziaWG peers** (`wgfleet_wg_*`, agent endpoint, `node` + `role`,
per interface):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_wg_handshake_age_seconds` | `iface,peer` | seconds since that peer's last handshake |
| `wgfleet_wg_peers_active` | `iface` | peers with a handshake inside the freshness window |
| `wgfleet_wg_collector_up` | `iface` | 1 when the peer dump could be read, 0 when it could not |

`wgfleet_wg_collector_up` exists because absence of the peer series is otherwise
indistinguishable from having no peers — "the interface has zero clients" and "we
could not run `awg show`" are different facts and only one of them is an outage.
`WgfleetNoClientPeers` reads both arms for that reason.


**Scheduled probes** (`wgfleet_probe_*`, agent endpoint, `node` + `role` labels).
These cover the timer-driven probes that refresh a cache on their own schedule —
the WARP path-MTU auto-probe (`warp_path_mtu`, daily) and the scanner-ASN feed
refresh (`as_blacklist_feed`):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_probe_last_success_timestamp_seconds` | `probe` | unix time of the last successful run; **0 = never succeeded** |
| `wgfleet_probe_last_attempt_timestamp_seconds` | `probe` | unix time of the last attempt, successful or not; 0 = never ran |

A probe that has never even attempted to run on a node (feature disabled, or
`warp_mtu` pinned by the operator) emits **no series at all** — an all-zero pair
would be indistinguishable from a broken probe.

Why they exist: these probes fail *softly* by design — the error is non-fatal, the
last-good/default value stays in force, and only a `WARN` is logged. That is the
right behaviour, but it makes total failure look exactly like normal operation.
The WARP path-MTU probe failed on 100% of runs on every node while the whole fleet
reported `Ready`, so auto-MTU discovery was dead and a real PMTU
regression would have gone unnoticed. These two timestamps make "attempting on
schedule, never succeeding" a visible state.

## 4. Alerts

**Do not hand-write these.** `vmrule.yaml` / `prometheusrule.yaml` ship 28 alerts,
already applied by step 2 above. Earlier revisions of this file printed two of them
as a snippet to paste; the copies drifted from the shipped rules (different group
name, different `for`, a different expression on one), so pasting produced a second,
differently-behaving alert beside the real one. The rules carry their reasoning in
comments — read the file, do not retype it.

What ships, by severity:

| Alert | Severity |
|---|---|
| `WgfleetClientPathDown` | critical |
| `WgfleetControllerDown` | critical |
| `WgfleetNoClientPeers` | critical |
| `WgfleetNoReadyExit` | critical |
| `WgfleetNodeCertExpired` | critical |
| `WgfleetNodeError` | critical |
| `WgfleetNodeReportStale` | critical |
| `WgfleetWARPEgressBlocked` | critical |
| `WgfleetASBlacklistEmpty` | warning |
| `WgfleetAgentFlapping` | warning |
| `WgfleetAgentScrapeDown` | warning |
| `WgfleetAgentUnscraped` | warning |
| `WgfleetAgentVersionSkew` | warning |
| `WgfleetConfigDrift` | warning |
| `WgfleetCAExpiringSoon` | critical |
| `WgfleetConfigUnreadable` | warning |
| `WgfleetHealthCheckFailing` | warning |
| `WgfleetNodeCertExpiring` | warning |
| `WgfleetNodeDrainedTooLong` | warning |
| `WgfleetNodeNotReady` | warning |
| `WgfleetNodeReconcileFailed` | warning |
| `WgfleetPersistentDrift` | warning |
| `WgfleetProbeNeverSucceeded` | warning |
| `WgfleetProbeStale` | warning |
| `WgfleetReconcileErrors` | warning |
| `WgfleetWARPEgressDegraded` | warning |
| `WgfleetWireGuardHandshakeStale` | warning |
| `WgfleetWireVersionSkew` | warning |

Two notes worth carrying in your head:

- **`WgfleetWARPEgress{Blocked,Degraded}` only fire on an exit running WARP.** The
  reachability classifier produces nothing without a `warp-egress` health check, so an
  exit on direct egress publishes no such series and cannot raise these. They were
  called `WgfleetEgress*` until 2026-08-28; if you have Alertmanager routes or
  silences on the old names, they match nothing now.
- **`WgfleetNodeCert{Expiring,Expired}` mean renewal is BROKEN, not that a birthday is
  near.** Agents renew themselves between 70% and 90% of the certificate's life, so by
  the time the 30-day warning fires it has been failing for at least forty days.
