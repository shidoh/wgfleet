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
| `vmrule.yaml` | VictoriaMetrics-Operator `VMRule` — 22 alerts over the fleet metrics. No addresses to edit. |
| `prometheusrule.yaml` | Prometheus-Operator `PrometheusRule` — the same 22 alerts. |

Pick the one that matches your stack: `ServiceMonitor`/`ScrapeConfig` +
`PrometheusRule` for Prometheus-Operator, `VMStaticScrape` + `VMRule` for
VictoriaMetrics-Operator.

## Metrics ports

| Component | Endpoint | Set by |
|---|---|---|
| controller | `<mgmt-addr>:9300` | `controller.metrics` in `controller.yaml` |
| agent | `<mgmt-addr>:9301` | `--metrics <mgmt-addr>:9301` agent flag |

## 1. Enable the agent `/metrics`

Each agent serves metrics only when started with `--metrics`. Bind it to the
node's ZT address (the agent already knows it via `--mgmt-addr`):

```ini
# /etc/systemd/system/wgfleet-agent.service.d/metrics.conf  (drop-in)
# Replace 10.20.0.20 with THIS node's ZT/mgmt address.
[Service]
ExecStart=
ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml --log-format json --metrics 10.20.0.20:9301
```

then `systemctl daemon-reload && systemctl restart wgfleet-agent`. New nodes get
this automatically from the provisioner. The controller's `/metrics` is already on
`controller.metrics` (9300).

## 2. Scrape from Kubernetes

The Prometheus pods must be able to **reach the ZT addresses** — join the cluster
to the ZeroTier network, or route the ZT subnet to the Prometheus pods. Then:

```sh
kubectl apply -f servicemonitor.yaml     # Prometheus-Operator (Service/Endpoints)
kubectl apply -f scrapeconfig.yaml       # Prometheus-Operator (ScrapeConfig CRD)
kubectl apply -f vmstaticscrape.yaml     # VictoriaMetrics-Operator (vmagent)
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

## 4. Alerts worth having

```yaml
groups:
  - name: wgfleet-probes
    rules:
      # The probe runs and fails every time: it has attempted, but never once
      # produced a result. This is the shape of a probe that is dead but silent.
      - alert: WgfleetProbeNeverSucceeded
        expr: wgfleet_probe_last_success_timestamp_seconds == 0
        for: 2h
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.probe }} on {{ $labels.node }} has never succeeded"
          description: "The probe is attempting on schedule but has never produced a result; the node is silently running on the built-in default."

      # It worked once and then stopped. Both probes run about daily.
      - alert: WgfleetProbeStale
        expr: |
          (wgfleet_probe_last_success_timestamp_seconds > 0)
          and (time() - wgfleet_probe_last_success_timestamp_seconds > 7 * 24 * 3600)
        for: 1h
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.probe }} on {{ $labels.node }} has not succeeded in 7d"
          description: "Last-good value still in force; the probe has been failing since {{ $value | humanizeTimestamp }}."
```

Both are also on the dashboard's **Scheduled probes** row.
