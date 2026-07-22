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

Pick the one that matches your stack: `ServiceMonitor`/`ScrapeConfig` for
Prometheus-Operator, `VMStaticScrape` for VictoriaMetrics-Operator.

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
| `wgfleet_node_client_vless_clients` | `node` | VLESS/REALITY clients issued for a master's client-facing inbound (ADR-0031); masters only |
| `wgfleet_build_info` | `component,version,commit` | controller build (=1) |

**Agent** (`wgfleet_agent_*`, every series carries `node` + `role`):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_agent_reconcile_total` | `result` | passes by success/error |
| `wgfleet_agent_reconcile_duration_seconds` | (histogram) | pass duration |
| `wgfleet_agent_reconcile_changes` | | resources changed last pass |
| `wgfleet_agent_state_info` | `state` | current lifecycle state (=1) |
| `wgfleet_agent_health_check` / `_latency_seconds` | `check` | self-check result / probe latency |
| `wgfleet_agent_drift_total` / `_resources` | `component` | config-drift repairs (ADR-0015) |
| `wgfleet_agent_egress_reachability` | `state` | ok/degraded/blocked (ADR-0016) |
| `wgfleet_agent_egress_active` | `method` | active egress, warp/direct (ADR-0017) |
| `wgfleet_agent_egress_throughput_bytes` | | measured egress bandwidth (ADR-0021) |
| `wgfleet_agent_start_time_seconds` | | process start (for uptime) |
