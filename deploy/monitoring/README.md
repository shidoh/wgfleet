# wgfleet — monitoring

Prometheus + Grafana for the fleet. The controller and every agent expose a
Prometheus `/metrics` endpoint **bound to the mgmt/ZeroTier address only** (never
the public interface — the code refuses a public bind).

## Files

| File | What |
|---|---|
| `grafana-dashboard.json` | Grafana dashboard, **classic schema** (`schemaVersion: 39`) — import it into Grafana 12 and older. Source of truth: edit this one. |
| `grafana-dashboard-v2.json` | The same dashboard in the **Grafana 13 schema** (`dashboard.grafana.app/v2`) — paste it into the JSON editor of an existing dashboard to replace it in place. Generated; do not hand-edit. |
| `dashboard-to-v2.py` | Regenerates the v2 file from the classic one. |
| `servicemonitor.yaml` | Prometheus-Operator `ServiceMonitor` + headless `Service`/`Endpoints` for the controller and the agents. Edit the ZT addresses. |
| `scrapeconfig.yaml` | Prometheus-Operator `ScrapeConfig` CRD (operator ≥ v0.65) — static targets, no Service plumbing. |
| `vmstaticscrape.yaml` | VictoriaMetrics-Operator `VMStaticScrape` CRD — for a `vmagent`. Edit the ZT addresses. |
| `vmscrapeconfig-sd.yaml` | VictoriaMetrics-Operator `VMScrapeConfig` over the controller's service discovery — the same three jobs with no address list. Edit the controller address only. Use it **instead of** `vmstaticscrape.yaml`. |
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

### Service discovery from the controller

The controller serves Prometheus HTTP service discovery next to its `/metrics`,
on the same mgmt-only address:

| URL | Job | Targets | Target labels |
|---|---|---|---|
| `/sd/wgfleet` | `wgfleet` | the controller, every agent on `:9301` | `component`; agents also `__meta_wgfleet_node`, `__meta_wgfleet_role` |
| `/sd/node-exporter` | `wgfleet-node` | every node on `:9100` | `node`, `role` |
| `/sd/blocky` | `blocky` | every node with `dns_filter` and blocky metrics on, on its blocky HTTP port | `node`, `role` |

Only nodes with a mgmt address are listed. If the controller cannot read its
store, the endpoint answers `503` and the scraper keeps the last list.
`vmscrapeconfig-sd.yaml` points a `vmagent` at it. With Prometheus-Operator, use
`httpSDConfigs` in a `ScrapeConfig` with these URLs and set `job` to the job name
above — the alerts select on it.

### Host metrics (node_exporter)

Every node exports host metrics on `<mgmt_addr>:9100` only. The bootstrap installs
`prometheus-node-exporter` on a node that serves nothing there; an exporter you
already run on that address is adopted as-is — see "Host metrics (yours to upgrade)"
in `docs/operations.md`. Scrape it as job `wgfleet-node` with a
`node` label equal to the manifest name, so host series join the fleet series —
`vmstaticscrape.yaml` carries the template. `WgfleetHostMetricsMissing` names any
node the controller knows that this job is not scraping; nodes provisioned before
this existed are exactly those, and a re-provision (or a one-off
`apt-get install prometheus-node-exporter`) closes it.

## 3. Import the dashboard

**Which file depends on your Grafana.** Grafana 13 replaced the dashboard wire
format, and the two are not interchangeable — each version rejects the other's
file, so shipping only one strands whoever runs the other.

- **Grafana 12 and older:** Dashboards → New → Import → upload
  `grafana-dashboard.json`.
- **Grafana 13+:** open the dashboard → Edit → JSON model, and paste
  `grafana-dashboard-v2.json` over what is there. Its `metadata.name` matches the
  classic `uid` (`wgfleet-fleet`), so this REPLACES the existing dashboard rather
  than leaving a second copy beside it.

### DNS metrics (blocky)

blocky runs on every node with metrics on `<mgmt_addr>:4000`. Scrape it as job
`blocky` with per-target `node` and `role` labels — blocky sets no node label of
its own. `vmstaticscrape.yaml` carries the template; `WgfleetDNSMetricsMissing`
names any node the controller knows that this job is not scraping.

### What the dashboard answers, top to bottom

| Row | Answers |
|---|---|
| Now | what is firing; clients online and their traffic; synthetic-client failures; exits carrying traffic and reserve tier, per master; DNS SERVFAIL share |
| Clients | client peers and traffic per master; the masters' DNS answers; DNS latency and failures per node |
| Master → exit | exit × master matrix (carrying / ready / held out / OUT); only the pairs that left rotation in the range; traffic leaving each exit; tunnel delay; stale AWG tunnels, exits silent at the gate, failed reserve members — each empty while healthy |
| Control plane & inventory | controller build, CA expiry, manifest drift, store; node table with agent build, cert days left and uptime |
| Health | checks failing now, by kind, and what failed in the range |
| collapsed | client-path internals, transport, egress watchdog, VLESS, reconcile, scheduled probes, host |

`$master` filters the per-master panels, `$exit` the per-tunnel ones, `$node` the
rest. The "Agent restarts" annotation marks rollouts.

Then pick your Prometheus data source. The dashboard variable `$node` is
populated from `wgfleet_node_info` (controller metrics), so the controller alone
already drives the overview, inventory and health rows; the egress-throughput,
exit-rotation, client-path and reconcile rows need the agent `/metrics` (step 1),
and the host row needs the node-exporter job.

### Editing it

`grafana-dashboard.json` is the source of truth. After changing it:

```bash
python3 deploy/monitoring/dashboard-to-v2.py
```

`TestDashboardV2MatchesClassic` fails if the two drift, so a forgotten
regeneration is a red build rather than a dashboard whose halves disagree about
which panels exist. What actually differs between the formats — a flat panel list
with absolute coordinates versus elements plus a row layout with **row-relative**
ones — is documented at the top of that script.

## Metric reference

**Controller** (`wgfleet_*`, projected from the state store at scrape time):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_nodes` | `state` | node count per lifecycle state |
| `wgfleet_node_info` | `node,role,region,state` | inventory (=1) |
| `wgfleet_node_last_report_age_seconds` | `node` | staleness of the last status report |
| `wgfleet_node_reconcile_failed` | `node` | 1 if last reconcile errored |
| `wgfleet_node_health_check` | `node,check` | 1 ok / 0 failing (incl. `egress-throughput`, `egress-reachability`, `client-vless`, `lifeline`) |
| `wgfleet_node_egress_info` | `node,egress_ip` | observed egress IP (=1) |
| `wgfleet_node_agent_info` | `node,agent_version,wire_version` | reported agent build (=1) |
| `wgfleet_node_drain` / `wgfleet_node_decommission` | `node` | admin intent (0/1) |
| `wgfleet_node_client_vless_clients` | `node` | VLESS/REALITY clients issued for a master's client-facing inbound; masters only |
| `wgfleet_client_info` | `node,peer,client,device,kind` | one per client credential (=1); `node` is the master. `kind=awg`: `peer` is the WireGuard key in the agents' 8-character form — join `on(peer)` to `wgfleet_wg_peer_*` on the master's `wg0` and an exit's lifeline `awgl0`. `kind=vless`: `peer` is the VLESS stats id — join to `wgfleet_vless_user_*{user}` |
| `wgfleet_build_info` | `component,version,commit` | controller build (=1) |
| `wgfleet_exit_tunnel_alive` | `node,exit` | 1 when the master's mihomo has this master↔exit tunnel up, 0 when it is out of the load-balance rotation. `node` is the MASTER holding the tunnel, `exit` the far end |
| `wgfleet_exit_tunnel_selected` | `node,exit` | 1 when this exit currently carries traffic for wg-best |
| `wgfleet_exit_tunnel_delay_seconds` | `node,exit` | last url-test delay; **absent when the measurement failed** — a failed probe is not a fast one and must never read as 0 |
| `wgfleet_exit_tunnel_last_test_age_seconds` | `node,exit` | age of that measurement. mihomo's alive flag is sticky, so a stale age means the reading is frozen, not that the tunnel is fine |

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
| `wgfleet_agent_cert_renew_total` | `result` | this node's own certificate rotations, `success` or `error`; both series exist from agent start |
| `wgfleet_agent_cert_reload_errors_total` | | handshakes at which the certificate/key pair could not be re-read from disk; the agent kept the pair loaded at startup |

**Watching the certificate.** Agents renew their own mTLS certificate in place,
between 70% and 90% of its life, with no restart — so on a healthy node the expiry
steps forward roughly once a year and otherwise sits still. A node whose remaining
time **stops going up** is one whose renewal is failing. `WgfleetNodeCertRenewFailing` says so within hours of the
first failed attempts; by the time `WgfleetNodeCertExpiring` fires it has been
failing for at least forty days. The
gauge is re-read on every scrape for exactly this reason: an earlier version read
the file once at process start, so a node that renewed cleanly and a node whose
renewal had been broken for months published the identical series.

**WireGuard / AmneziaWG peers** (`wgfleet_wg_*`, agent endpoint, `node` + `role`,
per interface):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_wg_handshake_age_seconds` | `iface,peer` | seconds since that peer's last handshake |
| `wgfleet_wg_peer_rx_bytes` / `_tx_bytes` | `iface,peer` | bytes from and to that peer, cumulative; they reset when the interface is re-created, so read them with `rate()`/`increase()` rather than as a running total |
| `wgfleet_wg_peers_active` | `iface` | peers with a handshake inside the freshness window |
| `wgfleet_wg_collector_up` | `iface` | 1 when the peer dump could be read, 0 when it could not |

**VLESS clients** (`wgfleet_vless_*`, master agent, `node` + `role`; only while the
master runs the client VLESS inbound):

| Metric | Labels | Meaning |
|---|---|---|
| `wgfleet_vless_user_rx_bytes` / `_tx_bytes` | `user` | bytes from and to that client, cumulative; reset when xray restarts — which it does on every client issue or revoke — so read with `rate()`/`increase()`. Payload after decryption, without REALITY/XHTTP overhead |
| `wgfleet_vless_user_online_ips` | `user` | source IPs with open connections now; `> 0` = online. Absent when the xray build cannot say |
| `wgfleet_vless_collector_up` | — | 1 when xray's stats API answered, 0 when it did not (`WgfleetVLESSStatsUnreadable`) |

`user` is the client's stats id — the first 12 hex digits of sha256(UUID) — never
the UUID: the UUID is the credential, and this endpoint is unauthenticated. xray
serves the stats API on `127.0.0.1:10085` only.

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
| `wgfleet_controller_store_up` | — | 1 when the controller could read its store on this scrape, 0 when it could not. Fleet-wide rules gate on it, so an unreadable store no longer reads as an empty fleet |
| `wgfleet_controller_ca_expiry_timestamp_seconds` | — | unix time the fleet CA expires. Every node certificate chains to it, so its lapse cannot be repaired over the control plane |
| `wgfleet_controller_config_drift` | — | 1 when the manifest on disk differs from the one the controller loaded, 0 when they match, **absent when it cannot be read** — which is what `WgfleetConfigUnreadable` watches |
| `wgfleet_agent_transport_active` | `transport` | which master↔exit transport this exit is serving (exit-only) |
| `wgfleet_agent_exit_held_out` | `exit` | 1 while the master's multi-destination probe holds this exit out of wg-best (master-only). The CAUSE behind `wgfleet_exit_tunnel_alive == 0` |
| `wgfleet_agent_awg_pin_armed` | `exit` | 1 when the master answers this exit's AmneziaWG tunnel only from its pinned port and only after hearing the exit (`transports.awg.exit_initiated`). Master-only |
| `wgfleet_agent_awg_exit_heard` | `exit` | 1 while the exit's knocks on its pinned master port keep it in the gate's heard set, 0 when armed and silent. Master-only |
| `wgfleet_agent_awg_exit_heard_age_seconds` | `exit` | seconds since the exit's last knock; absent while not heard. Master-only |
| `wgfleet_agent_awg_gate_drops_total` | `exit` | packets the master's gate held back from a new flow because the exit had not knocked yet. Master-only |
| `wgfleet_agent_reserve_tier_active` | — | 1 when wg-best routes to the second-choice (reserve) exit tier instead of the primary one (master-only) |
| `wgfleet_agent_standby_tier_usable` / `_total` | — | members of the INACTIVE tier the last warm probe found usable, out of those it could sample (master-only) |
| `wgfleet_agent_standby_tier_member_usable` | `exit` | 1 when the last warm probe reached the internet through this member of the INACTIVE tier, 0 when it did not (master-only). The tally above cannot be acted on — one dead reserve exit hides inside "2 of 3"; this names it. **Absent means never sampled** |
| `wgfleet_agent_standby_transport_usable` | `exit,transport` | 1 when this exit's INACTIVE transport — the one an operator would switch it onto — reached the internet on the last probe, 0 when it did not (master-only). **Absent means never measured**, which is not the same as healthy |
| `wgfleet_agent_reality_bridge_connected` | `master` | 1 when the exit's REALITY bridge holds a connection to this master's portal, 0 when it holds none (exit-only, exit-initiated REALITY). **Absent outside the mode** |
| `wgfleet_agent_reality_bridge_kills_total` | `master` | bridge sockets to this master's portal the watchdog killed after 30 s without a received byte — one-way freezes on that path (exit-only) |
| `wgfleet_fw_as_blacklist_size` | `family` | size of the scanner-ASN blacklist set actually loaded in nftables |
| `wgfleet_agent_client_path_ok` | `probe` | 1 when the master's OWN client can send and receive over this protocol through the full client path (interface, firewall, proxy, exit); 0 when it cannot (master-only). Probes: `icmp/direct`, `icmp/gateway`, `icmp/mgmt`, `tcp/443`, `udp/53`. The one measurement that says whether a client works, as opposed to whether each component looks fine |
| `wgfleet_agent_udp_return_socket` | `port` | 1 when a TPROXY reply socket can still be opened for this destination port; 0 when a socket this namespace already holds makes it impossible, so client traffic to that port gets no replies (master-only) |
| `wgfleet_agent_udp_return_known` | `port` | 1 when a port whose replies cannot come back is one we have decided about (refused by rule, or a declared loss); 0 marks a silent black hole. `WgfleetClientUDPBlackHole` reads both |
| `wgfleet_agent_netns_move_state` | `state` | 1 for the state the client-interception move is in (`waiting`, `attached`, `gave_up`), 0 for the others (master-only) |
| `wgfleet_agent_netns_move_attempts` | — | reverts this master has spent out of its allowance; at the limit it stops trying and stays on the host path |
| `wgfleet_agent_mihomo_errors_total` | — | error lines mihomo has written about itself, deliberately unclassified: the signal is that the data plane is complaining at all |
| `wgfleet_agent_guard_drops_packets` | `chain` | packets each firewall guard chain has dropped since its ruleset was applied. `egress_path_guard` must stay at zero (any drop pages); `egress_leak_guard` catches stragglers that would leave un-NATed, and only a RISING count alerts |
| `wgfleet_agent_mihomo_start_time_seconds` | — | unix time mihomo's container last started, from `docker inspect` (master-only). Steps forward on EVERY restart — a self-heal, a crash, docker's restart policy — so `changes()` over it counts restarts no single restarter has to confess to |
| `wgfleet_agent_self_heal_restarts` | `service` | self-heal restarts the agent has applied to this service since it started (monotonic gauge; read with `increase()`; master-only) |
| `wgfleet_agent_self_heal_throttled` | `service` | 1 while the restart governor refuses further self-heal restarts of this service. **The defect is still there; only the symptom is muted** — fewer restarts here is not recovery |

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

The `wgfleet_exit_tunnel_*` family is the **only** view of the master↔exit tunnels.
They are userspace mihomo proxies, not kernel WireGuard, so no `wgfleet_wg_*` series
covers them — and until 2026-09-04 nothing else did either. Three exits had been
dropping out of the load balancer for two weeks and the sole record was the master
agent's journal, which is why an exit falling out of rotation could not be seen on a
dashboard at all.

Read it together with `wgfleet_agent_exit_held_out`. Two health criteria write
mihomo's alive flag: mihomo's own group check (one lightweight URL, every interval)
and the master agent's multi-destination probe (four independent destinations, which
is what catches a censored-but-"healthy" exit). `alive` shows the effect; the
held-out gauge says which criterion caused it.

Two different "standby" ideas live next to each other, and mixing them up costs an
outage. `standby_tier_*` is about a whole TIER of exits the master fails over to on
its own. `standby_transport_usable` is about the second TRANSPORT of one exit
(AWG ↔ REALITY), which nothing fails over to automatically — an operator switches
it by hand, in an emergency, precisely when the active path has been blocked.

The distinction matters because the second one is invisible by construction: a
standby transport is deliberately drained, so it sits in no proxy group, so
neither mihomo's own health check nor the tier probe ever dials it. Measured on
the live fleet 2026-09-04, five of six exits had a standby transport and none had
ever been health-checked — four reported `alive=1`, which is mihomo's default for
an untested proxy rather than a measurement.

## 4. Alerts

**Do not hand-write these.** `vmrule.yaml` / `prometheusrule.yaml` ship 58 alerts,
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
| `WgfleetNoExitInRotation` | critical |
| `WgfleetNoReadyExit` | critical |
| `WgfleetNodeCertExpired` | critical |
| `WgfleetNodeCertUnloadable` | critical |
| `WgfleetNodeError` | critical |
| `WgfleetNodeReportStale` | critical |
| `WgfleetWARPEgressBlocked` | critical |
| `WgfleetASBlacklistEmpty` | warning |
| `WgfleetAgentFlapping` | warning |
| `WgfleetAgentScrapeDown` | warning |
| `WgfleetAgentUnscraped` | warning |
| `WgfleetAgentVersionSkew` | warning |
| `WgfleetConfigDrift` | warning |
| `WgfleetExitOutOfRotation` | warning |
| `WgfleetExitTunnelHealthStale` | warning |
| `WgfleetReserveTierActive` | warning |
| `WgfleetStandbyTierUnusable` | warning |
| `WgfleetStandbyTierMemberUnusable` | warning |
| `WgfleetStandbyTransportUnusable` | warning |
| `WgfleetRealityBridgeDown` | warning |
| `WgfleetMasterPathsDegrading` | warning |
| `WgfleetExitPathDegrading` | warning |
| `WgfleetExitDegradingFromAllMasters` | warning |
| `WgfleetMasterUplinkDegrading` | warning |
| `WgfleetClientPathDead` | critical |
| `WgfleetClientUDPBlackHole` | critical |
| `WgfleetGuardIsCatchingPackets` | warning |
| `WgfleetUnNATedClientTrafficRising` | warning |
| `WgfleetMihomoComplaining` | warning |
| `WgfleetCAExpiringSoon` | critical |
| `WgfleetConfigUnreadable` | warning |
| `WgfleetHealthCheckFailing` | warning |
| `WgfleetNodeCertExpiring` | warning |
| `WgfleetNodeCertRenewFailing` | warning |
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
| `WgfleetMihomoRestartLoop` | warning |
| `WgfleetSelfHealThrottled` | warning |
| `WgfleetReconcileNeverConverges` | warning |
| `WgfleetHostMetricsMissing` | warning |
| `WgfleetDNSMetricsMissing` | warning |
| `WgfleetVLESSStatsUnreadable` | warning |
| `WgfleetHostDiskAlmostFull` | warning |
| `WgfleetHostMemoryPressure` | warning |
| `WgfleetHostCPUSaturated` | warning |

With several masters, `WgfleetNoExitInRotation` is evaluated per master (label `node`); tunnel alerts join on master and exit. Re-apply the rules after upgrading: rules in the cluster do not update themselves.

Two notes worth carrying in your head:

- **`WgfleetWARPEgress{Blocked,Degraded}` only fire on an exit running WARP.** The
  reachability classifier produces nothing without a `warp-egress` health check, so an
  exit on direct egress publishes no such series and cannot raise these. They were
  called `WgfleetEgress*` until 2026-08-28; if you have Alertmanager routes or
  silences on the old names, they match nothing now.
- **`WgfleetNodeCert{Expiring,Expired}` mean renewal is BROKEN, not that a birthday is
  near.** Agents renew themselves between 70% and 90% of the certificate's life, so by
  the time the 30-day warning fires it has been failing for at least forty days.

## Two different "reserve"s

`WgfleetReserveTierActive` / `wgfleet_agent_reserve_tier_active` are about the
reserve **tier of exits** — the second-choice group the master's balancer falls
back to when every primary exit is down. They have nothing to do with the reserve
**client profiles** an exit's `lifeline` hands out. Those are watched by `wgfleet_node_health_check{check="lifeline"}`
(`WgfleetClientPathDown` when it fails, `WgfleetLifelineCheckMissing` when it stops
being reported at all) and by `wgfleet_wg_peers_active{iface="awgl0"}`.
