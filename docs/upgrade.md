# Upgrading a wgfleet deployment

Runbook for rolling a new build of wgfleet across a running fleet. The controller
never pushes: an agent asks for its spec when it is ready for one, so a node that
cannot be reached keeps serving its last good configuration.

## Two versions, one of which matters for compatibility

| Version | Where | Purpose |
|---|---|---|
| **Build version** | Stamped from git at build time | Human/observability. Shown by `--version`, in the UI, and in `wgfleet_node_agent_info`. |
| **Wire-contract version** | A constant in each binary | Compatibility key. Controller and agent must agree within `[MinSupportedWire .. WireContractVersion]`. |

Same wire version → release only changes behaviour the agent already understands.
Bumped wire version → agent must understand something new to converge correctly.

Check what a binary speaks:
```
wgfleet-controller --version
wgfleet-agent --version
```
Result: prints wire + build version.

## What happens on a version mismatch

The agent sends its wire + build version as gRPC metadata on every call. The
controller gates `Register` and `PullSpec`.

| Situation | What happens | What to do |
|---|---|---|
| Compatible | Served normally. Controller records the agent's version (UI node page, `wgfleet_node_agent_info`). | — |
| Agent too old / unknown (below `MinSupportedWire`) | Refused with `FailedPrecondition`. Node marked `Degraded` ("agent wire vN …"). Auto-upgrade triggered: controller pushes the configured agent binary over SSH and restarts the agent. | Requires `controller.agent_bin` and SSH reach. |
| Agent too new (controller behind) | Refused. | Upgrade the controller first — auto-upgrade cannot fix a too-old controller. |
| Any refusal | Agent keeps its last-good spec and keeps reconciling. | — |

## Recommended order: controller first, then agents

1. **Get the new binaries.** From a release archive: `wgfleet-controller` and
   `wgfleet-agent`, unpacked beside this file, built for the archive's
   architecture.

   Point the controller at the new agent binary (needed for auto-upgrade and
   `--upgrade-agent` / UI button):
   ```yaml
   # controller.yaml
   controller:
     agent_bin: /usr/local/bin/wgfleet-agent
   ```

   All keys: [configuration.md#2-controller-the-controller-process](configuration.md#2-controller-the-controller-process)

2. **Validate the manifest.**
   ```
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   ```
   Result: exits nonzero with an error if invalid. Run BEFORE restarting — a bad
   manifest makes the controller exit at startup, and `Restart=on-failure` turns
   that into a crash loop that swapping the binary back does **not** fix.

3. **Replace the controller binary and restart.** While it is down, agents keep
   reconciling their last spec and failover keeps working.

   - Wire version unchanged → agents keep talking to it as normal.
   - Wire version changed → agents are auto-upgraded only when they fall below
     `MinSupportedWire`. A bump that keeps the previous version supported
     upgrades nothing on its own — roll those agents in the next step.

4. **Roll the agents.** Three equivalent ways:

   | Method | Command / action | Notes |
   |---|---|---|
   | Automatic | (none — happens on next `Register`) | Only agents below `MinSupportedWire`, on their next `Register` (every `reconcile_interval`, default 30 s). A merely older but still-supported agent is never touched this way. |
   | Per node | `wgfleet-controller --upgrade-agent exit-de-1 --plan` (dry-run: show upload+restart), then `wgfleet-controller --upgrade-agent exit-de-1` (apply) | — |
   | UI | node page → **Upgrade agent** | — |

   Upgrade = upload new binary + restart the agent service, then wait for the
   node to report back on the new version. The data plane (kernel WG interfaces,
   mihomo/wg-easy/blocky containers) survives the restart: **no drain is
   required** and clients are not dropped.

   If `wgfleet_node_agent_info` or the fleet page shows versions not moving,
   roll explicitly (per node or UI) — automatic only fires below
   `MinSupportedWire`.

5. **Verify.**
   ```
   wgfleet-agent --version
   ```
   Result: prints the wire version the node now speaks — confirm it matches
   what the new binaries speak before considering the roll done.

   Node page: shows the new **Agent** version, clears the `version skew` badge
   once the node re-registers.

   | Metric | Meaning |
   |---|---|
   | `wgfleet_node_agent_info{node,agent_version,wire_version}` | Per-node agent + wire version. |
   | `wgfleet_nodes{state="Ready"}` | Fleet health. |

   An agent on an older but still-supported wire keeps reconciling and is
   neither refused nor auto-upgraded, so it can silently lack behaviour the
   release relies on — certificate self-renewal, for one (see below).

## What this release changes on its own

Each release lists its own behaviour changes in its release notes — read them
before rolling, so a normal change does not read as a fault. The rules below
hold across releases.

| Rule | Detail |
|---|---|
| Agents renew their own certificates | Between 70% and 90% of the one-year lifetime, over the control plane, no operator step. An agent from before this behaviour never renews: runs to its certificate's `NotAfter` about a year after provisioning, then falls off the control plane. Recovery is SSH plus `--certs renew`. Also invisible to the certificate-expiry alert, because that metric arrives with the same agent generation. Roll stragglers before their certificates age out. |
| `fleet.awg3_key` is REQUIRED once AmneziaWG 3.x header protection is on | Triggers when `fleet.awg3` is true, OR any `exits[].awg3` is true, OR any `masters[].client_awg.awg3` is `full` (`client_awg.awg3: timers` needs no secret). Missing key → controller refuses to start. Run `--check-config` BEFORE the restart: a missing key is a startup failure and a crash loop. Set it once and never change it — rotating it re-derives the key on every 3.x tunnel and invalidates every client config in the field at once. |

```yaml
fleet:
  awg3: true
  awg3_key: file:///etc/wgfleet/awg3.key
  exits:
    - name: exit-a
      awg3: true
```

All keys: [configuration.md#3-fleet-fleet-wide-settings](configuration.md#3-fleet-fleet-wide-settings)

### Several masters

| Rule | Detail |
|---|---|
| Wire 13 | Controller first, then agents. An exit on the older agent keeps serving the master in slot 0 only |
| Non-base master on an exit with an older agent | No AmneziaWG tunnel. If that exit's active transport is AmneziaWG, the master does not route through it until the exit's agent is upgraded |
| A remote master | Upgraded by the upgrade action on its node page; a fleet-wide rolling upgrade skips masters |

Adding a master: [operations.md](operations.md#several-masters).

### Exit-initiated AmneziaWG flow

`transports.awg.exit_initiated` needs the controller, the master agent and the exit agent on wire 12. Order: controller, master agent, exit agents, then the key. Before all three are upgraded the key changes nothing. Client configs do not change. Nodes prepared before this release may lack `conntrack`: `apt-get install conntrack` on the master.

## Notes & gotchas

- **`controller.agent_bin` must be set** for auto-upgrade, `--upgrade-agent`, and
  the UI button. Without it those paths error with "no agent binary configured".
- **"Outdated" is measured against `agent_bin`, not against the controller's own
  build.** The rolling upgrade probes the version of the binary it is about to
  push. Upgrading only the controller (`deploy-master.sh --controller`, which
  warns about this) leaves the panel reading "nothing to roll". Push the agent
  binary to the controller host before rolling the fleet.
- **SSH reach is required to upgrade.** The upgrade dials the node's manifest
  SSH target, and when that fails, the node's `mgmt_addr` with the same port,
  user and key. If you removed SSH access after bootstrap, restore it before
  upgrading (or re-provision).
- **A wedged SSH path costs one node, not the run.** A path that accepts the
  connection and then swallows everything is abandoned 20 s into the handshake:
  the node's `mgmt_addr` is tried next, and only when that fails too is
  the node reported by name as untouched — it keeps the agent it had, it is
  never downgraded — and the rollout moves to the next one. `--node-timeout`
  (default `5m`) bounds everything after the dial: upload, install, restart.
- **Bumping `MinSupportedWire`** strands any agent older than the new minimum on
  its last-good spec until it is rolled. Do it only after the fleet is known to
  be past that version.
- **Store schema** evolves via `PRAGMA user_version`-tracked migrations. A
  controller upgrade migrates the existing DB in place on first open; no manual
  step. A current controller refuses a database written by a newer controller
  with a clear message, and heals a version stamp an older one lowered.
  **Rolling the controller back to an older release** can leave the
  database unable to roll forward again: take a backup first (`--backup`) and
  expect to restore it rather than to roll forward.
- **Masters** upgrade exactly like exits: restarting the master agent does not
  restart its mihomo container (containers restart only on a config change), so
  client sessions are unaffected.
  **One exception:** on a master where `client_awg.managed` has just been turned
  on, the first pass after the upgrade takes the client interface over from
  wg-easy and, a pass later, removes the wg-easy container. That is a migration
  with its own procedure and rollback: read
  [client-migration.md](client-migration.md) BEFORE upgrading such a master.
