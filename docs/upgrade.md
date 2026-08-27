# Upgrading a wgfleet deployment

This is the operator runbook for rolling a new build of wgfleet across a running
fleet. The controller never pushes: an agent asks for its spec when it is ready
for one, which is what lets a node that cannot be reached keep serving its last
good configuration instead of stalling on a delivery it never got.

## Two versions, one of which matters for compatibility

| Version | Where | Purpose |
|---|---|---|
| **Build version** | `internal/version`, stamped from git by the Makefile | Human/observability. Shown by `--version`, in the UI, and in `wgfleet_node_agent_info`. |
| **Wire-contract version** | `internal/api.WireContractVersion` (a constant) | The compatibility key. Controller and agent must agree within `[MinSupportedWire .. WireContractVersion]`. |

A new release that only changes behaviour the agent already understands keeps the
same wire version. **Bump `WireContractVersion` whenever an agent must understand
something new to converge correctly** (a new `NodeSpec` field's semantics, a
changed field meaning). Forgetting to bump it reintroduces the silent-skew hazard
the pull-based design exists to prevent.

Check what a binary speaks:

```
wgfleet-controller --version
wgfleet-agent --version
```

## What happens on a version mismatch

The agent sends its wire + build version as gRPC metadata on every call. The
controller gates `Register` and `PullSpec`:

- **Compatible** → served normally; the controller records the agent's version
  (visible in the UI node page and `wgfleet_node_agent_info`).
- **Agent too old / unknown** (behind the controller) → refused with
  `FailedPrecondition`, node marked `Degraded` ("agent wire vN …"), and an
  **auto-upgrade is triggered** (the controller pushes the configured agent
  binary over SSH and restarts the agent). Requires `controller.agent_bin` set
  and SSH reach to the node.
- **Agent too new** (controller behind) → refused; **upgrade the controller
  first**. Auto-upgrade cannot fix a too-old controller.

A refused agent keeps its last-good spec and keeps reconciling — the control
plane refusing service does not break the data plane.

## Recommended order: controller first, then agents

1. **Build the new binaries** (version is stamped from git):

   ```
   make controller-linux ARCH=amd64      # if co-located / self-hosted controller
   make agent-linux       ARCH=amd64      # agent for the fleet (set ARCH per node)
   ```

   Point the controller at the new agent binary so auto-upgrade and the
   `--upgrade-agent` / UI button use it:

   ```yaml
   # controller.yaml
   controller:
     agent_bin: /opt/wgfleet/dist/wgfleet-agent-linux-amd64
   ```

2. **Upgrade the controller.** Replace its binary and restart it. While it is
   down, agents keep reconciling their last spec (and keep failover working).
   Validate the manifest first — a typo makes the controller exit at startup, and
   `Restart=on-failure` turns that into a crash loop of the whole control plane
   that swapping the binary back does **not** fix:

   ```
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   ```

   - If the wire version did **not** change, agents keep talking to it as normal.
   - If the wire version **did** change, what happens depends on whether the OLD
     version is still supported. Agents are auto-upgraded only when the controller
     considers them INCOMPATIBLE — i.e. below `MinSupportedWire`. A bump that keeps
     the previous version supported upgrades nothing on its own; those agents keep
     running happily on the old contract until you roll them (next step).

3. **Roll the agents.** Three equivalent ways — pick one:

   - **Automatic — only below `MinSupportedWire`:** an agent the controller
     considers incompatible is upgraded on its next `Register` (every
     `reconcile_interval`, default 30s). A merely *older but still supported*
     agent is never touched this way, so do not wait for something that will not
     happen — check `wgfleet_node_agent_info` or the fleet page, and if the
     versions are not moving, roll them explicitly.
   - **Per node, explicitly:**

     ```
     wgfleet-controller --upgrade-agent exit-de-1 --plan   # dry-run: show upload+restart
     wgfleet-controller --upgrade-agent exit-de-1          # apply
     ```

   - **From the UI:** open the node page → **Upgrade agent**.

   The upgrade is just *upload new binary + restart the service*. The data plane
   (kernel WG interfaces, mihomo/wg-easy/blocky containers) survives the restart,
   so **no drain is required** and clients are not dropped.

4. **Verify.** Each node's page shows the new **Agent** version and clears the
   `version skew` badge once it re-registers. Watch:

   ```
   wgfleet_node_agent_info{node,agent_version,wire_version}   # per-node versions
   wgfleet_nodes{state="Ready"}                               # fleet health
   ```

## Notes & gotchas

- **`controller.agent_bin` must be set** for auto-upgrade, `--upgrade-agent`, and
  the UI button. Without it those paths error clearly ("no agent binary
  configured").
- **"Outdated" is measured against `agent_bin`, not against the controller's own
  build.** The rolling upgrade probes the version of the binary it is about to
  push and selects nodes against that. So upgrading only the controller — which
  `deploy-master.sh --controller` does, and warns about — correctly leaves the
  panel reading "nothing to roll" rather than offering an upgrade that would
  reinstall the version every node already has. Push the agent binary to the
  controller host before rolling the fleet.
- **SSH reach is required to upgrade.** The upgrade reuses the node's manifest
  SSH target — the same channel bootstrap used. If you decommissioned SSH access
  after bootstrap, restore it before upgrading (or re-provision).
- **Bumping `MinSupportedWire`** strands any agent older than the new minimum on
  its last-good spec until it is rolled. Do it deliberately and only after the
  fleet is known to be past that version.
- **This release adds a key that is REQUIRED once AmneziaWG 3.x is on.** If
  `fleet.awg3` or any `exits[].awg3` is true, the controller now refuses to start
  without `fleet.awg3_key` — and the header-protection key it derives is a
  DIFFERENT value from the one your tunnels use today, because it is now keyed on
  that secret instead of a salt compiled into the binary. Setting it flips both
  ends of every 3.x master↔exit tunnel, each on its own pull, so expect up to one
  `reconcile_interval` of downtime per exit. Run `--check-config` BEFORE the
  restart, not after: a missing or unresolvable key is a startup failure, and
  `Restart=on-failure` turns that into a crash loop that swapping the binary back
  does not fix.
- **Store schema** evolves via `PRAGMA user_version`-tracked migrations
  (append-only). A controller upgrade that adds columns migrates the existing DB
  in place on first open; no manual step.
  **Rolling the controller BACK is only safe from a build that carries this
  paragraph.** An older controller stamps the schema version down to its own
  count, and until the migrations were made replayable, rolling forward again
  then failed permanently on an `ALTER TABLE` that had already run — a crash loop
  with no way out but hand-editing `user_version`. Current builds detect a
  database written by a newer controller and refuse it with a clear message
  instead, and heal a stamp an older one lowered. If you are rolling back to a
  release older than that, take a backup first (`--backup`) and expect to restore
  it rather than to roll forward.
- **Masters** upgrade exactly like exits — restarting the master agent does not
  restart its mihomo container (containers only restart on a config change), so
  client sessions are unaffected.
  **One exception:** on a master where `client_awg.managed` has just been turned
  on, the first pass after the upgrade takes the client interface over from
  wg-easy and, a pass later, removes the wg-easy container. That is a migration,
  not an upgrade, and it has its own procedure and its own rollback — read
  [client-migration.md](client-migration.md) BEFORE upgrading such a master.
