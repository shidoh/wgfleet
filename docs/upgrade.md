# Upgrading a wgfleet deployment

This is the operator runbook for rolling a new build of wgfleet across a running
fleet. See ADR-0019 for the design and rationale.

## Two versions, one of which matters for compatibility

| Version | Where | Purpose |
|---|---|---|
| **Build version** | `internal/version`, stamped from git by the Makefile | Human/observability. Shown by `--version`, in the UI, and in `wgfleet_node_agent_info`. |
| **Wire-contract version** | `internal/api.WireContractVersion` (a constant) | The compatibility key. Controller and agent must agree within `[MinSupportedWire .. WireContractVersion]`. |

A new release that only changes behaviour the agent already understands keeps the
same wire version. **Bump `WireContractVersion` whenever an agent must understand
something new to converge correctly** (a new `NodeSpec` field's semantics, a
changed field meaning). Forgetting to bump it reintroduces the silent-skew hazard
ADR-0019 exists to prevent.

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
   - If the wire version did **not** change, agents keep talking to it as normal.
   - If the wire version **did** change, agents now report an older wire version;
     the controller refuses them and (since they are "too old") **auto-upgrades
     each one** as it checks in. You can also drive upgrades explicitly (next
     step) instead of waiting.

3. **Roll the agents.** Three equivalent ways — pick one:

   - **Automatic:** do nothing; the gate auto-upgrades each too-old agent on its
     next `Register` (every `reconcile_interval`, default 60s).
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
- **SSH reach is required to upgrade.** The upgrade reuses the node's manifest
  SSH target — the same channel bootstrap used. If you decommissioned SSH access
  after bootstrap, restore it before upgrading (or re-provision).
- **Bumping `MinSupportedWire`** strands any agent older than the new minimum on
  its last-good spec until it is rolled. Do it deliberately and only after the
  fleet is known to be past that version.
- **Store schema** evolves via `PRAGMA user_version`-tracked migrations
  (append-only). A controller upgrade that adds columns migrates the existing DB
  in place on first open; no manual step.
- **Masters** upgrade exactly like exits — restarting the master agent does not
  restart its mihomo/wg-easy containers (those only restart on a config change),
  so client sessions are unaffected.
