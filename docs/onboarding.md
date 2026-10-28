# Onboarding a node — from a blank VM to `Ready`

Takes a fresh Ubuntu VM (root SSH) to a managed wgfleet node. Assumes one
controller and the reference topology (one `master`, one `exit`); repeat the
per-node steps for more.

> Controller and master on the **same** box? See
> [colocated-controller-master.md](colocated-controller-master.md): the master is
> onboarded by hand, exits stay SSH-provisioned.

Supported OS, sizing and pinned versions: [system requirements](requirements.md).

## Preconditions

- [ ] Release archive with `wgfleet-controller` and `wgfleet-agent` (no build step)
- [ ] One fresh Ubuntu VM per node, root SSH access
- [ ] ZeroTier network id (`controller.yaml → fleet.zerotier_network`)
- [ ] `mgmt_addr` planned per node (ZeroTier managed IP, e.g. `10.20.0.10` master, `10.20.0.11` exit)
- [ ] `public_ip` known per node (defaults to `ssh.host`; set explicitly if different)
- [ ] Out-of-band console access on the first-run VM — first apply touches firewall/routing

| Stage | Tool | Does |
|---|---|---|
| OS prep | `prepare-node.sh` (beside this file) | builds the AmneziaWG kernel module (DKMS); caps the systemd journal; joins the ZeroTier overlay. Run once per VM. |
| Fleet onboarding | `controller --provision` | hardening, baseline firewall, apt deps, Docker, wgcf, the mTLS identity, installs the agent. Agent then reconciles the node to its spec over mTLS. Re-runnable: wgcf is compared against the version this build pins and replaced when it differs, so a node provisioned before a bump catches up instead of staying on whatever it already had. |

Skipping OS prep leaves the journal uncapped: a unit stuck in a log loop can then
fill the disk and take the data plane down.

## 0. One-time controller setup

The release archive contains both binaries; nothing to build.

1. Generate the CA:

   ```sh
   ./wgfleet-controller --config controller.yaml --init-pki
   ```

   Expected: CA written to the configured pki paths (`controller.yaml → pki.ca_cert/ca_key`).

2. Set `controller.listen` to an address agents can reach — it is baked into
   each agent's config as the dial endpoint and seeds the server cert SAN.
   Bind the mgmt/ZT address (e.g. `10.20.0.1:8443`). Bind `0.0.0.0` only
   together with `controller.advertise` (the reachable address); otherwise
   agents are told to dial `0.0.0.0:8443`, which is undialable.

3. Point `controller.agent_bin` at the agent binary:

   ```yaml
   controller:
     agent_bin: ./wgfleet-agent        # in the release archive beside the controller
   ```

   All keys: [configuration.md#2-controller-the-controller-process](configuration.md#2-controller-the-controller-process)

   Expected: `--provision` installs this binary on each node.

## 1. Prep each VM (OS-level)

1. Get the ZeroTier network id (`controller.yaml → fleet.zerotier_network`).

2. On **each** VM — directly, or as cloud-init user-data:

   ```sh
   scp prepare-node.sh root@<vm-ip>:/root/
   ssh root@<vm-ip> 'bash prepare-node.sh <zerotier-network-id>'
   ```

   Expected: AWG kernel module built, journal capped, node visible in ZeroTier
   Central as an unauthorized member.

3. In **ZeroTier Central**:
   1. Authorize the new member.
   2. Assign it a **managed IP** — this becomes the node's `mgmt_addr`. Use
      the value planned in the preconditions checklist so the manifest and
      ZeroTier agree.

Every admin/metrics/DNS surface binds the ZeroTier address only, never the public
interface; the provisioner and the agent also reach the controller over this overlay.

## 2. Describe the fleet

1. Fill `controller.yaml` (start from `examples/controller.yaml`). Per node: role,
   address pool, the planned `mgmt_addr`, and an SSH bootstrap target:

   ```yaml
   fleet:
     masters:
       - name: master-xa-1
         mgmt_addr: 10.20.0.10          # the ZeroTier managed IP from step 1
         public_ip: 203.0.113.10         # WG endpoint peers dial — see note below
         ssh: { host: 203.0.113.10, port: 22, user: root, key_path: ~/.ssh/id_ed25519, host_key: "ssh-ed25519 AAAA..." }
         client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
         mihomo: { dashboard_disabled: false }   # see the dashboard row in the symptom table below
     exits:
       - name: exit-de-1
         region: de
         egress: warp
         # warp_mtu: 1400                 # pin if the real WARP path is < 1500
         address_pool: 10.81.0.0/24
         mgmt_addr: 10.20.0.11
         public_ip: 198.51.100.7          # WG endpoint the master dials this exit at
         ssh: { host: 198.51.100.7, port: 22, user: root, key_path: ~/.ssh/id_ed25519, host_key: "ssh-ed25519 AAAA..." }
   ```

   All keys: [configuration.md#4-fleetmasters-master-nodes](configuration.md#4-fleetmasters-master-nodes),
   [configuration.md#5-fleetexits-exit-nodes](configuration.md#5-fleetexits-exit-nodes)

2. Pin `ssh.host_key`. Run `ssh-keyscan -t ed25519 <vm-ip>` and paste the
   `ssh-ed25519 AAAA...` part verbatim. Bootstrap ships the node's private mTLS
   key over SSH; an unpinned (trust-on-first-use) dial lets a MITM capture it.

   - To skip host-key verification: `ssh.insecure_ignore_host_key: true` on
     that node, or `WGFLEET_SSH_INSECURE_HOST_KEY=1` in the controller's
     environment for the whole fleet. Logged loudly; drops MITM protection on
     the bootstrap channel.
   - `ssh.port` defaults to 22.
   - `public_ip` defaults to `ssh.host`. Set it explicitly when `ssh.host` is
     not the WG endpoint (bastion, forwarded SSH port, private SSH path);
     otherwise the master renders an undialable tunnel endpoint.

## 3. Provision

Start the controller first (§4), then provision. Provisioning starts the
agent immediately and the agent dials the controller on its first reconcile;
with no controller serving, the node sits in `Error` until the next retry
(`reconcile_interval`, default 30s).

1. Dry-run — `--plan` renders the full bootstrap and changes nothing:

   ```sh
   ./wgfleet-controller --config controller.yaml --provision master-xa-1 --plan
   ```

2. Apply (drop `--plan`):

   ```sh
   ./wgfleet-controller --config controller.yaml --provision master-xa-1
   ```

   Expected: node's mTLS cert issued, sshd hardened, baseline firewall
   installed, apt deps, Docker and (on exits) wgcf installed, agent +
   systemd unit installed and started.

3. Repeat for `exit-de-1` (and every other node).

`--agent-bin <path>` overrides `controller.agent_bin`; one of the two must be
set. Provisioning is also available from the Web UI (a **Provision** button
on Pending/Error nodes).

## 4. Verify

1. Run the control plane:

   ```sh
   ./wgfleet-controller --config controller.yaml
   ```

2. **Web UI** (`controller.webui`, ZeroTier-only). Expected: node state moves
   `Pending → Provisioning → Reconciling → Ready`, with per-check health.

3. **Metrics** (`controller.metrics`). Expected: `wgfleet_nodes{state="Ready"}`.

4. **Client credentials.**

   ```yaml
   fleet:
     masters:
       - name: master-xa-1
         public_ip: 203.0.113.10         # the endpoint every client config carries
         client_awg:
           address_pool: 10.80.0.0/24    # required
   ```

   All keys: [configuration.md#client_awg-the-client-facing-amneziawg-listener](configuration.md#client_awg-the-client-facing-amneziawg-listener)

   - The agent owns the client interface `wg0`. Issue, pause, rename and
     revoke credentials on the master's page in the console; hand each person
     their self-service link.
   - Set the master's `public_ip` — it is the endpoint written into every
     client config.

5. An exit reaches `Ready` only when its self-checks pass: fresh WG
   handshake, WARP egress exits via Cloudflare, DNS filter resolves.

## Decommission (reverse)

```
drain → decommission → delete
```

| Action | Effect |
|---|---|
| Drain | takes the exit out of the load-balancer; existing connections survive |
| Decommission | tears the data plane down; **wipes** the rendered configs and key material |
| Delete | removes the node from inventory |

All three are UI buttons.

## Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| AWG module never updates after re-running `prepare-node.sh` | the script builds the module once (DKMS) and never upgrades it | `prepare-node.sh --upgrade-awg` (see [operations.md](operations.md), "Upgrading the AmneziaWG module"); a kernel upgrade rebuilds it via DKMS, `modules-load.d` re-inserts it on boot |
| Manifest `mgmt_addr` and node disagree | `mgmt_addr` is the ZeroTier IP and must be planned before onboarding | plan `mgmt_addr` per node in advance, assign it as the managed IP in ZT Central (step 1) |
| Egress packets fragment / first N requests fail | real WARP path MTU is below 1500 | pin `exits[].warp_mtu` (typically 1320–1420) |
| `warp-egress` stays red; `wg show wgcf` shows `0 B received` | WARP blocked by the ISP | confirm with `tcpdump -ni <egress-if> 'udp port 2408'` (handshake leaves, nothing returns) and a fresh `wgcf register` that also fails; use a different egress network for the node — nothing to change in wgfleet |
| mihomo dashboard fails to start on first run | dashboard fetch needs GitHub reachability; default is on (`dashboard_disabled: false`) | set `masters[].mihomo.dashboard_disabled: true`, or point `mihomo.dashboard_url` at a reachable mirror |

Master-side gotchas (the mihomo version pin, the master staying `Degraded` until the first exit registers) are in the
Gotchas section of [colocated-controller-master.md](colocated-controller-master.md).
