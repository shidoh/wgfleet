# Onboarding a node — from a blank VM to `Ready`

Takes a fresh Ubuntu VM (root SSH) to a managed wgfleet node. Assumes one
controller and the reference topology (one `master`, one `exit`); repeat the
per-node steps for more.

> Controller and master on the **same** box? See
> [colocated-controller-master.md](colocated-controller-master.md): the master is
> onboarded by hand, exits stay SSH-provisioned.

Supported OS, sizing and pinned versions: [system requirements](requirements.md).

Two stages:

- **OS prep** (`prepare-node.sh`, beside this file) — what the provisioner does
  not do: build the AmneziaWG kernel module (DKMS), cap the systemd journal, join
  the ZeroTier overlay. Run once per VM. Skipping it leaves the journal uncapped;
  a unit stuck in a log loop can then fill the disk and take the data plane down.
- **Fleet onboarding** (`controller --provision`) — hardening, baseline firewall,
  apt deps, Docker, wgcf, the mTLS identity and the agent. The agent then
  reconciles the node to its spec over mTLS.

## 0. One-time controller setup

The release archive contains both binaries; nothing to build.

```sh
# Generate the CA at the configured pki paths (controller.yaml → pki.ca_cert/ca_key).
./wgfleet-controller --config controller.yaml --init-pki
```

> **`controller.listen` must be an address agents can reach.** It is baked into each
> agent's config as the dial endpoint and seeds the server cert SAN. Bind the mgmt/ZT
> address (e.g. `10.20.0.1:8443`). Bind `0.0.0.0` only together with
> `controller.advertise` (the reachable address); otherwise agents are told to dial
> `0.0.0.0:8443`, which is undialable.

`--provision` installs a Linux agent binary on each node. Point
`controller.agent_bin` at it:

```yaml
controller:
  agent_bin: ./wgfleet-agent        # in the release archive beside the controller
```

## 1. Prep each VM (OS-level)

Get the ZeroTier network id (`controller.yaml → fleet.zerotier_network`),
then on **each** VM — directly, or as cloud-init user-data:

```sh
scp prepare-node.sh root@<vm-ip>:/root/
ssh root@<vm-ip> 'bash prepare-node.sh <zerotier-network-id>'
```

Then, in **ZeroTier Central**:

1. Authorize the new member.
2. Assign it a **managed IP** — this becomes the node's `mgmt_addr`. Plan these
   in advance (e.g. `10.20.0.10` master, `10.20.0.11` exit) so the manifest and
   ZeroTier agree.

Every admin/metrics/DNS surface binds the ZeroTier address only, never the public
interface; the provisioner and the agent also reach the controller over this overlay.

## 2. Describe the fleet

Fill `controller.yaml` (start from `examples/controller.yaml`). Per node: role,
address pool, the planned `mgmt_addr`, and an SSH bootstrap target:

```yaml
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.0.10          # the ZeroTier managed IP from step 1
      public_ip: 203.0.113.10         # WG endpoint peers dial — see note below
      ssh: { host: 203.0.113.10, port: 22, user: root, key_path: ~/.ssh/id_ed25519, host_key: "ssh-ed25519 AAAA..." }
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
      mihomo: { dashboard_disabled: false }   # see the dashboard gotcha below
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

> **Pin `ssh.host_key`.** Bootstrap ships the node's private mTLS key over SSH; an
> unpinned (trust-on-first-use) dial lets a MITM capture the node's identity. Run
> `ssh-keyscan -t ed25519 <vm-ip>` and paste the `ssh-ed25519 AAAA...` part verbatim.
>
> To skip host-key verification set `ssh.insecure_ignore_host_key: true` on that
> node, or `WGFLEET_SSH_INSECURE_HOST_KEY=1` in the controller's environment for the
> whole fleet. It is logged loudly and drops MITM protection on the bootstrap channel.
>
> **`ssh.port`** defaults to 22.
>
> **`public_ip`** is the WG endpoint peers dial. It defaults to `ssh.host`. Set it
> explicitly when `ssh.host` is not the WG endpoint (bastion, forwarded SSH port,
> private SSH path); otherwise the master renders an undialable tunnel endpoint.

## 3. Provision

> **Start the controller first (§4), then provision.** Provisioning starts the
> agent immediately and the agent dials the controller on its first reconcile;
> with no controller serving, the node sits in `Error` until the next retry
> (`reconcile_interval`, default 30s).

Dry-run first — `--plan` renders the full bootstrap and changes nothing:

```sh
./wgfleet-controller --config controller.yaml --provision master-xa-1 --plan
# review, then apply (drop --plan):
./wgfleet-controller --config controller.yaml --provision master-xa-1
```

Repeat for `exit-de-1`. Provisioning issues the node's mTLS cert, hardens sshd,
installs the baseline firewall, apt deps, Docker and (on exits) wgcf, installs the
agent + systemd unit, and starts it.

> `--agent-bin <path>` overrides `controller.agent_bin`; one of the two must be set.
>
> Provisioning is also available from the Web UI (a **Provision** button on
> Pending/Error nodes).

## 4. Verify

```sh
./wgfleet-controller --config controller.yaml   # run the control plane
```

- **Web UI** (`controller.webui`, ZeroTier-only): the node moves
  `Pending → Provisioning → Reconciling → Ready`, with per-check health.
- **Metrics** (`controller.metrics`): `wgfleet_nodes{state="Ready"}`.
- **Client credentials.** With `client_awg.managed: true` (not the default) the
  agent owns the client interface and there is no wg-easy: issue, pause, rename and
  revoke credentials on the master's page in the console, and hand each person
  their self-service link. Set the master's `public_ip`; it is the endpoint written
  into every client config.

  On a master still running wg-easy: `sudo cat /etc/wgfleet/wg-easy-admin-password`
  (username `admin`). The file does not exist once the agent has taken the
  interface over.
- An exit reaches `Ready` only when its self-checks pass: fresh WG handshake, WARP
  egress exits via Cloudflare, DNS filter resolves.

## Decommission (reverse)

```
drain → decommission → delete
```

Drain takes the exit out of the load-balancer (existing connections survive);
decommission tears the data plane down and **wipes** the rendered configs and key
material; delete removes it from inventory. All three are UI buttons.

## Gotchas

- **AmneziaWG module** is a pre-flight requirement — `prepare-node.sh` builds it.
  Re-running the script never upgrades it; `prepare-node.sh --upgrade-awg` does
  (see operations.md, "Upgrading the AmneziaWG module"). A kernel upgrade rebuilds
  it via DKMS; `modules-load.d` re-inserts it on boot.
- **`mgmt_addr` is the ZeroTier IP**, planned in advance and assigned in ZT Central.
- **WARP MTU**: if egress packets fragment / "first N requests fail", the real WARP
  path is below 1500 — pin `exits[].warp_mtu` (typically 1320–1420).
- **WARP blocked by the ISP**: `warp-egress` stays red and `wg show wgcf` shows
  `0 B received`. Confirm with `tcpdump -ni <egress-if> 'udp port 2408'` (handshake
  leaves, nothing returns) and a fresh `wgcf register` that also fails. Fix: a
  different egress network for the node; nothing to change in wgfleet.
- **First real apply touches firewall/routing.** Use a VM with out-of-band console
  access for the first run; verify SSH/ZT reachability before depending on the box.
- **mihomo dashboard needs GitHub on first run.** Where GitHub is unreachable set
  `masters[].mihomo.dashboard_disabled: true` or a reachable `mihomo.dashboard_url`.
  Default is on.
- **Master-side gotchas** (the mihomo version pin, wg-easy's cosmetic `unhealthy`,
  the master staying `Degraded` until the first exit registers) are in the
  Gotchas section of [colocated-controller-master.md](colocated-controller-master.md).
