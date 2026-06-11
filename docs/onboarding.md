# Onboarding a node — from a blank VM to `Ready`

This runbook takes a fresh Ubuntu VM (root SSH only) to a managed wgfleet node.
It assumes a single controller and the reference two-VM topology (one `master`,
one `exit`); scale the per-node steps for more.

The work splits cleanly in two:

- **OS prep** (`deploy/prepare-node.sh`) — the environmental / kernel-risky bits
  the provisioner deliberately won't do: build the AmneziaWG kernel module (DKMS)
  and join the ZeroTier overlay. Run once per VM.
- **Fleet onboarding** (`controller --provision`) — declarative: hardening,
  baseline firewall, apt deps, Docker, wgcf, the mTLS identity and the agent. The
  agent then reconciles the node to its `NodeSpec` over mTLS.

## 0. One-time controller setup

```sh
# Build the controller (or `make controller-linux` to run it on a VM).
go build -o wgfleet-controller ./cmd/wgfleet-controller

# Generate the CA at the configured pki paths (controller.yaml → pki.ca_cert/ca_key).
./wgfleet-controller --config controller.yaml --init-pki
```

Build the Linux agent that `--provision` installs on each node:

```sh
make agent-linux              # dist/wgfleet-agent-linux-amd64
make agent-linux ARCH=arm64   # for ARM VMs (Graviton, Apple-silicon Lima)
```

## 1. Prep each VM (OS-level)

Get the ZeroTier network id (`controller.yaml → controller.zerotier_network`),
then on **each** VM — directly, or as cloud-init user-data:

```sh
scp deploy/prepare-node.sh root@<vm-ip>:/root/
ssh root@<vm-ip> 'bash prepare-node.sh <zerotier-network-id>'
```

The script builds the AmneziaWG module (satisfying the provisioner's hard
pre-flight) and joins ZeroTier. Then, in **ZeroTier Central**:

1. Authorize the new member.
2. Assign it a **managed IP** — this becomes the node's `mgmt_addr`. Plan these
   in advance (e.g. `10.20.0.10` master, `10.20.0.11` exit) so the manifest and
   ZeroTier agree.

> **Why mgmt_addr matters:** every admin/metrics/DNS surface binds the ZeroTier
> address only, never the public interface (docs/DESIGN.md §9). The provisioner and
> agent also talk to the controller over this overlay.

## 2. Describe the fleet

Fill `fleet.yaml` (see `deploy/examples/controller.yaml`). Per node you need its
role, address pool, the planned `mgmt_addr`, and an SSH bootstrap target:

```yaml
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.0.10          # the ZeroTier managed IP from step 1
      ssh: { host: 203.0.113.10, user: root, key_path: ~/.ssh/id_ed25519, host_key: "ssh-ed25519 AAAA..." }
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
  exits:
    - name: exit-de-1
      region: de
      egress: warp
      # warp_mtu: 1400                 # pin if the real WARP path is < 1500
      address_pool: 10.81.0.0/24
      mgmt_addr: 10.20.0.11
      ssh: { host: 198.51.100.7, user: root, key_path: ~/.ssh/id_ed25519, host_key: "ssh-ed25519 AAAA..." }
```

> **Pin `ssh.host_key`.** Bootstrap ships the node's private mTLS key over SSH, so
> an unpinned (trust-on-first-use) dial lets a MITM capture the node's identity.
> Grab the key once the VM is up: `ssh-keyscan -t ed25519 <vm-ip>`.

## 3. Provision

Always dry-run first — `--plan` renders the full bootstrap and changes nothing:

```sh
./wgfleet-controller --config controller.yaml \
  --provision master-xa-1 --agent-bin dist/wgfleet-agent-linux-amd64 --plan
# review, then apply (drop --plan):
./wgfleet-controller --config controller.yaml \
  --provision master-xa-1 --agent-bin dist/wgfleet-agent-linux-amd64
```

Repeat for `exit-de-1`. Provisioning issues the node's mTLS cert inline, hardens
sshd, installs the baseline firewall, the apt deps, Docker and (on exits) wgcf,
installs the agent + systemd unit, and starts it. The agent then reconciles.

> Provisioning is also available from the read-only Web UI (a **Provision** button
> on Pending/Error nodes) once the controller is running.

## 4. Verify

```sh
./wgfleet-controller --config controller.yaml   # run the control plane
```

- **Web UI** (`controller.webui`, ZeroTier-only): node should move
  `Pending → Provisioning → Reconciling → Ready`, with per-check health.
- **Metrics** (`controller.metrics`): `wgfleet_nodes{state="Ready"}`.
- An exit reaches `Ready` only when its self-checks pass: fresh WG handshake,
  WARP egress actually exits via Cloudflare, DNS filter resolves.

## Decommission (reverse)

```
drain → decommission → delete
```

Drain takes the exit out of the mihomo load-balancer (existing connections
survive); decommission tears the data plane down and **wipes** the rendered
configs and key material; delete removes it from inventory. All three are UI
buttons or store flags.

## Gotchas (hard-won)

- **AmneziaWG module** is a pre-flight requirement — `prepare-node.sh` builds it.
  A kernel upgrade rebuilds it via DKMS and `modules-load.d` re-inserts it on boot.
- **`mgmt_addr` is the ZeroTier IP**, planned in advance and assigned in ZT Central.
- **WARP MTU**: if egress packets fragment / "first N requests fail", the real
  WARP path is below 1500 — pin `exits[].warp_mtu` (an earlier finding: 1320–1420).
- **First real apply touches firewall/routing.** Use a VM with out-of-band console
  access for the first run; the baseline firewall + `Table = off` keep SSH/ZT
  reachable, but verify before depending on the box.
