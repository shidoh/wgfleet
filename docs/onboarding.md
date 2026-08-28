# Onboarding a node — from a blank VM to `Ready`

This runbook takes a fresh Ubuntu VM (root SSH only) to a managed wgfleet node.
It assumes a single controller and the reference two-VM topology (one `master`,
one `exit`); scale the per-node steps for more.

> Running the controller and the master on the **same** box (no separate VM)?
> See [colocated-controller-master.md](colocated-controller-master.md) — the
> master is onboarded by hand (local cert issue) while exits stay SSH-provisioned.

The work splits cleanly in two:

- **OS prep** (`deploy/prepare-node.sh`) — the environmental bits the provisioner
  deliberately won't do: build the AmneziaWG kernel module (DKMS), cap the systemd
  journal, and join the ZeroTier overlay. Run once per VM. Skipping it leaves the
  journal uncapped, so a unit stuck in a log-spewing loop can fill the disk and
  take the exit's data plane with it.
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

> **`controller.listen` must be an address agents can reach.** It is baked into each
> agent's config as the dial endpoint and seeds the server cert SAN. Bind the mgmt/ZT
> address (e.g. `10.20.0.1:8443`). Bind `0.0.0.0` ONLY together with
> `controller.advertise` (the reachable address — controller behind a NAT/LB/gateway);
> otherwise agents are told to dial `0.0.0.0:8443`, which is undialable.

Build the Linux agent that `--provision` installs on each node:

```sh
make agent-linux              # dist/wgfleet-agent-linux-amd64
make agent-linux ARCH=arm64   # for ARM VMs (Graviton, Apple-silicon Lima)
```

## 1. Prep each VM (OS-level)

Get the ZeroTier network id (`controller.yaml → fleet.zerotier_network`),
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
> address only, never the public interface. The provisioner and
> agent also talk to the controller over this overlay.

## 2. Describe the fleet

Fill `fleet.yaml` (see `deploy/examples/controller.yaml`). Per node you need its
role, address pool, the planned `mgmt_addr`, and an SSH bootstrap target:

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

> **Pin `ssh.host_key`.** Bootstrap ships the node's private mTLS key over SSH, so
> an unpinned (trust-on-first-use) dial lets a MITM capture the node's identity.
> Grab the key once the VM is up: `ssh-keyscan -t ed25519 <vm-ip>` and paste the
> `ssh-ed25519 AAAA...` part verbatim.
>
> **Need to skip host-key verification** (trusted network, fast bring-up, a stale
> pin you can't fix right now)? Set `ssh.insecure_ignore_host_key: true` on that
> node, or `WGFLEET_SSH_INSECURE_HOST_KEY=1` in the controller's environment for the
> whole fleet. It's logged loudly and trades away MITM protection on the bootstrap
> channel — prefer pinning.
>
> **`ssh.port`** defaults to 22 — set it if SSH is on another port or reached via a
> forwarded port / bastion.
>
> **`public_ip` is the WG endpoint peers actually dial.** It defaults to `ssh.host`,
> which is correct when you SSH straight to the node's public IP. Set it explicitly
> when `ssh.host` is NOT the WG endpoint — a bastion, a NAT/forwarded SSH port, or a
> private SSH path — otherwise the master would render an undialable tunnel endpoint.

## 3. Provision

> **Start the controller FIRST (see §4), then provision.** Provisioning installs
> the agent and starts it immediately (`systemctl enable --now`), and the agent
> dials the controller on its very first reconcile. If the controller is not yet
> serving, that first dial gets `connection refused` and the node sits in
> `Error`/silent until the agent's next retry (`reconcile_interval`, default 30s).
> It self-heals, but starting the controller first avoids the transient entirely.

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

> `--agent-bin` overrides `controller.agent_bin` from the config; set either so the
> provisioner knows which agent binary to install. Build it with `make agent-linux
> [ARCH=arm64]` → `dist/wgfleet-agent-linux-<arch>`.
>
> Provisioning is also available from the read-only Web UI (a **Provision** button
> on Pending/Error nodes) once the controller is running.

## 4. Verify

```sh
./wgfleet-controller --config controller.yaml   # run the control plane
```

- **Web UI** (`controller.webui`, ZeroTier-only): node should move
  `Pending → Provisioning → Reconciling → Ready`, with per-check health.
- **Metrics** (`controller.metrics`): `wgfleet_nodes{state="Ready"}`.
- **Client credentials.** With `client_awg.managed: true` — the default for a new
  fleet — the agent owns the client interface itself and there is no wg-easy: issue,
  pause, rename and revoke credentials on the master's page in the console, and hand
  each person their own self-service link. Set the master's `public_ip`; it is the
  endpoint written into every client config.

  Only on a master still running wg-easy (a fleet part-way through the migration) is
  there a wg-easy UI to log into: `sudo cat /etc/wgfleet/wg-easy-admin-password`
  (username `admin`). That file does not exist once the agent has taken the interface
  over.
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
  WARP path is below 1500 — pin `exits[].warp_mtu` (typically 1320–1420).
- **WARP blocked by the ISP**: if `warp-egress` stays red and the tunnel never comes up
  (`wg show wgcf` → `0 B received`), it may be a path/provider block of UDP to
  Cloudflare's WARP endpoint, not a wgfleet issue. Confirm with
  `tcpdump -ni <egress-if> 'udp port 2408'` (handshake leaves, nothing returns) and a
  **fresh `wgcf register` that also fails**. The fix is a different egress network for
  the node; there is nothing to change in wgfleet. (The platform sets
  `PersistentKeepalive = 25` on the WARP peer so an idle tunnel does not go cold and flap
  the health check.)
- **First real apply touches firewall/routing.** Use a VM with out-of-band console
  access for the first run; the baseline firewall + `Table = off` keep SSH/ZT
  reachable, but verify before depending on the box.
- **Pin the mihomo version**, not `:latest` — and not `Alpha` either, since a moving tag
  defeats the pin. The code default is now `v1.19.30`, which carries AmneziaWG 2.0 (it
  shipped in `v1.19.14`). ⚠️ Do not fall back to `v1.19.27` or older: those **crash-loop on
  AmneziaWG-2.0 master↔exit junk**. The AmneziaWG-param safety is otherwise handled
  by the platform: it floors `Jmin ≥ S4` so no obfuscation junk packet is short enough to trip
  the unguarded S4-strip in older `amneziawg-go` (mihomo) builds. (This was a real crash-loop —
  our derivation once produced `Jmin=22` with `S4=52`, panicking mihomo on a 41-byte junk packet;
  fixed in the derivation, so any mihomo/kernel pairing is safe now.)
- **mihomo dashboard needs GitHub on first run.** The master's mihomo fetches the web
  dashboard zip from GitHub on first start; if GitHub is unreachable it fails and can
  crash-loop. Set `masters[].mihomo.dashboard_disabled: true` (or a reachable
  `mihomo.dashboard_url`) where GitHub is blocked. Default is on.
- **`wg-easy` shows `unhealthy` in `docker ps` — cosmetic.** Its Docker healthcheck runs
  `wg show`, which can't see AmneziaWG interfaces. The real signal is the agent's
  `client-wg` check; ignore the container flag.
- **The master converges after the exits register.** It can't render its mihomo proxies
  until each exit has published its public key, so on first start the master may show
  `Error`/`Degraded` ("no exit tunnels yet") for ~1–2 reconcile intervals, then go `Ready`.
