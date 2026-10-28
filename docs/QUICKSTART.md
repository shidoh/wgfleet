# wgfleet quickstart

From two blank Ubuntu servers to a working VPN in about 30 minutes.

Annotated long form: [colocated-controller-master.md](colocated-controller-master.md)
(master), [onboarding.md](onboarding.md) (exits).

---

## What you are building

```
 your phone/laptop  ──AmneziaWG──►  MASTER  ──AmneziaWG──►  EXIT  ──►  internet
                                  (near you)              (abroad)
```

- **Master** — server your devices connect to; also runs the controller and the
  Web UI.
- **Exit** — server your traffic actually leaves from. Add more later; the
  master load-balances between them.

## What you need

- [ ] **2+ servers**, Ubuntu 24.04, root SSH access, each with a public IP.
      1 vCPU / 1 GB is enough for an exit; give the master 2 vCPU. Older than
      24.04 is best effort — check [requirements.md](requirements.md) first.
- [ ] A free **ZeroTier** account: <https://my.zerotier.com> — wgfleet's
      private management network; no admin port is exposed to the internet.
- [ ] The **release archive** for each server's CPU:
      `wgfleet-<version>-linux-amd64.tar.gz` (Intel/AMD) or
      `wgfleet-<version>-linux-arm64.tar.gz` (ARM/Ampere/Graviton). Check with
      `uname -m` on the server: `x86_64` → amd64, `aarch64` → arm64. Unpacks
      into `wgfleet-linux-<arch>`. `<version>` below stands for the release
      you downloaded (e.g. `v0.2.0`).
- [ ] Optional, for backups: **`age`** on the master (`apt install age`).
      `--backup`/`--restore` shell out to it and fail without it;
      `--check-config` warns when it is missing.
- [ ] Root shell on every server: `sudo -i`. Every command below runs as root.

---

## Step 1 — Create the ZeroTier network

1. <https://my.zerotier.com> → **Create A Network**.
2. Copy the 16-character **Network ID** (e.g. `8056c2e21c000001`) — you need
   it on every server.

Keep the tab open — you come back to authorize each server (Step 3, Step 7).

## Step 2 — Install the master

1. Copy the archive and unpack it:
   ```bash
   scp wgfleet-<version>-linux-amd64.tar.gz root@<MASTER-IP>:/root/
   ssh root@<MASTER-IP>
   tar xzf wgfleet-<version>-linux-amd64.tar.gz
   cd wgfleet-linux-amd64
   ```
2. Run the installer — installs the AmneziaWG kernel module, ZeroTier,
   Docker, the two binaries, the systemd services and config templates. Does
   not start anything yet.
   ```bash
   ZT_NETWORK=<NETWORK-ID> PUBLIC_IP=<MASTER-IP> ./install.sh
   ```
   Expect: a few minutes (it compiles a kernel module). Safe to re-run if it
   fails.

## Step 3 — Authorize the master in ZeroTier

1. ZeroTier Central → your network → **Members** → tick **Auth?** on the new
   member.
2. In **Managed IPs**, give it a fixed address — write it down (e.g.
   `10.147.20.10`). This is the master's **management address**.
3. Confirm on the server:
   ```bash
   zerotier-cli listnetworks     # should show OK and your 10.147.x.x address
   ip -4 addr show | grep 10.147 # the address is on a zt* interface
   ```

## Step 4 — Fill in the config

1. ```bash
   nano /etc/wgfleet/controller.yaml
   ```
   Replace every `<placeholder>` (every other key you can set is in
   `CONFIGURATION.md`):

   | Placeholder | Value |
   |---|---|
   | `<mgmt-zt-ip>` | the ZeroTier address from Step 3 (e.g. `10.147.20.10`) |
   | `<public-ip>` | the master's public IP |
   | `<zt-network-id>` | your ZeroTier Network ID |

2. Set the same management address in the agent config:
   ```bash
   nano /etc/wgfleet/agent.yaml
   ```

## Step 5 — Start the master

```bash
# create the internal certificate authority and the master's own identity
wgfleet-controller --config /etc/wgfleet/controller.yaml --init-pki
wgfleet-controller --config /etc/wgfleet/controller.yaml \
    --issue-node master-1 --issue-out /etc/wgfleet
chmod 600 /etc/wgfleet/ca.key

# pick a Web UI password
wgfleet-controller --config /etc/wgfleet/controller.yaml --set-admin-password

systemctl enable --now wgfleet-controller wgfleet-agent
systemctl status wgfleet-controller wgfleet-agent
```

Expect: `Degraded` for 1–2 minutes — with no exit declared, mihomo has
nothing to balance and its health check fails; the client interface,
nftables and routing converge normally. Turns `Ready` once Step 7 registers
the first exit. Verify:

```bash
journalctl -u wgfleet-agent -n 30 --no-pager
```

## Step 6 — Open the Web UI

The UI is bound to localhost only — tunnel it from your own machine:

```bash
ssh -L 9000:127.0.0.1:9000 root@<MASTER-IP>
```

Open <http://127.0.0.1:9000>, log in with the Step 5 password. Expect: the
master node, `Degraded` until Step 7 adds an exit.

## Step 7 — Add an exit server

1. OS prep on the **exit**, join the same ZeroTier network:
   ```bash
   scp wgfleet-<version>-linux-amd64.tar.gz root@<EXIT-IP>:/root/
   ssh root@<EXIT-IP>
   tar xzf wgfleet-<version>-linux-amd64.tar.gz
   ./wgfleet-linux-amd64/prepare-node.sh <NETWORK-ID>
   ```
2. Authorize it in ZeroTier Central exactly like Step 3; note its managed IP
   (e.g. `10.147.20.11`). Nothing else is installed by hand — the master does
   the rest over SSH.
3. On the **master**, edit the config:
   ```bash
   nano /etc/wgfleet/controller.yaml
   ```
   Replace the whole `exits: []` line with the block below (items cannot be
   pasted under an empty `[]`):
   ```yaml
     exits:
       - name: exit-1
         region: de                    # free-form label
         egress: warp                  # leave via Cloudflare WARP
         # warp_mtu: 1380              # leave unset: the agent probes the path daily; pin only when it is below 1500
         address_pool: 10.81.0.0/24    # must be unique per exit
         mgmt_addr: "10.147.20.11"     # the exit's ZeroTier address
         ssh:
           host: "<EXIT-IP>"
           port: 22
           user: root
           key_path: "/root/.ssh/id_ed25519"
           # host_key: "ssh-ed25519 AAAA..."   # recommended, see below
   ```

   All keys: [configuration.md#5-fleetexits-exit-nodes](configuration.md#5-fleetexits-exit-nodes)
4. Recommended — pin the exit's SSH host key: provisioning ships the node's
   private identity over this connection.
   ```bash
   ssh-keyscan -t ed25519 <EXIT-IP>   # run on the master
   ```
   Paste the `ssh-ed25519 AAAA...` part into `host_key`. Without it, wgfleet
   trusts the key it sees on first connection and logs a warning.
5. The master needs SSH key access to the exit. If you have no key yet:
   ```bash
   ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519
   ssh-copy-id -i /root/.ssh/id_ed25519 root@<EXIT-IP>
   ```
6. Apply and provision:
   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1 --plan  # preview
   wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1         # do it
   ```
   Expect: the exit appears in the Web UI and turns `Ready` in a couple of
   minutes.

Repeat this step for every additional exit (new name, new `address_pool`).

## Step 8 — Connect your devices

wgfleet issues client credentials itself; the agent carries the client
interface `wg0`. Client keys:
[configuration.md#client_awg-the-client-facing-amneziawg-listener](configuration.md#client_awg-the-client-facing-amneziawg-listener)

1. Restart the controller (`--check-config` first — see [CLI.md](cli.md)).
2. Web UI → master → **AWG CLIENTS** → issue one. You get a `.conf` to
   download and a QR to scan.
3. Import it with the **AmneziaWG** app — iOS, Android or desktop, *not* the
   plain WireGuard app: it cannot read the obfuscation parameters.

Optional — a permanent self-service link instead of a file: set
`controller.client_portal` **together with** `controller.client_portal_url`
(see `CONFIGURATION.md`). Setting one without the other is a startup error,
which under `Restart=on-failure` becomes a restart loop — run
`--check-config` before you restart the controller.

```yaml
controller:
  client_portal: 10.147.20.10:9001             # the master's mgmt address
  client_portal_url: https://vpn.example.org
fleet:
  masters:
    - name: master-1
      client_admin_ports: [9001]               # so clients can reach it
```

All keys: [configuration.md#2-controller-the-controller-process](configuration.md#2-controller-the-controller-process)

With the portal set, prefer a **device** over a bare credential: Web UI →
**Devices** → create one. It gets one subscription link for a mihomo app
(FlClash, ClashMetaForAndroid, ClashX Meta, Clash Verge Rev) that carries
AmneziaWG and VLESS and switches between them. Procedure:
[operations.md#client-devices](operations.md#client-devices).

Done. Your traffic now goes device → master → exit → internet.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Install failed on the kernel module | `apt-get install -y linux-headers-$(uname -r)` and re-run `./install.sh` |
| Node stuck at `Reconciling` for >5 min | `journalctl -u wgfleet-agent -n 50 --no-pager` on that node |
| Master `Degraded` right after start, journal says `spec rejected, keeping the last-good config: mihomo render: no exit tunnels` | normal until the first exit registers (step 7); the rest of the master converges meanwhile |
| Web UI unreachable | the SSH tunnel from step 6 must stay open |
| Client connects but no websites | you used the plain WireGuard app — use **AmneziaWG** |
| Exit provisioning fails on SSH | test `ssh -i /root/.ssh/id_ed25519 root@<EXIT-IP>` from the master first |
| None of the above explains it, and you need to send someone diagnostics with no access to your servers | `wgfleet-agent --support-bundle` (or `wgfleet-controller --support-bundle --fleet`) — see `SUPPORT-BUNDLE.md` in this archive |

Useful commands on any node:

```bash
systemctl status wgfleet-agent
journalctl -u wgfleet-agent -f
wgfleet-agent --config /etc/wgfleet/agent.yaml --once --plan   # dry run: what would change
```

## Next: RU / non-RU split tunnel + DNS filtering

- The setup above sends **all** client traffic through the exit.
- To keep Russian sites direct and route only the rest abroad, plus filter
  ads/trackers on DNS, use
  [`controller-split-ru.yaml`](../deploy/examples/controller-split-ru.yaml)
  and its walkthrough,
  [RU split tunnel + DNS filtering](recipes/ru-split-tunnel-dns-filter.md)
  (both in this archive). It changes only a handful of keys from the setup
  above.

## Every configuration option

- `CONFIGURATION.md` in this archive is the complete reference: every key in
  `controller.yaml` and `agent.yaml`, with its type, default and meaning,
  plus links to the upstream documentation of every third-party component
  wgfleet drives (mihomo, blocky, xray/REALITY, wgcf, ZeroTier) for
  the settings passed through via `overrides` and `extra_files`.
- Fully annotated reference configs are in `examples/` inside the archive;
  every key listed in `CONFIGURATION.md` appears there too, commented.
