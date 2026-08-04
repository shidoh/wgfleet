# wgfleet quickstart

From two blank Ubuntu servers to a working VPN in about 30 minutes.

This is the short path. For the reasoning behind each step see
[colocated-controller-master.md](colocated-controller-master.md) (master) and
[onboarding.md](onboarding.md) (exits).

---

## What you are building

```
 your phone/laptop  ──AmneziaWG──►  MASTER  ──AmneziaWG──►  EXIT  ──►  internet
                                  (near you)              (abroad)
```

- **Master** — the server your devices connect to. It also runs the controller
  (the brain) and the Web UI.
- **Exit** — the server your traffic actually leaves from. You can add more
  later; the master load-balances between them.

## What you need

- **2 servers** (or more), Ubuntu 22.04/24.04, **root SSH access**, each with a
  public IP. 1 vCPU / 1 GB RAM is enough for an exit; give the master 2 vCPU.
- A free **ZeroTier** account — <https://my.zerotier.com>. wgfleet uses it as a
  private management network so no admin port is ever exposed to the internet.
- The release archive for your CPU, from the Releases page:
  `wgfleet-<version>-linux-amd64.tar.gz` (Intel/AMD) or
  `wgfleet-<version>-linux-arm64.tar.gz` (ARM / Ampere / Graviton). Check with
  `uname -m` on the server: `x86_64` → amd64, `aarch64` → arm64. The commands
  below use `<version>` as a stand-in — substitute the release you downloaded
  (e.g. `v0.2.0`); the folder it unpacks into is always `wgfleet-linux-<arch>`.

> Every command below runs as **root** on the server (`sudo -i` first).

---

## Step 1 — Create the ZeroTier network

1. Log in to <https://my.zerotier.com> → **Create A Network**.
2. Copy the 16-character **Network ID** (e.g. `8056c2e21c000001`). You need it
   on every server.

Leave the tab open — you will come back to authorize each server.

## Step 2 — Install the master

Copy the archive to the master server and unpack it:

```bash
scp wgfleet-<version>-linux-amd64.tar.gz root@<MASTER-IP>:/root/
ssh root@<MASTER-IP>
tar xzf wgfleet-<version>-linux-amd64.tar.gz
cd wgfleet-linux-amd64
```

Run the installer. It installs the dependencies (AmneziaWG kernel module,
ZeroTier, Docker), the two binaries, the systemd services and config templates.
It does **not** start anything yet.

```bash
ZT_NETWORK=<NETWORK-ID> PUBLIC_IP=<MASTER-IP> ./install.sh
```

Takes a few minutes (it compiles a kernel module). Safe to re-run if it fails.

## Step 3 — Authorize the master in ZeroTier

Back in the ZeroTier tab, on your network page → **Members**: a new member
appeared.

1. Tick **Auth?**.
2. In the **Managed IPs** column, give it a fixed address — write down
   `10.147.20.10` (or whatever ZeroTier offers). This is the master's
   **management address**.

On the server, confirm it arrived:

```bash
zerotier-cli listnetworks     # should show OK and your 10.147.x.x address
ip -4 addr show | grep 10.147 # the address is on a zt* interface
```

## Step 4 — Fill in the config

```bash
nano /etc/wgfleet/controller.yaml
```

Replace every `<placeholder>` (see `CONFIGURATION.md` for every other key you can set):

| Placeholder | Value |
|---|---|
| `<mgmt-zt-ip>` | the ZeroTier address from step 3 (e.g. `10.147.20.10`) |
| `<public-ip>` | the master's public IP |
| `<zt-network-id>` | your ZeroTier Network ID |

Then the agent config — the same management address:

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

Give it 1–2 minutes. The master goes `Reconciling → Ready` once its containers
are up. Check:

```bash
journalctl -u wgfleet-agent -n 30 --no-pager
```

## Step 6 — Open the Web UI

The UI is bound to localhost only. Tunnel it from your own machine:

```bash
ssh -L 9000:127.0.0.1:9000 root@<MASTER-IP>
```

Then open <http://127.0.0.1:9000> and log in with the password from step 5.
You should see the master node, `Ready`.

## Step 7 — Add an exit server

On the **exit** server, do the OS prep and join the same ZeroTier network:

```bash
scp wgfleet-<version>-linux-amd64.tar.gz root@<EXIT-IP>:/root/
ssh root@<EXIT-IP>
tar xzf wgfleet-<version>-linux-amd64.tar.gz
./wgfleet-linux-amd64/prepare-node.sh <NETWORK-ID>
```

Authorize it in ZeroTier Central exactly like step 3 and note its managed IP
(e.g. `10.147.20.11`). Nothing else is installed by hand — the master does the
rest over SSH.

Back on the **master**, add the exit to the config:

```bash
nano /etc/wgfleet/controller.yaml
```

```yaml
  exits:
    - name: exit-1
      region: de                    # free-form label
      egress: warp                  # leave via Cloudflare WARP
      warp_mtu: 1380
      address_pool: 10.81.0.0/24    # must be unique per exit
      mgmt_addr: "10.147.20.11"     # the exit's ZeroTier address
      ssh:
        host: "<EXIT-IP>"
        port: 22
        user: root
        key_path: "/root/.ssh/id_ed25519"
        # host_key: "ssh-ed25519 AAAA..."   # recommended, see below
```

> **Recommended:** pin the exit's SSH host key. Provisioning ships the node's
> private identity over this connection, so an unverified first dial could in
> principle be intercepted. Get the line with
> `ssh-keyscan -t ed25519 <EXIT-IP>` (run it on the master) and paste the
> `ssh-ed25519 AAAA...` part into `host_key`. Without it, wgfleet trusts the
> key it sees on first connection and logs a warning.

The master needs SSH key access to the exit. If you have no key yet:

```bash
ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519
ssh-copy-id -i /root/.ssh/id_ed25519 root@<EXIT-IP>
```

Apply and provision:

```bash
systemctl restart wgfleet-controller
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1 --plan  # preview
wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-1         # do it
```

Watch the Web UI: the exit appears and turns `Ready` in a couple of minutes.
Repeat this step for every additional exit (new name, new `address_pool`).

## Step 8 — Connect your devices

Client configs are managed by **wg-easy**, which runs on the master. Tunnel to
it the same way:

```bash
ssh -L 51821:127.0.0.1:51821 root@<MASTER-IP>
cat /etc/wgfleet/wg-easy-admin-password    # username: admin
```

Open <http://127.0.0.1:51821>, log in, **+ New Client**, then scan the QR code
with the **AmneziaWG** app (iOS / Android / desktop — *not* the plain WireGuard
app; the obfuscation is AmneziaWG-specific).

Done. Your traffic now goes device → master → exit → internet.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Install failed on the kernel module | `apt-get install -y linux-headers-$(uname -r)` and re-run `./install.sh` |
| Node stuck at `Reconciling` for >5 min | `journalctl -u wgfleet-agent -n 50 --no-pager` on that node |
| Node `Error: no exit tunnels yet` right after start | normal for 1–2 minutes while the exit registers |
| Web UI unreachable | the SSH tunnel from step 6 must stay open |
| Client connects but no websites | you used the plain WireGuard app — use **AmneziaWG** |
| Exit provisioning fails on SSH | test `ssh -i /root/.ssh/id_ed25519 root@<EXIT-IP>` from the master first |
| None of the above explains it, and you need to send someone diagnostics with no access to your servers | `wgfleet-agent --support-bundle` (or `wgfleet-controller --support-bundle --fleet`) — see `SUPPORT-BUNDLE.md` in this archive |

Useful commands on any node:

```bash
systemctl status wgfleet-agent
journalctl -u wgfleet-agent -f
wgfleet-agent --config /etc/wgfleet/agent.yaml --plan   # dry run: what would change
```

## Next: RU / non-RU split tunnel + DNS filtering

The setup above sends **all** client traffic through the exit. To instead keep
Russian sites local (direct, full speed) and route only the rest abroad — plus
filter ads/trackers on DNS — use the ready-to-adapt
[`examples/controller-split-ru.yaml`](examples/controller-split-ru.yaml) and its
walkthrough [`examples/RU-SPLIT-TUNNEL.md`](examples/RU-SPLIT-TUNNEL.md) (both in
this archive). It changes only a handful of keys from the setup above.

## Every configuration option

`CONFIGURATION.md` in this archive is the complete reference: every key in
`controller.yaml` and `agent.yaml`, with its type, default and meaning, plus links
to the upstream documentation of every third-party component wgfleet drives
(mihomo, blocky, xray/REALITY, wg-easy, wgcf, ZeroTier) for the settings passed
through via `overrides` and `extra_files`.

Fully annotated reference configs are in `examples/` inside the archive; every key
listed in `CONFIGURATION.md` appears there too, commented.
