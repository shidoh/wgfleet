# Co-located controller + master (one node)

You do not need a separate VM for the controller. The control plane is **pull-based**
— the agent always dials the controller, the controller never dials the agent — so
running `wgfleet-controller` and a `wgfleet-agent` on the **same box**
is a fully supported topology. It is the recommended default for small fleets where
a dedicated controller VM is not worth it.

> **Fast path:** [QUICKSTART.md](QUICKSTART.md) — shipped as `INSTALL.md` in the
> release archive — is the short, step-by-step
> version of this document (master + one exit + clients, ~30 min). Its installer
> automates steps 1–6 below (deps, binaries, dirs, units, config templates) on a
> fresh Ubuntu/Debian VM — either from the release archive:
> ```sh
> tar xzf wgfleet-<version>-linux-amd64.tar.gz && cd wgfleet-linux-amd64 && sudo ./install.sh
> ```
> or straight off the internet:
> ```sh
> curl -fsSL https://raw.githubusercontent.com/shidoh/wgfleet/main/install.sh | sudo bash
> ```
> It then prints the operator-specific steps (ZeroTier authorization, real
> addresses, CA init, starting the services). This document is the manual
> equivalent and the reference for what each step does.

```
┌────────────────────────── master node (one VM) ──────────────────────────┐
│  wgfleet-controller            wgfleet-agent (role=master)                 │
│   ├─ mTLS API   <mgmt>:8443  ◄──── dials ──── controller: <mgmt>:8443      │
│   ├─ Web UI     127.0.0.1:9000     ├─ wg-easy (client AmneziaWG)           │
│   ├─ /metrics   127.0.0.1:9300     ├─ mihomo  (master↔exit + LB, :9090)    │
│   ├─ sqlite store                  ├─ nftables NAT                          │
│   └─ CA key (issues node certs)    └─ /metrics <mgmt>:9301                  │
└───────────────────────────────────────────────────────────────────────────┘
        │ SSH-provisions + mTLS  ▼ (exits stay on their own VMs)
                          exit nodes (exit-a/exit-b/…)
```

The agent dials the controller at the node's own **mgmt/ZeroTier address** — a host
can reach its own ZT IP, so nothing special is needed beyond a matching cert SAN.

## Security trade-off (read this)

Co-locating puts the **CA private key on the master box**, which also terminates
client traffic and is more exposed than a back-office controller. For a small fleet
this is an acceptable trade-off; everything that listens (API, Web UI, metrics) is
already pinned to the mgmt/ZT overlay or loopback, never the public interface. If you
later want blast-radius isolation (a compromised master must not also leak the CA),
move the controller to its own node — no code changes, just split the two processes
across boxes and point `agent.controller` at the remote address.

## Ports — keep them distinct

Both processes share the host network namespace, so their listeners must not collide:

| Listener | Address (example) | Notes |
|---|---|---|
| controller mTLS API | `<mgmt>:8443` | agents dial this; SAN must cover `<mgmt>` |
| controller Web UI | `127.0.0.1:9000` | mgmt/loopback only |
| controller /metrics | `127.0.0.1:9300` | mgmt/loopback only |
| agent /metrics | `<mgmt>:9301` | pick a port ≠ 9300 |
| mihomo Clash API | `<mgmt>:9090` | set by the master spec |
| wg-easy web | `<mgmt>:51821` (or your choice) | `compose.wg_easy_web_port` |
| client AmneziaWG | `:443/udp` (or your choice) | `client_awg.listen_port` |

## Steps

The master box is **not** SSH-provisioned by the controller (it cannot bootstrap
itself). Onboard it by hand once; the controller then SSH-provisions the **exits**
normally.

### 1. OS prep (once, on the master box)

Same kernel-risky prep as any node — the master's client-facing interface is
AmneziaWG (kernel module), and the data plane runs in Docker:

```bash
sudo ./deploy/prepare-node.sh <zerotier-network-id>  # AmneziaWG DKMS module + ZeroTier join
sudo zerotier-cli listnetworks  # authorize the node, assign it a stable managed IP = <mgmt>

# prepare-node.sh deliberately does NOT install Docker — that is normally the
# provisioner's job, but the controller does NOT SSH-provision this box (it can't
# bootstrap itself). The master runs mihomo + wg-easy in Docker, so install the
# engine by hand here — the exact step the provisioner runs on exits:
curl -fsSL https://get.docker.com | sh
```

### 2. Install both binaries

Co-location runs BOTH binaries on this box, so build both for the VM's
architecture (`ARCH=amd64` default, `ARCH=arm64` for Graviton/Ampere). Build on a
dev box and copy, or build on the VM (needs Go 1.26+):

```bash
make agent-linux      ARCH=amd64     # → dist/wgfleet-agent-linux-amd64
make controller-linux ARCH=amd64     # → dist/wgfleet-controller-linux-amd64
sudo install -m755 dist/wgfleet-agent-linux-amd64      /usr/local/bin/wgfleet-agent
sudo install -m755 dist/wgfleet-controller-linux-amd64 /usr/local/bin/wgfleet-controller
sudo mkdir -p /etc/wgfleet /var/lib/wgfleet
```

Both binaries stamp their build version from git via `-ldflags` (shown by
`wgfleet-controller --version`); the wire-contract version they speak must match
between controller and agent. The controller rejects `Register`/`PullSpec` from an
agent whose contract version it does not serve, so a half-upgraded pair fails loudly
instead of drifting; for a co-located pair built from the same checkout they always
match. `--version` prints the contract version under the build identity.

### 3. `controller.yaml`

Listen on the mgmt/ZT address (so the local agent — and remote exits — can dial it):

```yaml
controller:
  listen:  "<mgmt>:8443"        # e.g. 10.20.25.254:8443 — agents dial this; seeds the cert SAN
  webui:   "127.0.0.1:9000"     # mgmt/ZT or loopback only
  store:   "/var/lib/wgfleet/state.db"
  metrics: "127.0.0.1:9300"
  pki:
    ca_cert: "/etc/wgfleet/ca.crt"
    ca_key:  "file:///etc/wgfleet/ca.key"   # file:// path (NOT secret://) so the CLI can sign certs
fleet:
  zerotier_network: "<zt-network-id>"  # 16-hex mgmt overlay id; exits join it during provisioning
  masters:
    - name: master-xa-1
      mgmt_addr: "<mgmt>"        # same ZT address as controller.listen host
      public_ip: "<public-ip>"  # seeds wg-easy first run (INIT_HOST)
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
      routing:   { direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16], direct_geo: [RU], balance: health }
      mihomo:    { dashboard_disabled: false }  # metacubexd dashboard, downloaded via a DIRECT detour
                                                # (the master reaches GitHub on its own path, not via an
                                                # exit). If GitHub is blocked even directly from this box,
                                                # set dashboard_disabled: true or dashboard_url: "<mirror>".
      compose:   { wg_easy_web_port: 51821 }
  exits:
    - name: exit-de-1           # provisioned later over SSH from this controller
      region: de
      egress: warp
      # warp_mtu: 1400          # pin if the real WARP path is < 1500. Too high and large
                                # packets vanish into a PMTU black hole: handshakes and
                                # pings work, TLS and downloads stall. 1380 is a safe floor.
      address_pool: 10.81.0.0/24
      mgmt_addr: "<exit-mgmt>"
      ssh: { host: "<exit-public-ip>", port: 22, user: root, key_path: "~/.ssh/id_ed25519", host_key: "ssh-ed25519 AAAA..." }
      # ssh.port: set it if the exit's SSH is not on 22 / reached via a forwarded port.
      # ssh.host_key: pin it (ssh-keyscan -t ed25519 <exit-ip>) — bootstrap ships the node's
      #               mTLS key over SSH, so an unpinned dial lets a MITM capture its identity.
      # ssh.insecure_ignore_host_key: true — escape hatch to skip the check for this node
      #               (or WGFLEET_SSH_INSECURE_HOST_KEY=1 fleet-wide). Logged; drops MITM protection.
```

### 4. Initialise the CA and issue the master's identity locally

Because the controller is on this box, the master's mTLS cert is issued **locally**
instead of being shipped over SSH:

```bash
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --init-pki
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml \
     --issue-node master-xa-1 --issue-out /etc/wgfleet
# → writes /etc/wgfleet/{node.crt,node.key,ca.crt}
```

### 5. `agent.yaml` for the master

```yaml
agent:
  role: master
  controller: "<mgmt>:8443"     # the local controller, via the node's own ZT IP
  node_id: "master-xa-1"        # must match masters[].name (and the issued cert CN)
  mgmt_addr: "<mgmt>"           # ZT address; agent binds /metrics to <mgmt>:9301 by default
  reconcile_interval: 30s
  identity:
    cert: "/etc/wgfleet/node.crt"
    key:  "/etc/wgfleet/node.key"
    ca:   "/etc/wgfleet/ca.crt"    # REQUIRED — verifies the controller; --issue-node wrote it above
```

### 6. systemd units (two services, one box)

```ini
# /etc/systemd/system/wgfleet-controller.service
[Unit]
Description=wgfleet controller
After=network-online.target
[Service]
ExecStart=/usr/local/bin/wgfleet-controller --config /etc/wgfleet/controller.yaml
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/wgfleet-agent.service
[Unit]
Description=wgfleet agent (master)
After=network-online.target wgfleet-controller.service docker.service
Wants=wgfleet-controller.service
[Service]
# Generic unit (no per-node flags): mgmt_addr comes from agent.yaml (drives the
# default <mgmt>:9301 metrics bind), and the master's public_ip is taken from the
# manifest masters[] entry. Add `--metrics off` to disable metrics.
ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml --log-format json
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wgfleet-controller wgfleet-agent
```

### 7. Verify

```bash
# Dry-run the master's plan first if you like (writes nothing):
sudo wgfleet-agent --config /etc/wgfleet/agent.yaml --once --plan \
     --mgmt-addr <mgmt> --public-ip <public-ip>
```

Open the Web UI on `http://127.0.0.1:9000` (tunnel it over SSH/ZT). The master should
move `Reconciling → Ready` once wg-easy + mihomo are up and its self-checks pass.

> **wg-easy comes up non-interactively (no setup wizard).** The agent seeds wg-easy's
> unattended setup, so it does NOT prompt for a password/host/port. To log into the
> wg-easy UI (`http://<mgmt>:<wg_easy_web_port>`), read the agent-generated admin
> password off the master — it is never sent to the controller:
> ```bash
> sudo cat /etc/wgfleet/wg-easy-admin-password   # username: admin
> ```
> `public_ip` (step 3) must be set: it becomes wg-easy's `INIT_HOST` (the endpoint
> clients dial) and is required for the unattended setup to complete.

### 8. Add the exits (normal flow, from this same controller)

The exits are remote VMs, so they ARE provisioned over SSH by the controller:

```bash
# On each exit VM first: sudo ./deploy/prepare-node.sh <zerotier-network-id> ; authorize + assign its ZT IP.
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-de-1 --plan
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-de-1 \
     --agent-bin /usr/local/bin/wgfleet-agent
```

### 9. Upgrading the binaries later

The exits update their agent via the controller (Web UI upgrade button /
`controller --upgrade-agent <node>`, over SSH). The co-located master has **no
such path** — it is not SSH-provisioned and cannot bootstrap itself — so use
`deploy/deploy-master.sh`, the master's equivalent. It cross-builds on your
machine, copies over SSH, installs ETXTBSY-safe (temp + atomic rename over the
running binary) and restarts the services:

```bash
# both binaries (default); or --agent / --controller for one
deploy/deploy-master.sh root@<master-host>
deploy/deploy-master.sh root@<master-host> --plan     # dry-run, build + show intent
```

When deploying **both**, it installs/restarts the agent FIRST, then the
controller: a controller restart re-reads the fleet manifest and serves a new
spec, and the already-updated agent then reconciles it correctly. If a manifest
change adds a mihomo `file` rule-provider (e.g. `direct-domains`), update the
agent before the controller restart so the file is written before mihomo reloads.

## Gotchas

- **Cert SAN must cover the dialed host.** The agent dials `<mgmt>:8443`; `controller.listen`
  must use that same `<mgmt>` host (it seeds the SAN). If you must listen on `0.0.0.0`,
  set `controller.advertise: "<mgmt>:8443"` so the SAN and the agents' baked-in endpoint
  use a reachable address.
- **`ca_key` is a `file://` path, not `secret://`** — the `--issue-node`/`--init-pki`
  CLI signs certs and needs to read the key directly. Keep it `chmod 600`.
- **Start order:** controller before agent (the unit `Wants=`/`After=` handles it), so
  the master's first `PullSpec` succeeds instead of retrying.
- **One AmneziaWG kernel module** still required on this box for wg-easy's client-facing
  interface — `prepare-node.sh` installs it; don't skip OS prep just because it is "only
  the controller host".
- **`wg-easy` shows `unhealthy` in `docker ps` — cosmetic.** Its built-in Docker
  healthcheck runs `wg show`, which cannot enumerate AmneziaWG interfaces. The real
  signal is the agent's `client-wg` health check (the controller marks the master `Ready`
  off that). Don't chase the wg-easy container health flag.
- **Pin the mihomo version**, not `:latest` — and not `Alpha`, which is a moving tag that
  defeats the pin. The code default is now `v1.19.30` (AmneziaWG 2.0 shipped in `v1.19.14`).
  ⚠️ `v1.19.27` and older **crash-loop on AmneziaWG-2.0 master↔exit junk**. The AmneziaWG obfuscation
  params are derived safely by the platform — it keeps `Jmin ≥ S4 + 8`, shifting the whole
  junk band rather than clamping onto that floor, so no junk packet is short
  enough to trip the unguarded S4-strip in older `amneziawg-go` builds (this was a real
  crash-loop: `Jmin=22` with `S4=52` panicked mihomo on a 41-byte junk packet; fixed in the
  derivation, so the mihomo/kernel pairing no longer matters).
- **mihomo's own downloads (dashboard, geo `.dat`) follow the proxy rules and stall.** Routed
  through the default rules (`MATCH wg-best` → exit → WARP) a GitHub download TLS-times-out even
  though GitHub is reachable DIRECT from the master in <1s, and mihomo's `external-ui-download-detour`
  is NOT honored by the running build. So neither is left to mihomo:
  - **Dashboard**: the agent (`master dashboardPlanner`) downloads + unpacks it into `/etc/mihomo/ui`
    over the host's direct path; mihomo only serves the static dir (the renderer emits `external-ui`
    with no `external-ui-url`). `dashboard_url` / `dashboard_disabled` drive the agent.
  - **Geo**: keep `geo-auto-update: false` and serve RU geo via `.mrs` HTTP rule-providers with
    `proxy: DIRECT` (they auto-update over the direct path) — see the hardening section of
    [recipes/ru-split-tunnel-dns-filter.md](recipes/ru-split-tunnel-dns-filter.md) and its
    `deploy/examples/controller-split-ru.yaml`.

  If GitHub is blocked even directly from the master, set `dashboard_disabled: true`.
- **Convergence takes a pass or two.** The master can only render its mihomo proxies once
  each exit has registered its public key. Expect the master to sit at `Error`/`Degraded`
  ("no exit tunnels yet") for ~1–2 reconcile intervals after first start, then go `Ready`.
- **"Clients get pings/DNS but no web" = the input firewall is dropping the mihomo
  redirect.** Client TCP is DNAT'd to the local mihomo redir port (a master address),
  so it lands on the INPUT hook, not FORWARD. The master input firewall must accept
  `iifname "wg0" tcp dport <redir-port>` or the drop policy swallows every web
  connection while ICMP (accepted) and DNS (forwarded to an exit) still work. The
  agent renders that accept rule automatically as part of trusting the management
  overlay; the symptom only appears with a stale agent that predates the fix.
```
