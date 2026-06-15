# Co-located controller + master (one node)

You do not need a separate VM for the controller. The control plane is **pull-based**
— the agent always dials the controller, the controller never dials the agent — so
running `wgfleet-controller` and a `wgfleet-agent --role master` on the **same box**
is a fully supported topology. It is the recommended default for small fleets where
a dedicated controller VM is not worth it.

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
sudo ./deploy/prepare-node.sh   # AmneziaWG DKMS module + Docker + ZeroTier join
sudo zerotier-cli listnetworks  # authorize the node, assign it a stable managed IP = <mgmt>
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
between controller and agent (ADR-0019 — for a co-located pair built from the same
checkout they always do).

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
  masters:
    - name: master-xa-1
      mgmt_addr: "<mgmt>"        # same ZT address as controller.listen host
      public_ip: "<public-ip>"  # seeds wg-easy first run (INIT_HOST)
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
      routing:   { direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16], direct_geo: [RU], balance: health }
      mihomo:    { dashboard_disabled: false }  # mihomo fetches the web dashboard zip from GitHub on
                                                # first run; if GitHub is blocked from this box it will
                                                # FAIL/panic — then set dashboard_disabled: true, or
                                                # dashboard_url: "<reachable-mirror>".
      compose:   { wg_easy_web_port: 51821 }
  exits:
    - name: exit-de-1           # provisioned later over SSH from this controller
      region: de
      egress: warp
      egress_fallback: [direct] # ADR-0017 censorship-adaptive failover
      # warp_mtu: 1400          # pin if the real WARP path is < 1500
      address_pool: 10.81.0.0/24
      mgmt_addr: "<exit-mgmt>"
      ssh: { host: "<exit-public-ip>", port: 22, user: root, key_path: "~/.ssh/id_ed25519", host_key: "ssh-ed25519 AAAA..." }
      # ssh.port: set it if the exit's SSH is not on 22 / reached via a forwarded port.
      # ssh.host_key: pin it (ssh-keyscan -t ed25519 <exit-ip>) — bootstrap ships the node's
      #               mTLS key over SSH, so an unpinned dial lets a MITM capture its identity.
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
  reconcile_interval: 60s
  identity:
    cert: "/etc/wgfleet/node.crt"
    key:  "/etc/wgfleet/node.key"
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
ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml \
          --mgmt-addr <mgmt> --public-ip <public-ip> --metrics <mgmt>:9301
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
sudo wgfleet-agent --config /etc/wgfleet/agent.yaml --plan \
     --mgmt-addr <mgmt> --public-ip <public-ip>
```

Open the Web UI on `http://127.0.0.1:9000` (tunnel it over SSH/ZT). The master should
move `Reconciling → Ready` once wg-easy + mihomo are up and its self-checks pass.

### 8. Add the exits (normal flow, from this same controller)

The exits are remote VMs, so they ARE provisioned over SSH by the controller:

```bash
# On each exit VM first: sudo ./deploy/prepare-node.sh ; authorize + assign its ZT IP.
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-de-1 --plan
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-de-1 \
     --agent-bin /usr/local/bin/wgfleet-agent
```

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
- **Pin a specific mihomo version** (`compose.mihomo_tag`, e.g. `v1.19.27`) for reproducible
  deploys rather than `:latest` (the default is already pinned). The AmneziaWG obfuscation
  params are derived safely by the platform — it floors `Jmin ≥ S4` so no junk packet is short
  enough to trip the unguarded S4-strip in older `amneziawg-go` builds (this was a real
  crash-loop: `Jmin=22` with `S4=52` panicked mihomo on a 41-byte junk packet; fixed in the
  derivation, so the mihomo/kernel pairing no longer matters).
- **mihomo dashboard download is a startup dependency.** mihomo fetches the dashboard zip
  from GitHub on first run; if GitHub is unreachable from the master it fails and can
  crash-loop. Set `masters[].mihomo.dashboard_disabled: true` (or a reachable
  `dashboard_url`) on networks where GitHub is blocked. Default is on.
- **Convergence takes a pass or two.** The master can only render its mihomo proxies once
  each exit has registered its public key. Expect the master to sit at `Error`/`Degraded`
  ("no exit tunnels yet") for ~1–2 reconcile intervals after first start, then go `Ready`.
```
