# Co-located controller + master (one node)

The control plane is pull-based (the agent dials the controller, never the
reverse), so `wgfleet-controller` and a `wgfleet-agent` on the **same box** is a
supported topology and the default for small fleets.

> **Fast path:** [QUICKSTART.md](QUICKSTART.md) — shipped as `INSTALL.md` in the
> release archive — is the short version (master + one exit + clients). Its
> installer automates steps 1–6 below on a fresh Ubuntu 24.04 VM (see
> [requirements.md](requirements.md) for what else is supported):
> ```sh
> tar xzf wgfleet-<version>-linux-amd64.tar.gz && cd wgfleet-linux-amd64 && sudo ./install.sh
> ```
> It then prints the operator-specific steps (ZeroTier authorization, real
> addresses, CA init, starting the services). This document is the manual
> equivalent.

The agent dials the controller at the node's own **mgmt/ZeroTier address**; the
controller cert SAN must cover that address (step 3).

## Security trade-off (read this)

Co-locating puts the **CA private key on the master box**, which also terminates
client traffic. Everything that listens (API, Web UI, metrics) is pinned to the
mgmt/ZT overlay or loopback, never the public interface. To isolate the CA later,
move the controller to its own node and point `agent.controller` at the remote
address — no other change.

## Ports — keep them distinct

Both processes share the host network namespace, so their listeners must not collide:

| Listener | Address (example) | Notes |
|---|---|---|
| controller mTLS API | `<mgmt>:8443` | agents dial this; SAN must cover `<mgmt>` |
| controller Web UI | `127.0.0.1:9000` | mgmt/loopback only |
| controller /metrics | `127.0.0.1:9300` | mgmt/loopback only |
| agent /metrics | `<mgmt>:9301` | pick a port ≠ 9300 |
| mihomo Clash API | `<mgmt>:9090` | set by the master spec |
| client AmneziaWG (`wg0`, the agent's) | `:443/udp` (or your choice) | `client_awg.listen_port` |

## Steps

The master box is **not** SSH-provisioned by the controller (it cannot bootstrap
itself). Onboard it by hand once; the controller then SSH-provisions the **exits**.

### 1. OS prep (once, on the master box)

```bash
sudo ./prepare-node.sh <zerotier-network-id>  # AmneziaWG DKMS module + ZeroTier join
sudo zerotier-cli listnetworks  # authorize the node, assign it a stable managed IP = <mgmt>

# prepare-node.sh does NOT install Docker (normally the provisioner's job, and the
# master is not provisioned). The master runs mihomo in Docker:
curl -fsSL https://get.docker.com | sh
```

### 2. Install both binaries

From the unpacked release archive (`linux-amd64` or `linux-arm64` to match the VM):

```bash
sudo install -m755 wgfleet-agent      /usr/local/bin/wgfleet-agent
sudo install -m755 wgfleet-controller /usr/local/bin/wgfleet-controller
sudo mkdir -p /etc/wgfleet /var/lib/wgfleet
```

Controller and agent must speak the same wire-contract version (`--version` prints
it under the build identity); the controller refuses `Register`/`PullSpec` from an
agent on a contract it does not serve. Binaries from one archive always match.

### 3. `controller.yaml`

Listen on the mgmt/ZT address so the local agent and the remote exits can dial it:

```yaml
controller:
  listen:  "<mgmt>:8443"        # e.g. 10.20.0.10:8443 — agents dial this; seeds the cert SAN
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
      public_ip: "<public-ip>"  # the endpoint written into every client config
      # the agent carries the client interface wg0; credentials live in the controller's
      # store and issue/pause/rename/revoke are console actions.
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
      routing:   { direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16], direct_geo: [RU], balance: health }
      mihomo:    { dashboard_disabled: false }  # dashboard is downloaded over the master's DIRECT path.
                                                # If GitHub is blocked even directly from this box,
                                                # set dashboard_disabled: true or dashboard_url: "<mirror>".
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
      # ssh.insecure_ignore_host_key: true — skip the check for this node
      #               (or WGFLEET_SSH_INSECURE_HOST_KEY=1 fleet-wide). Logged; drops MITM protection.
```

### 4. Initialise the CA and issue the master's identity locally

The master's mTLS cert is issued **locally** instead of being shipped over SSH:

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
# No per-node flags: mgmt_addr comes from agent.yaml, public_ip from the manifest.
# Add `--metrics off` to disable metrics.
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
# Optional dry-run of the master's plan (writes nothing):
sudo wgfleet-agent --config /etc/wgfleet/agent.yaml --once --plan \
     --mgmt-addr <mgmt> --public-ip <public-ip>
```

Open the Web UI on `http://127.0.0.1:9000` (tunnel it over SSH/ZT). The master
moves `Reconciling → Ready` once its data plane is up and the self-checks pass.

> **Client credentials.** Issue, pause, rename and revoke on the master's page in
> the console and hand each person their self-service link. There is no admin UI
> and no password file. `public_ip` (step 3) must be set: it is the endpoint
> clients dial.

### 8. Add the exits (normal flow, from this same controller)

```bash
# On each exit VM first: sudo ./prepare-node.sh <zerotier-network-id> ; authorize + assign its ZT IP.
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-de-1 --plan
sudo wgfleet-controller --config /etc/wgfleet/controller.yaml --provision exit-de-1 \
     --agent-bin /usr/local/bin/wgfleet-agent
```

### 9. Upgrading the binaries later

Exits update their agent via the controller (Web UI upgrade button /
`controller --upgrade-agent <node>`, over SSH). The co-located master has no such
path; use `deploy-master.sh` from the unpacked release archive. It copies the
binaries beside it over SSH, installs them atomically over the running binary and
restarts the services:

```bash
# both binaries (default); or --agent / --controller for one
./deploy-master.sh root@<master-host>
./deploy-master.sh root@<master-host> --plan     # dry-run: show intent only
```

When deploying **both** it installs/restarts the agent first, then the controller,
and flips that order itself when the release bumps the wire contract. Agent-first
is safe only while the wire contract is unchanged (an agent newer than its
controller is refused a spec); by hand, install the controller first, as
[upgrade.md](upgrade.md) says. If a manifest
change adds a mihomo `file` rule-provider (e.g. `direct-domains`), update the agent
before the controller restart so the file exists before mihomo reloads.

## Gotchas

- **The controller backup holds the keys of this co-located master only.** The keys of a remote master (`wg.key`, `client-wg.key`, `client-vless.key`) are not in the archive.
- **Cert SAN must cover the dialed host.** The agent dials `<mgmt>:8443`;
  `controller.listen` must use that same `<mgmt>` host. If you must listen on
  `0.0.0.0`, set `controller.advertise: "<mgmt>:8443"`.
- **`ca_key` is a `file://` path for `--init-pki`** — that one command writes the
  key to disk and needs a writable path. Everything after it (`--issue-node`,
  `--certs renew`, the running controller) resolves the key through the secret
  provider, so `secret://` works there — see [secrets-sops.md](secrets-sops.md).
  Keep a file key `chmod 600`.
- **Start order:** controller before agent (the unit `Wants=`/`After=` handles it).
- **The AmneziaWG kernel module is still required on this box** for the
  client-facing interface — do not skip OS prep because it is "only the controller host".
- **Pin the mihomo version**, not `:latest` or `Alpha` (a moving tag). Default is
  `v1.19.30`. `v1.19.27` and older **crash-loop on AmneziaWG-2.0 master↔exit junk**.
- **mihomo's own downloads must not go through the exit.** Routed via `MATCH wg-best`
  a GitHub download times out, and mihomo's `external-ui-download-detour` is not
  honoured by the running build. So:
  - **Dashboard**: the agent downloads and unpacks it into `/etc/mihomo/ui` over the
    host's direct path; mihomo only serves the static dir. `dashboard_url` /
    `dashboard_disabled` drive this. If GitHub is blocked even directly from the
    master, set `dashboard_disabled: true`.
  - **Geo**: keep `geo-auto-update: false` and serve RU geo via `.mrs` HTTP
    rule-providers with `proxy: DIRECT` — see the hardening section of
    [recipes/ru-split-tunnel-dns-filter.md](recipes/ru-split-tunnel-dns-filter.md)
    and its `examples/controller-split-ru.yaml`.
- **The master converges after the exits register.** It renders its mihomo proxies
  only once an exit has registered its public key. Until then the mihomo component
  is deferred, not failed — the journal says `spec rejected, keeping the last-good
  config: mihomo render: no exit tunnels` — the rest of the master (client
  interface, nftables, routing) converges, and the node reads `Degraded`. It turns
  `Ready` a pass or two after the first exit registers.
- **"Clients get pings/DNS but no web"** = the master input firewall is dropping the
  mihomo redirect port. Client TCP is DNAT'd to a master address, so it lands on
  INPUT, not FORWARD. The agent renders the `iifname "wg0" tcp dport <redir-port>`
  accept rule itself; if you see this, the agent on the master is out of date.
