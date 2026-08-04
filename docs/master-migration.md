# Migrating the master to another VM

Moving a co-located controller+master (control plane + client-facing AmneziaWG)
to a new box. Exits are not touched and keep running throughout — they reconnect
on their own at the end.

## Answer two questions first

They decide whether this is a 15-minute job or a client-config re-issue.

| | Keep it on the new VM | If it changes |
|---|---|---|
| **ZeroTier mgmt address** (e.g. `172.29.3.10`) | Assign the old address to the new node in ZeroTier Central | Every exit's `agent.yaml` `controller:` must be edited **and** the controller cert SAN re-issued |
| **Public IP** (what clients dial) | Keep it (floating/elastic IP), or use a DNS name | Existing client configs keep dialing the old address — see step 5 |

Keeping the mgmt address is the zero-touch path: CA, certs and endpoint all
match, and the fleet re-adopts itself with no per-exit edits.

## 1. Back up — old master, may stay live

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml \
  --backup /root/fleet.tar.age --age-recipient age1...
```

Omit `--age-recipient` to be prompted for a passphrase instead.

Copy the archive off the box before touching anything else:

```bash
scp root@old-master:/root/fleet.tar.age .
```

Captured: the store db (consistent snapshot), CA cert + key, `controller.yaml`,
the sops secrets file, and — because this box is also a master — the wg-easy
client db, the wg-easy admin password, the AmneziaWG key, and the node identity
(`node.crt`, `node.key`, `agent.yaml`).

Not captured, because the agent regenerates it all on first reconcile: nftables
rules, mihomo/xray/blocky configs, compose files.

> The archive holds the CA key and every client key. The age envelope is its only
> protection at rest. Store it like a password.

## 2. Prepare the new VM

From the release archive, on the new box:

```bash
tar xzf wgfleet-<version>-linux-amd64.tar.gz && cd wgfleet-linux-amd64
ZT_NETWORK=<16-hex-network-id> sudo ./install.sh

# install.sh does not include age, and restore shells out to it.
sudo apt-get install -y age
```

`install.sh` installs the AmneziaWG kernel module, ZeroTier, Docker, both
binaries and both systemd units, and leaves the units **disabled** — which is
what you want here, since nothing should start before the restore.

Now authorize the node in ZeroTier Central and **assign it the old master's mgmt
address**. Confirm it landed:

```bash
ip -4 -o addr show | grep zt
```

> If the address disappears after `systemctl restart zerotier-one`, the member's
> managed-IP assignment is off in ZeroTier Central. Fix it there. An address added
> by hand vanishes on the next restart and takes the control plane with it.

## 3. Stop the old master

Restore refuses to run while a controller is still serving on the same endpoint,
and two live controllers on one mgmt address will fight.

```bash
ssh root@old-master 'systemctl disable --now wgfleet-agent wgfleet-controller'
```

Leave the box powered on. It is your rollback until step 6.

## 4. Restore and start — new VM

```bash
sudo wgfleet-controller --restore /root/fleet.tar.age --plan   # shows the change set
sudo wgfleet-controller --restore /root/fleet.tar.age
```

Restore moves any existing destination aside to `<path>.bak-<timestamp>` and
writes each file atomically — including the config templates `install.sh` just
dropped.

Start the controller first: the agent's first spec pull must find it serving.

```bash
sudo systemctl enable --now wgfleet-controller
sudo systemctl enable --now wgfleet-agent
```

Verify:

```bash
systemctl is-active wgfleet-controller wgfleet-agent
journalctl -u wgfleet-agent -n 20 --no-pager     # want state=Ready, drift=0
```

Then open `http://<mgmt>:9000` and wait for every exit to reach `Ready`. Exits
reconnect on their own within a reconcile interval; nothing to do on them.

## 5. Only if the public IP changed

The client-facing endpoint is stored inside the restored wg-easy database.
wg-easy applies its `INIT_*` environment only when it first creates that
database and ignores it afterwards — so a restored database keeps **the old
public IP baked in**, and existing client configs keep dialing the dead box.

1. Update the manifest so the rest of the system agrees:

   ```yaml
   # /etc/wgfleet/controller.yaml
   masters:
     - name: master-xa-1
       public_ip: <new-ip-or-dns-name>
   ```

   ```bash
   sudo systemctl restart wgfleet-controller
   ```

2. Change the host in the wg-easy admin UI.

3. Re-issue client configs. Every existing device needs a fresh config or QR
   code — an already-imported peer cannot be told about a new endpoint.

To avoid this step next time, put a **DNS name** in `public_ip` rather than a
literal address, so a future move is a DNS record change.

## 6. Decommission the old VM

Only once the dashboard shows every exit `Ready` and one real client has been
tested end to end. Keep the archive.

## Rollback

Nothing on the old box was deleted — only its services were stopped.

```bash
ssh root@new-vm     'systemctl disable --now wgfleet-agent wgfleet-controller'
ssh root@old-master 'systemctl enable --now wgfleet-controller wgfleet-agent'
```

Then reassign the mgmt address back to the old node in ZeroTier Central.

## Quick reference

```
1. old:  --backup  →  copy the archive off the box
2. new:  ZT_NETWORK=<id> ./install.sh ; apt install age
         authorize in ZT Central with the OLD mgmt address
3. old:  systemctl disable --now wgfleet-agent wgfleet-controller   (leave powered on)
4. new:  --restore --plan  →  --restore  →  start controller, then agent  →  verify
5. new:  public IP changed?  manifest + wg-easy UI + re-issue client configs
6. old:  decommission once exits are Ready and a client is tested
```
