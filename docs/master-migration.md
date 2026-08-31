# Migrating the master to another VM

Moving a co-located controller+master (control plane + client-facing AmneziaWG)
to a new box. Exits are not touched and keep running throughout — they reconnect
on their own at the end.

**What your users see: an outage for as long as the move takes.** This box is the
one they dial. Their traffic stops when you stop the old master and resumes when the
new one is serving — there is no failover here, because there is only one master.
Exits keep running on their last-good config the whole time, so nothing has to be
rebuilt; what is down is the way in.

So: do this in a window you have announced, expect the outage to be the length of
your slowest step (the restore and the first reconcile, not the file copy), and read
step 5 **before** you start — whether your users need new configs afterwards is
decided by the two questions below, not by anything you do later.

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

Also captured on a master: the fleet secret `awg3.key`, the client-facing
WireGuard key and the client VLESS/REALITY key, when they are files on this host.

Not captured, because the agent regenerates it all on first reconcile: nftables
rules, mihomo/xray/blocky configs, compose files.

**Not captured and NOT regenerable — copy these by hand or you lose the fleet.**
The migration will complete without them, every exit will go `Ready`, and nothing
will warn you until the day you need them:

- **The SSH private key(s) the exits are provisioned with** (`fleet.exits[].ssh.key_path`).
  Only the paths travel, inside `controller.yaml`. Without the keys the new master
  can see the fleet and cannot provision, upgrade or roll back a single exit — the
  recovery channel is the part that goes missing.
- **The ZeroTier identity** (`/var/lib/zerotier-one/`), if you want to rejoin as the
  same mgmt address rather than authorize a new member and reassign the old IP.

```bash
# on the OLD master, before you stop it
scp /root/.ssh/id_ed25519 root@<new-master>:/root/.ssh/
```

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

`--restore` loads the manifest before it restores anything, and step 2's
`install.sh` leaves `<mgmt-zt-ip>` and `<public-ip>` placeholders in it — so the
restore refuses with *"mgmt_addr \"<mgmt-zt-ip>\" is not a valid IP address"*
before reaching the archive. Fill those two in first; the restore then overwrites
the whole file anyway, so anything syntactically valid will do:

```bash
sudo sed -i "s|<mgmt-zt-ip>|$(ip -4 -o addr show dev zt+ | awk '{print $4}' | cut -d/ -f1)|; \
             s|<public-ip>|$(curl -4 -s ifconfig.me)|" /etc/wgfleet/controller.yaml
# If the archive was written with --age-recipient (step 1's headline command),
# add --age-identity /root/key.txt to BOTH lines; without it age cannot decrypt
# at all and the first line fails before it shows you anything.
sudo wgfleet-controller --restore /root/fleet.tar.age --plan   # shows the change set
sudo wgfleet-controller --restore /root/fleet.tar.age
```

With a recipient-encrypted archive the two commands read:

```bash
sudo wgfleet-controller --restore /root/fleet.tar.age --age-identity /root/key.txt --plan
sudo wgfleet-controller --restore /root/fleet.tar.age --age-identity /root/key.txt
```

Restore checks every destination in the archive BEFORE it writes anything, then
moves each existing file aside to `<path>.bak-<timestamp>` and writes atomically —
including the config templates `install.sh` just dropped. It writes ONLY to the
paths this host's own configuration names, with this host's own permissions; an
archive asking for anywhere else is refused before the first write, so a rejected
archive leaves the box exactly as it found it.

If the refusal names a path you recognise, this host's `controller.yaml` puts that
file somewhere the old one did not. Make the two agree and run the restore again.

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

Existing client configs carry the old endpoint and keep dialing the dead box. What
you do about it depends on which client leg this master runs.

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

2. **With `client_awg.managed: true`** — the agent owns the interface and there is
   nothing else to change. The controller renders configs from `public_ip` on demand,
   so every config the console or the self-service portal serves from now on carries
   the new endpoint. There is no wg-easy database and no admin UI.

   **Without it** (legacy wg-easy path) the endpoint is baked into the restored
   wg-easy database: wg-easy applies its `INIT_*` environment only when it first
   creates that database and ignores it afterwards. Change the host in the wg-easy
   admin UI as well.

3. Re-hand-out. Every already-imported peer needs a fresh config or QR — a device
   cannot be told about a new endpoint. On the managed path, send each person their
   self-service link again rather than a file: the page re-renders from the live spec,
   so the same link now yields the corrected config.

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
