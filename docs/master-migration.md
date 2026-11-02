# Migrating the master to another VM

Moving a co-located controller+master (control plane + client-facing AmneziaWG)
to a new box. Exits keep running on their last-good config and reconnect on their
own at the end.

**Clients are offline from the moment you stop the old master until the new one is
serving** — there is no failover with a single master. Announce a window and read
step 5 **before** you start.

## Answer two questions first

| | Keep it on the new VM | If it changes |
|---|---|---|
| **ZeroTier mgmt address** (e.g. `10.20.0.10`) | Assign the old address to the new node in ZeroTier Central | Every exit's `agent.yaml` `controller:` must be edited **and** the controller cert SAN re-issued |
| **Public IP** (what clients dial) | Keep it (floating/elastic IP), or use a DNS name | Existing client configs keep dialing the old address — see step 5 |

Keeping the mgmt address is the zero-touch path: no per-exit edits.

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

What the archive holds, what it warns about and how restore behaves is in
[operations.md](operations.md), "Backup & restore". Two things it never holds —
**copy them by hand**: the SSH private key(s) the exits are provisioned with
(`fleet.exits[].ssh.key_path`) and the ZeroTier identity (`/var/lib/zerotier-one/`)
if you want to rejoin as the same member.

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
binaries and both systemd units, and leaves the units **disabled** — nothing must
start before the restore.

Authorize the node in ZeroTier Central, **assign it the old master's mgmt
address**, and confirm it landed:

```bash
ip -4 -o addr show | grep zt
```

> If the address disappears after `systemctl restart zerotier-one`, the member's
> managed-IP assignment is off in ZeroTier Central. Fix it there; an address added
> by hand vanishes on the next restart and takes the control plane with it.

## 3. Stop the old master

Restore refuses to run while a controller is still serving on the same endpoint,
and two live controllers on one mgmt address will fight.

```bash
ssh root@old-master 'systemctl disable --now wgfleet-agent wgfleet-controller'
```

Leave the box powered on. It is your rollback until step 6.

## 4. Restore and start — new VM

`--restore` loads the manifest first, and `install.sh` left `<mgmt-zt-ip>` and
`<public-ip>` placeholders in it, so it refuses with *"mgmt_addr \"<mgmt-zt-ip>\"
is not a valid IP address"*. Fill those two in (the restore overwrites the file
anyway):

```bash
sudo sed -i "s|<mgmt-zt-ip>|$(ip -4 -o addr show | awk '/ zt/ {print $4}' | cut -d/ -f1)|; \
             s|<public-ip>|$(curl -4 -s ifconfig.me)|" /etc/wgfleet/controller.yaml
sudo wgfleet-controller --restore /root/fleet.tar.age --plan   # shows the change set
sudo wgfleet-controller --restore /root/fleet.tar.age
```

With a recipient-encrypted archive (step 1's `--age-recipient`) add
`--age-identity` to **both** lines, or the `--plan` line fails before showing anything:

```bash
sudo wgfleet-controller --restore /root/fleet.tar.age --age-identity /root/key.txt --plan
sudo wgfleet-controller --restore /root/fleet.tar.age --age-identity /root/key.txt
```

Restore writes only to the paths this host's `controller.yaml` names and refuses
the whole archive before the first write otherwise. If the refusal names a path
you recognise, the two `controller.yaml`s disagree on where that file lives — make
them agree and re-run.

Start the controller first, so the agent's first spec pull finds it serving.

```bash
sudo systemctl enable --now wgfleet-controller
sudo systemctl enable --now wgfleet-agent
```

Verify:

```bash
systemctl is-active wgfleet-controller wgfleet-agent
journalctl -u wgfleet-agent -n 20 --no-pager     # want state=Ready, drift=0
```

Then reach the console as in the Quickstart, step 6 (the installer binds it to
`127.0.0.1:9000`, so tunnel it over SSH), and wait for every exit to reach
`Ready`; they reconnect on their own within a reconcile interval.

## 5. Only if the public IP changed

Existing client configs carry the old endpoint.

1. Update the manifest:

   ```yaml
   # /etc/wgfleet/controller.yaml
   masters:
     - name: master-1
       public_ip: <new-ip-or-dns-name>
   ```

   ```bash
   sudo systemctl restart wgfleet-controller
   ```

2. Nothing else changes: configs are rendered from `public_ip` on demand, so the
   console and the self-service portal now serve the new endpoint.

3. Re-hand-out. Every already-imported peer needs a fresh config or QR: send each
   person their self-service link again.

To avoid this step next time, put a **DNS name** in `public_ip`.

## 6. Decommission the old VM

Only once every exit shows `Ready` and one real client has been tested end to
end. Keep the archive.

## Rollback

Nothing on the old box was deleted, only stopped.

```bash
ssh root@new-vm     'systemctl disable --now wgfleet-agent wgfleet-controller'
ssh root@old-master 'systemctl enable --now wgfleet-controller wgfleet-agent'
```

Then reassign the mgmt address back to the old node in ZeroTier Central.

## Quick reference

```
1. old:  --backup  →  copy the archive off the box (+ exit SSH keys by hand)
2. new:  ZT_NETWORK=<id> ./install.sh ; apt install age
         authorize in ZT Central with the OLD mgmt address
3. old:  systemctl disable --now wgfleet-agent wgfleet-controller   (leave powered on)
4. new:  fill placeholders  →  --restore --plan  →  --restore  →  start controller, then agent  →  verify
5. new:  public IP changed?  manifest + re-issue client configs
6. old:  decommission once exits are Ready and a client is tested
```
