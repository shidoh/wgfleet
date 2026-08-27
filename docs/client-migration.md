# Moving the client leg from wg-easy into wgfleet

Until now the interface your end users dial was owned by **wg-easy**: it held the
credentials, generated the configs, and raised the interface. wgfleet wrote into
its database from the outside.

This document walks the handover: wgfleet's controller takes ownership of the
credentials, and the master's agent renders and raises the interface itself.
wg-easy stops being part of the data path.

**The handover is transparent.** Nobody re-imports a tunnel, no config you have
already handed out stops working. That is a design constraint, not a hope — the
agent *adopts* wg-easy's own interface private key, so the server public key
every client pins keeps matching, and the obfuscation parameters come from the
same fleet config that fed wg-easy in the first place.

Read this end to end before starting. The three parts are independent decisions:
you may upgrade (Part 1) and stop there for weeks.

- [Part 1 — Upgrade the binaries](#part-1--upgrade-the-binaries) — required, low risk
- [Part 2 — Import the credentials](#part-2--import-the-credentials) — reversible, changes nothing live
- [Part 3 — Hand the interface over](#part-3--hand-the-interface-over) — the cutover
- [Part 4 — AmneziaWG 3.x afterwards](#part-4--amneziawg-3x-afterwards) — optional, later

---

## What changes and what does not

| | Before | After |
|---|---|---|
| Who stores client keys | wg-easy's SQLite | controller store (`client_wg_credentials`) |
| Who raises the interface | wg-easy container | master's agent (`awg-quick`) |
| Server public key | wg-easy's | **the same one**, adopted |
| Obfuscation parameters | from your fleet config | **the same ones**, same source |
| Client addresses | wg-easy's allocation | imported verbatim |
| Where you add a client | wg-easy web UI on :51821 | wgfleet Web UI, node → *WireGuard clients* |
| How a user gets a config | you export and send a file | permanent portal link, or you download it |
| wg-easy container | in the data path | still running, no longer in the data path |

---

## Pre-flight

Answer these before you touch anything.

**1. What AmneziaWG kernel module does the master run?**

```bash
cat /sys/module/amneziawg/version
```

If this reports **3.x**, note it: your wg-easy is already living on borrowed
time. Its container ships AmneziaWG tools of generation 1, which cannot drive a
3.x module. It works only because the interface is already up — the next
container restart will fail to raise it. For you this means **the rollback in
Part 3 is not available**, and the migration is the fix rather than a risk.

If this reports 1.x or 2.x, rollback is available and the whole exercise is
reversible.

**2. Do all your client names survive?**

Client names are rendered into the interface config. wgfleet accepts letters,
digits, `-`, `_` and `.`, up to 64 characters — nothing else. A client called
`Ivan's iPhone` will **not** migrate. Part 2's dry run tells you exactly which
ones, and you rename them in wg-easy before continuing.

**3. Do you have console access to the master?**

You will not need it if nothing goes wrong. Have it anyway: the client interface
is the one thing whose outage every user notices at once.

**4. Back up.**

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --backup /root/pre-migration.age
cp /etc/wireguard/wg-easy.db /root/wg-easy.db.bak
```

The first needs the `age` binary present (see `MASTER-MIGRATION.md`). The
second is the source of truth you are migrating away from — copy it even though
the import only ever reads it.

---

## Part 1 — Upgrade the binaries

This release bumps the wire contract from 7 to **8**. Nothing about the client
leg changes here; the new spec block simply becomes available.

### Order: controller first, then agents

```bash
# on the controller host
systemctl stop wgfleet-controller
cp wgfleet-controller /usr/local/bin/wgfleet-controller
systemctl start wgfleet-controller
```

The controller migrates its store on first start (schema v11–v13: the credential
table, the master's published client public key, and the per-peer status
column). This happens silently and takes milliseconds.

Then the agents. If `controller.agent_bin` is set in your config, **you do not
have to do anything** — an agent that is behind on the wire contract is upgraded
automatically the next time it registers. Otherwise, per node:

```bash
systemctl stop wgfleet-agent
cp wgfleet-agent /usr/local/bin/wgfleet-agent
systemctl start wgfleet-agent
```

### Why this order

The controller still serves agents all the way back to wire 1, so an old agent
against a new controller is fine — it simply does not receive the new spec
block, which is exactly the safe state. The reverse (new agent, old controller)
gives you a node asking for a contract the controller does not know.

### What does not happen

**The wg-easy container is not recreated.** The rendered `docker-compose.yml` is
byte-for-byte identical to the previous release for a master that has not opted
in, so nothing triggers a `docker compose up`. This matters more than it sounds:
recreating that container makes it re-read its database and, on a 3.x-module
host, fail to raise the interface.

### Rolling the binary back

Safe. The store migrations only add columns, all with defaults, and the previous
release's controller opens a migrated store, reads it, registers nodes and
writes status without complaint. Issued client credentials survive in the
database, ignored, until you roll forward again.

### Stop here if you want

At this point you have upgraded and nothing about your client leg has changed.
wg-easy still owns it. `client_awg.managed` defaults to **off**, and an unset
value means "keep wg-easy" — never "take over on upgrade".

The one new behaviour: the agent reads wg-easy's interface private key and
publishes the matching public key to the controller. You will see this in the
log as `adopted the client interface key from wg-easy`. It changes nothing; it
is preparation for Part 3.

---

## Part 2 — Import the credentials

This copies clients out of wg-easy's database into the controller store. It
**only reads** wg-easy's database, never writes to it, and never creates it.
Run it on the master, with the controller live.

### Dry run first

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml \
  --import-wg-easy master-xa-1 --plan
```

Add `--wg-easy-db /path/to/wg-easy.db` if it is not at the default
`/etc/wireguard/wg-easy.db`.

Read the report. Every line beginning `NOT MIGRATED` is a client that **will
lose its tunnel at cutover** unless you fix it first. The common causes:

| Report says | Fix |
|---|---|
| name is not safe to render into a config | rename in wg-easy to letters/digits/`-`/`_`/`.` |
| the public key / preshared key in wg-easy is not a valid WireGuard key | re-create that client in wg-easy |
| address is outside the configured pool | your `client_awg.address_pool` does not match what wg-easy handed out — fix the pool |
| address is already taken by another credential | duplicate in wg-easy; delete one |
| a different credential already uses this name | you already imported a different client under that name |

If the report ends with `NOTHING WAS MIGRATED`, every client was skipped for a
real reason. Do not proceed.

Fix, re-run the dry run, repeat until it is clean.

### Set the pool to match reality

The single most common failure is an address-pool mismatch. wgfleet allocates
from `client_awg.address_pool`; wg-easy allocated from whatever it was
configured with. They must be the same subnet, or every imported address falls
outside the pool.

```yaml
fleet:
  masters:
    - name: master-xa-1
      client_awg:
        address_pool: 10.8.0.0/24   # the subnet wg-easy actually used
```

### Apply

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml \
  --import-wg-easy master-xa-1
```

Credentials now exist in the controller store. **Nothing has happened to the
data path yet** — wg-easy still owns the interface, and the imported credentials
are inert. You can see them in the Web UI (node → *WireGuard clients*), where
the page tells you they do nothing yet.

The import is idempotent. Re-running it reports already-imported clients as
"already imported (same key and address) — nothing to do" and changes nothing,
so it is safe to run again after fixing a few names.

---

## Part 3 — Hand the interface over

One knob:

```yaml
fleet:
  masters:
    - name: master-xa-1
      client_awg:
        managed: true
```

Reload the controller. On the master's next reconcile the agent:

1. writes a claim file next to the interface config, marking the leg as ours;
2. adopts wg-easy's interface private key, so the server public key does not move;
3. renders the interface with the imported peers and raises it.

The wg-easy container keeps running and is simply no longer in the path. Leave
it alone for now — it is your rollback.

### Verify before you tell anyone

```bash
awg show wg0
```

Expect: your peers listed, handshakes appearing as clients reconnect. Then from
a client that has **not** been touched — an existing config on somebody's phone
— confirm traffic flows. That is the real test: it proves an old config works
against the new interface.

Then in the Web UI: mute a client, confirm its tunnel stops; unmute it, confirm
it returns. Issue a new client and import its config. Reboot the master and
confirm the interface comes back.

### Handing out configs from now on

Each credential has a **permanent portal link** shown on the client page, of the
form `<client_portal_url>/c/<id>`. Send that link to the person; they open it
and get their config and QR. The link does not change when you rename the
client, and the config is rendered fresh on every visit — so if the interface
parameters ever change, the same link serves the new config.

The portal has two knobs and both are required together:

```yaml
controller:
  client_portal: 10.8.0.1:8080          # MUST be the master's mgmt address
  client_portal_url: http://10.8.0.1:8080
fleet:
  masters:
    - name: master-xa-1
      client_admin_ports: [8080]         # opens the port to clients
```

Bind the portal on the **management address**, not `0.0.0.0` and not the client
pool gateway. A portal bound elsewhere is swallowed by the master's own client
redirect and simply times out.

### Rolling back

Only if the master's kernel module is 1.x or 2.x (see Pre-flight).

Set `managed: false`, reload, wait a reconcile. The agent drops its claim, takes
its interface down and leaves wg-easy's own state untouched — the container
never stopped and picks the leg back up. Imported credentials stay in the
controller store, inert, ready for a second attempt.

If the module is 3.x, there is no going back to wg-easy. Roll forward instead:
fix the problem and reconcile again.

### When you are confident

After a week or so, retire the container and stop paying its ~110 MB of RAM:

```bash
docker rm -f wg-easy
```

Keep `wg-easy.db` archived — it is the only record of the original allocation.

---

## Part 4 — AmneziaWG 3.x afterwards

Owning the client leg is what makes AmneziaWG 3.x reachable at all: we never
wrote 3.x parameters into wg-easy's database, so a wg-easy-owned leg is
permanently 2.0.

### What 3.x adds

On top of the 2.0 set your clients already carry (`Jc/Jmin/Jmax`, `S1–S4`,
`H1–H4`, `I1–I5`):

| Parameter | What it does |
|---|---|
| `HeaderProtectionKey` | chacha20 over the packet header. Requires `S1–S4 >= 12` — the nonce is read from those bytes, and a shorter pad makes the two ends derive different nonces while the interface stays UP. |
| `ContentPaddingAddition` | pads transport packets, breaking the packet-size profile. |
| `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` | ranges instead of constants, redrawn on every timer arm. This is the anti-fingerprint knob: a fixed 25-second keepalive is a timing signature that survives every payload-level obfuscation. |

### Only one of them breaks old clients

Measured against a real AmneziaWG 3.1.20260812 kernel module, both ends rendered
by the production renderers, two network namespaces:

| Server runs | Unmodified 2.0 client |
|---|---|
| full 3.x | **dead** — no handshake, 100% loss |
| the five timers only | works, 0% loss over 240 s across repeated rekeys |
| `ContentPaddingAddition` only | works, 0% loss including 1200-byte payloads |
| `HeaderProtectionKey` only | **dead** — no handshake |
| 2.0 (control) | works |

**`HeaderProtectionKey` is the only parameter that requires every client to be
reissued.** The timers can be enabled server-side with no client action at all,
and they carry the anti-fingerprint value.

### The staged path

**Stage 1 — no redistribution.** Enable the five timers. Requires a 3.x kernel
module on the master (the agent refuses a 3.x config the backend cannot carry,
keeping the last-good config rather than taking the leg down). Nobody
re-imports anything.

**Stage 2 — flag day, whenever you want it.** Add `HeaderProtectionKey`. Every
client must re-import. Because portal links are permanent and render on demand,
this is one announcement rather than a distribution: everyone reopens the link
they already have.

> **Stage 1 is not yet available in this release.** The client leg has no code
> path that applies 3.x parameters at all, and the generator emits header
> protection and the timers as one indivisible block. Both are tracked; until
> they land, the client leg is AmneziaWG 2.0 regardless of the fleet's `awg3`
> setting, which today governs only master↔exit tunnels.

---

## Troubleshooting

**Clients stopped working right after cutover, all of them.**
The adopted key did not match. Check the agent log for `adopted the client
interface key from wg-easy`; if it is absent, wg-easy's schema moved and the
agent minted a fresh key instead. Roll back (`managed: false`) if the module
allows it, and report the wg-easy version.

**One client stopped working.**
It was in the `NOT MIGRATED` list. Re-check the dry-run report, fix the cause in
wg-easy, re-run the import, and reconcile.

**The interface will not come up and the log says AmneziaWG 3.x refused.**
The fleet asks for 3.x parameters the master's kernel module cannot carry. The
agent deliberately keeps the last-good config rather than writing one it knows
`awg setconf` rejects. Upgrade the module or drop the 3.x parameters.

**The portal times out.**
It is bound somewhere other than the master's mgmt address, or its port is
missing from `client_admin_ports`. See Part 3.

**The Web UI shows clients but no *Download .conf* button.**
The master has not published its client interface public key yet. It appears
after one reconcile pass.

---

## See also

- `MASTER-MIGRATION.md` — moving a master to another VM, a different operation entirely
- `CONFIGURATION.md` — every knob mentioned here
- `SUPPORT-BUNDLE.md` — what to collect if you need help with any of the above
