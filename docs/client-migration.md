# Moving the client leg off wg-easy

For a master whose clients are still served by wg-easy.

## Read this first

**Parts 1-3 are invisible to your users.** The agent adopts wg-easy's own interface
key, so every config already on someone's phone keeps working, untouched. Nobody has
to re-import anything and nobody needs to be told in advance.

**Part 4 is where it gets painful, and only one setting in it.** `awg3: full` adds
header protection, which every client must re-import before it works again — and you
cannot send the new config through the tunnel, because after the flip nobody is
inside the tunnel. That is a step you plan around people, not around the fleet. It is
optional, it can wait indefinitely, and nothing else in this document depends on it.

Four parts, each a separate decision:

| | What it is | Reversible? | Do users notice? |
|---|---|---|---|
| 1 | Upgrade the binaries | yes, `.prev` binaries | no |
| 2 | Import the credentials | yes, nothing goes live | no |
| 3 | Hand the interface over — the cutover | yes, until you issue a new client | no |
| 4 | AmneziaWG 3.x `timers` | yes | no |
| 4 | AmneziaWG 3.x `full` | **no** | **every one of them, at once** |

**Stopping after any part is a finished state, not a half-migration.** Most fleets
should do 1-3 and leave 4 alone until there is a reason. Part 3 is the one worth
doing: it is what moves credentials into the controller's store, so issuing, pausing,
renaming and revoking become console actions and each person gets a self-service link
instead of a file you have to re-send.

**If something goes wrong**, [Rollback](#rollback) is in part 3 and it is free right
up until you issue your first new client. Read it before you start part 3, not after.

**What to tell your users:** nothing, for parts 1-3. For part 4 `full`, see the
sequence at the end — it is the only step that needs their cooperation, and it needs
it from every one of them before you flip the switch.

---

## Pre-flight

Six checks. The first four ask *can this machine do the handover at all*; the last two
are your way back. None of them changes anything.

```bash
cat /sys/module/amneziawg/version    # kernel module generation
command -v awg awg-quick             # BOTH must be on the HOST — see below
docker images | grep wg-easy         # must be present locally — rollback needs it
ls -l /etc/wireguard/wg-easy.db      # must exist, holds your clients
docker restart wg-easy && sleep 3 && docker logs --tail 20 wg-easy   # rollback must actually work

wgfleet-controller --config /etc/wgfleet/controller.yaml --backup /root/pre-migration.age
cp /etc/wireguard/wg-easy.db /root/wg-easy.db.bak
cp /var/lib/wgfleet/state.db  /root/state.db.bak
```

**`awg` / `awg-quick` on the HOST.** wg-easy shipped its own copies inside the
container, so a master that only ever ran wg-easy may never have needed them
outside it. Without them the handover in part 3 cannot raise the interface at all.

**Module 3.x** ⇒ your wg-easy is already broken and will fail to raise the
interface on its next container restart (its bundled tools are generation 1).
Rollback in part 3 is unavailable; the migration is the fix.

**Client names** must be letters, digits, `-`, `_`, `.`, max 64. Anything else
does not migrate. Part 2's dry run names them.

`--backup` needs the `age` binary on PATH.

---

## 1. Upgrade the binaries

*Required. Reversible via the `.prev` binaries the deploy script leaves behind.
Your users see nothing — this part does not touch the client leg at all.*

Wire contract 7 → 8 for this migration (the contract has since moved to 10).
**Controller first.** The reverse order makes the master's
reconcile fail on every pass until the controller catches up.

```bash
systemctl stop wgfleet-controller
cp wgfleet-controller /usr/local/bin/wgfleet-controller
systemctl start wgfleet-controller
```

Store migrations run on first start. Rolling the binary back afterwards is safe —
they only add columns with defaults.

Then the exit agents:

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --rolling-upgrade --plan
wgfleet-controller --config /etc/wgfleet/controller.yaml --rolling-upgrade
```

**Agents are NOT upgraded automatically.** Auto-upgrade fires only for an agent
the controller cannot serve; wire 7 is still supported, so nothing happens on its
own and the exits stay on the old build until you run the command above.

On a co-located master upgrade its agent too — `deploy/deploy-master.sh --both`
detects the wire bump and orders the two correctly.

Verify:

```bash
wgfleet-controller --version                           # wire-contract version 10 today
docker ps --filter name=wg-easy --format '{{.Status}}'  # uptime unchanged

# THE CHECK THAT DECIDES WHETHER PART 3 WORKS. Run it here, not later.
awg show wg0 public-key                    # what wg-easy is serving right now
awg pubkey < /etc/wgfleet/client-wg.key    # what the agent will serve
```

**These two MUST match.** Every client config in the field pins the first value;
the handover works precisely because the agent adopts it instead of minting its
own. If they differ, the agent generated a fresh identity — and since an existing
key file wins on every later pass, nothing will ever re-adopt. Nothing looks wrong
until part 3, at which point every client stops handshaking at once.

If they differ: stop. Check that `/etc/wireguard/wg-easy.db` is where the agent
looks, `rm /etc/wgfleet/client-wg.key`, restart the agent, and re-run the check.
The agent also logs its identity once per start and reports a mismatch as an
ERROR — `journalctl -u wgfleet-agent | grep -i "client interface identity"`.

**Nothing else about the client interface changed.** `client_awg.managed` defaults
off and the rendered compose file is byte-identical, so the wg-easy container is
not recreated. You may stop here indefinitely — but do not skip the key check,
because the decision it verifies has already been made by the time you read this.

---

## 2. Import the credentials

*Reversible, and nothing goes live. This copies wg-easy's clients into the
controller's store where they sit inert; wg-easy still owns the interface and still
serves every one of them. You can run it, read the report, and walk away.*

**This is where you find out who will not survive the cutover**, while it is still
free to fix. Run the dry run, fix what it names, re-run until it is clean.

Reads wg-easy's database, never writes to it. Run on the master, controller live.

The pool must match what wg-easy handed out:

```yaml
fleet:
  masters:
    - name: master-xa-1
      client_awg:
        address_pool: 10.73.0.0/24
```

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml \
  --import-wg-easy master-xa-1 --plan
```

Add `--wg-easy-db PATH` if it is not at `/etc/wireguard/wg-easy.db`.

Every `NOT MIGRATED` line is a client that **loses its tunnel at cutover**:

| Report says | Fix |
|---|---|
| name is not safe to render into a config | rename it in wg-easy |
| key is not a valid WireGuard key | re-create that client in wg-easy |
| address is outside the configured pool | fix `address_pool` above |
| address is already taken | duplicate in wg-easy, delete one |
| the private key in wg-easy is unusable | re-create that client in wg-easy, then re-run |
| private and public keys do not match | wg-easy's row is corrupt: delete and re-create that client, then re-run |

Re-run until clean, then:

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --import-wg-easy master-xa-1
```

Idempotent. Nothing has happened to the data path — wg-easy still owns the
interface and the imported credentials are inert.

---

## 3. Hand the interface over

*The cutover. Reversible until you issue your first new client — after that a
rollback strands the people you issued. Your users see nothing: the agent adopts
wg-easy's interface key, so the configs on their phones keep working.*

**What actually happens:** on the next reconcile pass the agent takes `wg0` over
with the same key and the peers you imported in part 2, and wg-easy is retired one
pass later, only after a pass has observed the new interface up and serving. If the
bring-up fails, wg-easy is still there — that is why it lingers.

**Read [Rollback](#rollback) below before you do this.**

```yaml
        managed: true
```

Validate and restart the controller (there is no reload signal — `systemctl
reload` does not apply; `kill -HUP` is caught and logged, and changes nothing):

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
systemctl restart wgfleet-controller
```

On the master's next reconcile the agent claims the interface, adopts wg-easy's
key and raises it with the imported peers.

```bash
awg show wg0 public-key     # SAME key as before the cutover
awg show wg0 peers | wc -l  # your client count
ls /etc/amnezia/amneziawg/wg0.conf.claim
```

Then connect from a device whose config you did **not** touch. That is the test
that matters.

**wg-easy is removed one pass LATER**, not in the pass that raises our interface.
The agent retires it only after a subsequent pass has OBSERVED the interface up
and serving the right peers — so a bring-up that fails leaves the fallback exactly
where it was. Expect the container to linger for one reconcile interval; that is
the design, not a stuck teardown. Your rollback is not the container anyway; it is
wg-easy's database plus its image, both checked in pre-flight.

### Rollback

*Free until you issue your first new client. After that it strands exactly those
people — see the warning at the end of this section.*

Only if the module is 1.x or 2.x.

```yaml
        managed: false
```

Validate, restart, wait one reconcile. The agent releases the interface, compose
puts wg-easy back and recreates it from the local image; it reads its untouched
database and takes the client interface again. Imported credentials stay in the
store.

**Anyone you issued AFTER the cutover exists only in the controller's store.**
wg-easy has never heard of them, so a rollback strands exactly those people — they
are not in the database it reads. Rollback is free only until you issue the first
new client; after that, plan to re-hand-out those configs by hand.

Archive `wg-easy.db` off the box — it is what a rollback reads.

---

## 4. AmneziaWG 3.x

*Optional, and there is no deadline. Two settings with very different costs:
`timers` is invisible and reversible; `full` requires **every** user to re-import
before their tunnel works again, and you cannot deliver the new config through the
tunnel. Do not start this part on the same evening as part 3.*

**Which one do you want?** `timers` if you want the 3.x timing behaviour and nothing
else — it costs your users nothing. `full` only when you have a concrete reason to
want header protection AND you can reach every single user to coordinate. If you
cannot list your users by name right now, you are not ready for `full`.

**The order is forced.** The wg-easy image carries generation-1 tools, so
upgrading the master's kernel module while that image is still in use breaks it:

1. finish part 3 and confirm it
2. drop the wg-easy image once you no longer want the rollback
3. upgrade the master's kernel module to 3.x
4. only then set `awg3` — and validate before restarting, exactly as in part 3:

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
systemctl restart wgfleet-controller
```

```yaml
        awg3: timers   # off | timers | full
```

**`timers`** — randomises the 3.x timers. Measured against a real 3.1 module: an
untouched 2.0 client keeps handshaking and passing traffic across rekeys. **No
client re-imports anything.**

**`full` also needs a fleet secret.** Header protection is keyed on
`fleet.awg3_key`, and the controller REFUSES TO START without it — so on a night
when you have already dropped the wg-easy image and handed out every config, a
missing key takes the control plane down rather than the tunnel up:

```yaml
fleet:
  awg3_key: secret://awg3-key   # openssl rand -base64 48
```

Set it once and never change it. Rotating it re-derives the key on every 3.x
tunnel: the master↔exit tunnels go dark for up to one reconcile interval each
(both ends are rendered by one controller but applied by seven agents on their own
schedules), and every client config in the field becomes invalid at once, exactly
as if you were flipping `full` again. `timers` needs no secret.

**`full`** — adds header protection. **Every client must re-import before it works
again.** Do not set it until you can reach every user.

**The portal cannot carry this one.** It binds a mgmt/client-pool address, so it
is reachable only from inside the tunnel — and after the flip nobody is inside the
tunnel. Fetching a link *before* the flip is no better: the portal renders from the
live spec, so it hands out the pre-3.x config. The order that works is:

1. download every client's `.conf` from the Web UI and send them out over whatever
   channel you use with those people — not the portal — telling them to save it and
   **not** import it yet;
2. wait until every single person has confirmed they have the file. Not most of
   them: the ones who have not are the ones who will be cut off with no way to reach
   you through the tunnel;
3. only then set `full`, restart, and tell everyone to import now;
4. stay available. Whoever imports late, or imports the wrong file, is offline until
   you hear from them on another channel.

Going back does not rescue them either: reverting to `timers` breaks the config they
have just imported, so a botched flip is two rounds of re-handout, not one.

**Do this when you can afford the evening**, with the fleet otherwise quiet, and not
straight after part 3. If you have more users than you can personally chase, that is
the signal to stay on `timers`.

Requires `managed: true` and a 3.x module. With an older module the agent refuses
the config and keeps the last-good one rather than taking the leg down.

---

## Troubleshooting

First, the two questions people ask at 2am:

- **"Did I just cut everyone off?"** Check `awg show wg0 peers | wc -l` against your
  client count and `awg show wg0 public-key` against what it was before. If the key
  changed, the adoption failed — roll back (part 3) and read the agent log for
  `adopted the client interface key from wg-easy`.
- **"Can I undo this?"** Yes, until you issued a new client after the cutover. See
  [Rollback](#rollback). The wg-easy database and image you saved in pre-flight are
  what it needs; nothing in the store has to be undone.

| Symptom | Cause |
|---|---|
| every client dies at cutover | the key was not adopted — check the agent log for `adopted the client interface key from wg-easy`, then roll back |
| one client dies | it was in the `NOT MIGRATED` list |
| interface will not come up, log says 3.x refused | module is older than the config asks for |
| portal times out | bound somewhere other than the master's mgmt address, or its port is missing from `client_admin_ports` |
| no *Download .conf* button | the master has not published its interface key yet — one reconcile pass |
| import says a client is `NOT MIGRATED` and you do not know why | the table in part 2 lists every reason and its fix; nothing is live yet, so take your time |
| wg-easy container still running after the cutover | by design — it is retired one pass after a pass observed the new interface serving. Give it one reconcile interval |
| a user says "it stopped working" and you did parts 1-3 only | it is not this migration: those parts do not change any config in the field. Check the node's health and the master↔exit tunnels first |

## See also

- `MASTER-MIGRATION.md` — moving a master to another VM, a different operation
- `CONFIGURATION.md` — every knob named here
- `SUPPORT-BUNDLE.md` — what to collect if you need help
