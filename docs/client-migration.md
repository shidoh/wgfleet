# Moving the client leg off wg-easy

For a master whose clients are still served by wg-easy.

## Read this first

**Parts 1-3 are invisible to your users.** The agent adopts wg-easy's own interface
key, so every config already in the field keeps working. Nobody re-imports anything.

**Part 4 `awg3: full`** adds header protection; every client must re-import before
it works again, and the new config cannot be delivered through the tunnel. It is
optional and nothing else depends on it.

Four parts, each a separate decision:

| | What it is | Reversible? | Do users notice? |
|---|---|---|---|
| 1 | Upgrade the binaries | yes, `.prev` binaries | no |
| 2 | Import the credentials | yes, nothing goes live | no |
| 3 | Hand the interface over — the cutover | yes, until you issue a new client | no |
| 4 | AmneziaWG 3.x `timers` | yes | a reconnect blip; needs the master's module on 3.x first |
| 4 | AmneziaWG 3.x `full` | **no** | **every one of them, at once** |

**Stopping after any part is a finished state.** Part 3 is the one that moves
credentials into the controller's store, so issuing, pausing, renaming and revoking
become console actions and each person gets a self-service link.

**One check decides everything.** [The key check](#1a-the-key-check--do-not-skip-this)
at the end of part 1 verifies that the agent will adopt wg-easy's identity rather
than mint its own. It fails silently, and its failure is the only way this
migration cuts everyone off at once. Run it even if you stop after part 1.

**If something goes wrong**, [Rollback](#rollback) in part 3 is free until you
issue your first new client. Read it before starting part 3.

---

## Pre-flight

Neither block changes anything.

**Can this machine do the handover?** A "no" to any line is a reason to stop and
fix it first.

```bash
cat /sys/module/amneziawg/version    # kernel module generation
command -v awg awg-quick             # BOTH must be on the HOST — see below
docker images | grep wg-easy         # must be present locally — rollback needs it
ls -l /etc/wireguard/wg-easy.db      # must exist, holds your clients
docker restart wg-easy && sleep 3 && docker logs --tail 20 wg-easy   # rollback must actually work
```

**Your way back.** Take these even if you are only doing part 1:

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --backup /root/pre-migration.age
cp /etc/wireguard/wg-easy.db /root/wg-easy.db.bak
cp /var/lib/wgfleet/state.db  /root/state.db.bak
```

`--backup` needs the `age` binary on PATH.

**`awg` / `awg-quick` on the HOST.** wg-easy ships its own copies inside the
container; without host copies the handover in part 3 cannot raise the interface.

**Module 3.x** ⇒ wg-easy needs the v15.4.0 image (generation-3 tools); v15.3.0
fails to raise the interface on a 3.x module. An agent of v0.2.4 or later recreates
the container from the right image by itself. On an older agent wg-easy is already
broken (`docker ps` shows `unhealthy`, `docker logs wg-easy` shows
`Invalid argument`) and this migration is the fix.

**Client names** must be letters, digits, `-`, `_`, `.`, max 64. Anything else
does not migrate; part 2's dry run names them.

---

## 1. Upgrade the binaries

*Required. Reversible via the `.prev` binaries the deploy script leaves behind.
Does not touch the client leg.*

**Controller first.** An agent newer than its controller is refused a spec, so the
reverse order makes the master's reconcile fail on every pass until the controller
catches up. The deploy script orders the two itself when the wire contract moves
forward; installing by hand, install the controller first.

```bash
systemctl stop wgfleet-controller
cp wgfleet-controller /usr/local/bin/wgfleet-controller
systemctl start wgfleet-controller
```

Store migrations run on first start and only add columns with defaults; rolling
the binary back afterwards is safe.

Then the exit agents:

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --rolling-upgrade --plan
wgfleet-controller --config /etc/wgfleet/controller.yaml --rolling-upgrade
```

**Agents are not upgraded automatically** while the controller still serves their
contract; the exits stay on the old build until you run the command above.

On a co-located master upgrade its agent too — `./deploy-master.sh --both` orders
the two correctly.

Verify:

```bash
wgfleet-controller --version                            # build and wire contract
docker ps --filter name=wg-easy --format '{{.Status}}'  # uptime unchanged: nothing restarted
```

`client_awg.managed` defaults off and the rendered compose file is unchanged, so
wg-easy is not recreated. You may stop after this part — but not before the next one.

### 1a. The key check — do not skip this

*Failure here means **every client stops working at once** at part 3, and nothing
looks wrong until then. Run it now, even if part 3 is weeks away.*

```bash
awg show wg0 public-key                    # what wg-easy is serving right now
awg pubkey < /etc/wgfleet/client-wg.key    # what the agent will serve
```

**These two MUST print the same key.** Every client config in the field pins the
first value. The agent adopts the key on a pass where it has none of its own, and
an existing key file wins on every later pass — so if it once minted a fresh
identity (because it could not find wg-easy's database), nothing re-adopts on
its own.

**If they differ, stop here.** Do not proceed to part 2.

```bash
# 1. is the database where the agent looks?
ls -l /etc/wireguard/wg-easy.db

# 2. what did the agent decide, and why?
journalctl -u wgfleet-agent | grep -i "client interface identity"
#    a mismatch is logged as an ERROR, once per agent start

# 3. discard the wrongly-minted key and let it adopt again
rm /etc/wgfleet/client-wg.key
systemctl restart wgfleet-agent

# 4. re-run the two commands above until they match
```

---

## 2. Import the credentials

*Reversible, nothing goes live. Copies wg-easy's clients into the controller's
store where they sit inert; wg-easy still owns the interface.*

Reads wg-easy's database, never writes to it. Run on the master, controller live.
Run the dry run, fix what it names, re-run until it is clean.

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

Idempotent. wg-easy still owns the interface; the imported credentials are inert.

---

## 3. Hand the interface over

*The cutover. Reversible until you issue your first new client — after that a
rollback strands the people you issued. Users see nothing: the agent adopts
wg-easy's interface key.*

On the next reconcile pass the agent takes `wg0` over with the same key and the
peers imported in part 2. wg-easy is retired one pass later, only after a pass has
observed the new interface up and serving; a failed bring-up leaves wg-easy in place.

**Before you do this:** the [key check](#1a-the-key-check--do-not-skip-this)
passed, and you have read [Rollback](#rollback) below.

```yaml
        managed: true
```

Validate and restart the controller (there is no reload signal; `kill -HUP` is
logged and changes nothing):

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
systemctl restart wgfleet-controller
```

After the master's next reconcile:

```bash
awg show wg0 public-key     # SAME key as before the cutover
awg show wg0 peers | wc -l  # your client count
ls /etc/amnezia/amneziawg/wg0.conf.claim
```

Then connect from a device whose config you did **not** touch. That is the test
that matters.

Expect the wg-easy container to linger for one reconcile interval; that is not a
stuck teardown. Your rollback is wg-easy's database plus its image, both checked
in pre-flight, not the container.

### Rollback

*Free until you issue your first new client.*

```yaml
        managed: false
```

Validate, restart, wait one reconcile. The agent releases the interface, compose
puts wg-easy back from the image matching the module's generation (v15.4.0 on a
3.x module — pulled if not local); it reads its untouched database and takes the
client interface again. Imported credentials stay in the store.

**Anyone you issued AFTER the cutover exists only in the controller's store.**
wg-easy has never heard of them, so a rollback strands exactly those people; plan
to re-hand-out their configs by hand.

Archive `wg-easy.db` off the box — it is what a rollback reads.

---

## 4. AmneziaWG 3.x

*Optional, no deadline. `timers` is reversible and needs no re-import; `full`
requires **every** user to re-import, and the new config cannot be delivered
through the tunnel. Do not start this part on the same evening as part 3.*

Requires `managed: true` and a 3.x module on the master. With an older module the
agent refuses the config and keeps the last-good one rather than taking the leg down.

**The order is forced.** The wg-easy image carries generation-1 tools, so upgrading
the master's kernel module while that image is still in use breaks it:

1. finish part 3 and confirm it
2. drop the wg-easy image once you no longer want the rollback
3. upgrade the master's kernel module to 3.x
4. only then set `awg3`, then validate and restart exactly as in part 3:

```yaml
        awg3: timers   # off | timers | full
```

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
systemctl restart wgfleet-controller
```

**`timers`** — randomises the 3.x timers. No client re-imports anything and no
config in the field becomes invalid. When the change lands the master rewrites and
reloads its client interface, so clients reconnect on their own within about twenty
seconds. Expect a blip, not an outage.

**`full`** — adds header protection. **Every client must re-import before it works
again.** Do not set it until you can reach every user.

What `full` looks like from the user's side: the old client stops passing traffic
within seconds, not at the next rekey, and nothing on the client says so. The
interface stays **UP**, `awg show` keeps printing a "latest handshake" that just
gets older, and on a phone the VPN toggle stays green. The report you will get is
**"the VPN is connected but nothing loads"**. Say in the announcement, in those
words, that the tunnel will look connected and be dead, and that the fix is to
import the new file. Reverting to `timers` breaks the config they just imported in
the same silent way.

**`full` needs a fleet secret.** The controller refuses to start without it:

```yaml
fleet:
  awg3_key: file:///etc/wgfleet/awg3.key   # openssl rand -base64 48 > /etc/wgfleet/awg3.key; chmod 600
```

A file rather than `secret://`, because only a file travels in `--backup`. Set it
once and never change it. Rotating it re-derives the key on every 3.x
tunnel: master↔exit tunnels go dark for up to one reconcile interval each, and
every client config in the field becomes invalid at once. `timers` needs no secret.

**The self-service portal cannot carry this one.** It is reachable only from inside
the tunnel, and a link fetched *before* the flip hands out the pre-3.x config. The
order that works:

1. **Warn people first, and hand out nothing yet.** Tell them a new file is coming,
   that the tunnel will look connected and be dead until they import it, and on
   what channel to expect it. That channel must reach every one of them.
2. **Set `full`, validate, restart.** The configs are rendered from the live spec,
   so anything downloaded before this moment will never connect.

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   ```

3. **Wait for the master to converge, then download.** Confirm header protection is
   live before handing anything out:

   ```bash
   awg showconf wg0 | grep -c HeaderProtectionKey   # must print 1
   ```

   Then download every client's `.conf` from the Web UI and send them out.
4. **Stay available.** From step 2 until each person imports, they are offline.

There is no ordering that avoids the outage window: the file that works cannot
exist until the flip that breaks the old one. A botched flip is two rounds of
re-handout, not one.

---

## Troubleshooting

- **"Did I just cut everyone off?"** Check `awg show wg0 peers | wc -l` against your
  client count and `awg show wg0 public-key` against what it was before. If the key
  changed, the adoption failed — roll back (part 3) and read the agent log for
  `adopted the client interface key from wg-easy`.
- **"Can I undo this?"** Yes, until you issued a new client after the cutover. See
  [Rollback](#rollback); it needs the wg-easy database and image from pre-flight.

| Symptom | Cause |
|---|---|
| every client dies at cutover | the key was not adopted — check the agent log for `adopted the client interface key from wg-easy`, then roll back |
| one client dies | it was in the `NOT MIGRATED` list |
| interface will not come up, log says 3.x refused | module is older than the config asks for |
| portal times out | bound somewhere other than the master's mgmt address, or its port is missing from `client_admin_ports` |
| no *Download .conf* button | the master has not published its interface key yet — one reconcile pass |
| import says a client is `NOT MIGRATED` | the table in part 2 lists every reason and its fix; nothing is live yet |
| wg-easy container still running after the cutover | by design — it is retired one pass after a pass observed the new interface serving |
| a user says "it stopped working" and you did parts 1-3 only | not this migration: those parts change no config in the field. Check the node's health and the master↔exit tunnels first |

## See also

- `MASTER-MIGRATION.md` — moving a master to another VM, a different operation
- `CONFIGURATION.md` — every knob named here
- `SUPPORT-BUNDLE.md` — what to collect if you need help
