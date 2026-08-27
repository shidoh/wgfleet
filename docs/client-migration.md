# Moving the client leg off wg-easy

For a master whose clients are still served by wg-easy.

Four parts, each a separate decision. Stopping after any of them is fine.

1. Upgrade the binaries — required, does not touch the client leg
2. Import the credentials — reversible, changes nothing live
3. Hand the interface over — the cutover
4. AmneziaWG 3.x — optional, later

The handover is transparent: the agent adopts wg-easy's own interface key, so
**no config already handed out stops working.**

---

## Pre-flight

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

Wire contract 7 → 8. **Controller first.** The reverse order makes the master's
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
wgfleet-controller --version                           # wire-contract version 8
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

```yaml
        managed: true
```

Validate and restart the controller (there is no reload signal — `systemctl
reload` does not apply, and `kill -HUP` terminates it):

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

1. download every client's `.conf` from the Web UI and send them out, telling
   people to import **after** you say so;
2. wait for confirmation from each person;
3. only then set `full` and announce it.

It is not reversible for them either — going back to `timers` breaks the config
they just imported.

Requires `managed: true` and a 3.x module. With an older module the agent refuses
the config and keeps the last-good one rather than taking the leg down.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| every client dies at cutover | the key was not adopted — check the agent log for `adopted the client interface key from wg-easy`, then roll back |
| one client dies | it was in the `NOT MIGRATED` list |
| interface will not come up, log says 3.x refused | module is older than the config asks for |
| portal times out | bound somewhere other than the master's mgmt address, or its port is missing from `client_admin_ports` |
| no *Download .conf* button | the master has not published its interface key yet — one reconcile pass |

## See also

- `MASTER-MIGRATION.md` — moving a master to another VM, a different operation
- `CONFIGURATION.md` — every knob named here
- `SUPPORT-BUNDLE.md` — what to collect if you need help
