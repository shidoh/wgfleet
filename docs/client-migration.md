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
docker images | grep wg-easy         # must be present locally — rollback needs it
ls -l /etc/wireguard/wg-easy.db      # must exist, holds your clients

wgfleet-controller --config /etc/wgfleet/controller.yaml --backup /root/pre-migration.age
cp /etc/wireguard/wg-easy.db /root/wg-easy.db.bak
cp /var/lib/wgfleet/state.db  /root/state.db.bak
```

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
```

**Nothing about the client leg changed.** `client_awg.managed` defaults off and
the rendered compose file is byte-identical, so the wg-easy container is not
recreated. You may stop here indefinitely.

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

Reload the controller. On the master's next reconcile the agent claims the
interface, adopts wg-easy's key and raises it with the imported peers.

```bash
awg show wg0 public-key     # SAME key as before the cutover
awg show wg0 peers | wc -l  # your client count
ls /etc/amnezia/amneziawg/wg0.conf.claim
```

Then connect from a device whose config you did **not** touch. That is the test
that matters.

**The wg-easy container is removed in this same pass** — after the interface is
up, never before. Your rollback is not the container; it is wg-easy's database
plus its image, both checked in pre-flight.

### Rollback

Only if the module is 1.x or 2.x.

```yaml
        managed: false
```

Reload, wait one reconcile. The agent releases the interface, compose puts
wg-easy back and recreates it from the local image; it reads its untouched
database and takes the leg again. Imported credentials stay in the store.

Archive `wg-easy.db` off the box — it is what a rollback reads.

---

## 4. AmneziaWG 3.x

**The order is forced.** The wg-easy image carries generation-1 tools, so
upgrading the master's kernel module while that image is still in use breaks it:

1. finish part 3 and confirm it
2. drop the wg-easy image once you no longer want the rollback
3. upgrade the master's kernel module to 3.x
4. only then set `awg3`

```yaml
        awg3: timers   # off | timers | full
```

**`timers`** — randomises the 3.x timers. Measured against a real 3.1 module: an
untouched 2.0 client keeps handshaking and passing traffic across rekeys. **No
client re-imports anything.**

**`full`** — adds header protection. **Every client must re-import before it works
again.** Do not set it until you can reach every user. Portal links are permanent
and render on demand, so this is one announcement, not a redistribution.

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
