# Moving the client leg off wg-easy

For a master whose clients are still served by wg-easy.

## Read this first

Four parts, each a separate decision. Stopping after any part is a finished state.

| | What it is | Reversible? | Do users notice? |
|---|---|---|---|
| 1 | Upgrade the binaries | yes, `.prev` binaries | no |
| 2 | Import the credentials | yes, nothing goes live | no |
| 3 | Hand the interface over — the cutover | yes, until you issue a new client | no |
| 4 | AmneziaWG 3.x `timers` | yes | a reconnect blip; needs the master's module on 3.x first |
| 4 | AmneziaWG 3.x `full` | **no** | **every one of them, at once** |

- Parts 1-3 are invisible to your users: the agent adopts wg-easy's own interface key, every config already in the field keeps working, nobody re-imports anything.
- Part 4 `awg3: full` adds header protection; every client must re-import before it works again, and the new config cannot be delivered through the tunnel. It is optional and nothing else depends on it.
- Part 3 is the one that moves credentials into the controller's store, so issuing, pausing, renaming and revoking become console actions and each person gets a self-service link.
- [The key check](#1a-the-key-check--do-not-skip-this) at the end of part 1 verifies that the agent will adopt wg-easy's identity rather than mint its own. It fails silently, and its failure is the only way this migration cuts everyone off at once. Run it even if you stop after part 1.
- [Rollback](#rollback) in part 3 is free until you issue your first new client. Read it before starting part 3.

---

## Pre-flight

Nothing in this section changes anything. A "no" to any line is a reason to stop and fix it first.

- [ ] `cat /sys/module/amneziawg/version` — kernel module generation.
- [ ] `command -v awg awg-quick` — BOTH must be on the HOST. wg-easy ships its own copies inside the container; without host copies the handover in part 3 cannot raise the interface.
- [ ] `docker images | grep wg-easy` — must be present locally; rollback needs it.
- [ ] `ls -l /etc/wireguard/wg-easy.db` — must exist, holds your clients.
- [ ] `docker restart wg-easy && sleep 3 && docker logs --tail 20 wg-easy` — rollback must actually work.
- [ ] On a 3.x module, wg-easy needs the v15.4.0 image (generation-3 tools); v15.3.0 fails to raise the interface on a 3.x module. An agent of v0.2.4 or later recreates the container from the right image by itself.
- [ ] On an older agent with a 3.x module wg-easy is already broken — `docker ps` shows `unhealthy`, `docker logs wg-easy` shows `Invalid argument` — and this migration is the fix.
- [ ] Client names are letters, digits, `-`, `_`, `.`, max 64. Anything else does not migrate; part 2's dry run names them.

Take your way back, even if you are only doing part 1:

```bash
wgfleet-controller --config /etc/wgfleet/controller.yaml --backup /root/pre-migration.age
cp /etc/wireguard/wg-easy.db /root/wg-easy.db.bak
cp /var/lib/wgfleet/state.db  /root/state.db.bak
```

`--backup` needs the `age` binary on PATH.

---

## 1. Upgrade the binaries

Required. Reversible via the `.prev` binaries the deploy script leaves behind. Does not touch the client leg.

**Controller first, then the agents.** An agent newer than its controller is refused a spec, so the reverse order makes the master's reconcile fail on every pass until the controller catches up. The deploy script orders the two itself when the wire contract moves forward; installing by hand, install the controller first.

1. Install the controller.

   ```bash
   systemctl stop wgfleet-controller
   cp wgfleet-controller /usr/local/bin/wgfleet-controller
   systemctl start wgfleet-controller
   ```

   Store migrations run on first start and only add columns with defaults; rolling the binary back afterwards is safe.

2. Plan, then run, the rolling upgrade of the exit agents.

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --rolling-upgrade --plan
   wgfleet-controller --config /etc/wgfleet/controller.yaml --rolling-upgrade
   ```

   Agents are not upgraded automatically while the controller still serves their contract; the exits stay on the old build until you run this.

3. On a co-located master, upgrade its agent too.

   ```bash
   ./deploy-master.sh --both
   ```

   Orders the controller and the agent correctly.

4. Verify.

   ```bash
   wgfleet-controller --version                            # build and wire contract
   docker ps --filter name=wg-easy --format '{{.Status}}'  # uptime unchanged: nothing restarted
   ```

   `client_awg.managed` defaults off and the rendered compose file is unchanged, so wg-easy is not recreated.

5. Run the key check below. You may stop after this part — but not before the key check.

### 1a. The key check — do not skip this

Failure here means **every client stops working at once** at part 3, and nothing looks wrong until then. Run it now, even if part 3 is weeks away.

1. Compare the two keys.

   ```bash
   awg show wg0 public-key                    # what wg-easy is serving right now
   awg pubkey < /etc/wgfleet/client-wg.key    # what the agent will serve
   ```

   **These two MUST print the same key**, because every client config in the field pins the first value. **If they differ, stop here** — do not proceed to part 2.

2. Check that the database is where the agent looks.

   ```bash
   ls -l /etc/wireguard/wg-easy.db
   ```

   The agent adopts the key on a pass where it has none of its own, and an existing key file wins on every later pass — so if it once minted a fresh identity (because it could not find wg-easy's database), nothing re-adopts on its own.

3. Read what the agent decided, and why.

   ```bash
   journalctl -u wgfleet-agent | grep -i "client interface identity"
   ```

   A mismatch is logged as an ERROR, once per agent start.

4. Discard the wrongly-minted key and let it adopt again.

   ```bash
   rm /etc/wgfleet/client-wg.key
   systemctl restart wgfleet-agent
   ```

5. Re-run step 1 until the two keys match.

---

## 2. Import the credentials

Reversible, nothing goes live. Copies wg-easy's clients into the controller's store where they sit inert; wg-easy still owns the interface.

1. Set the pool to match what wg-easy handed out.

   ```yaml
   fleet:
     masters:
       - name: master-xa-1
         client_awg:
           address_pool: 10.73.0.0/24
   ```

2. Dry-run the import. Run it on the master, controller live; it reads wg-easy's database and never writes to it. Add `--wg-easy-db PATH` if the database is not at `/etc/wireguard/wg-easy.db`.

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml \
     --import-wg-easy master-xa-1 --plan
   ```

3. Fix every `NOT MIGRATED` line and re-run step 2 until the report is clean. Each one is a client that **loses its tunnel at cutover**.

   | Report says | Fix |
   |---|---|
   | name is not safe to render into a config | rename it in wg-easy |
   | key is not a valid WireGuard key | re-create that client in wg-easy |
   | address is outside the configured pool | fix `address_pool` above |
   | address is already taken | duplicate in wg-easy, delete one |
   | the private key in wg-easy is unusable | re-create that client in wg-easy, then re-run |
   | private and public keys do not match | wg-easy's row is corrupt: delete and re-create that client, then re-run |

4. Import for real.

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --import-wg-easy master-xa-1
   ```

   Idempotent. wg-easy still owns the interface; the imported credentials are inert.

---

## 3. Hand the interface over

The cutover. Reversible until you issue your first new client — after that a rollback strands the people you issued. Users see nothing: the agent adopts wg-easy's interface key.

Before you start: the [key check](#1a-the-key-check--do-not-skip-this) passed, and you have read [Rollback](#rollback) below.

1. Set the knob.

   ```yaml
           managed: true
   ```

2. Validate and restart the controller. There is no reload signal; `kill -HUP` is logged and changes nothing.

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   ```

3. After the master's next reconcile pass, verify. The agent takes `wg0` over with the same key and the peers imported in part 2.

   ```bash
   awg show wg0 public-key     # SAME key as before the cutover
   awg show wg0 peers | wc -l  # your client count
   ls /etc/amnezia/amneziawg/wg0.conf.claim
   ```

4. Connect from a device whose config you did **not** touch. That is the test that matters.

5. Expect the wg-easy container to linger for one reconcile interval; that is not a stuck teardown. It is retired one pass after a pass has observed the new interface up and serving; a failed bring-up leaves wg-easy in place.

### Rollback

Free until you issue your first new client. Your rollback is wg-easy's database plus its image, both checked in pre-flight, not the container.

1. Set the knob back.

   ```yaml
           managed: false
   ```

2. Validate and restart the controller, then wait one reconcile.

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   ```

   The agent releases the interface, compose puts wg-easy back from the image matching the module's generation (v15.4.0 on a 3.x module — pulled if not local); it reads its untouched database and takes the client interface again. Imported credentials stay in the store.

3. Re-hand-out by hand the configs of anyone you issued AFTER the cutover. They exist only in the controller's store, wg-easy has never heard of them, so a rollback strands exactly those people.

4. Archive `wg-easy.db` off the box — it is what a rollback reads.

---

## 4. AmneziaWG 3.x

Optional, no deadline. Do not start this part on the same evening as part 3. Requires `managed: true` and a 3.x module on the master; with an older module the agent refuses the config and keeps the last-good one rather than taking the leg down.

| `awg3` | What it does | Re-import? | Reversible? |
|---|---|---|---|
| `off` | default | no | — |
| `timers` | randomises the 3.x timers | no client re-imports anything, and no config in the field becomes invalid | yes |
| `full` | adds header protection | **every client must re-import before it works again**; the new config cannot be delivered through the tunnel | **no** — reverting to `timers` breaks the config they just imported, in the same silent way |

**The order is forced.** The wg-easy image carries generation-1 tools, so upgrading the master's kernel module while that image is still in use breaks it.

1. Finish part 3 and confirm it.
2. Drop the wg-easy image once you no longer want the rollback.
3. Upgrade the master's kernel module to 3.x.
4. Only then set `awg3`, and validate and restart exactly as in part 3.

   ```yaml
           awg3: timers   # off | timers | full
   ```

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   ```

   When `timers` lands the master rewrites and reloads its client interface, so clients reconnect on their own within about twenty seconds. Expect a blip, not an outage.

### The `full` secret

`full` needs a fleet secret; the controller refuses to start without it.

```yaml
fleet:
  awg3_key: file:///etc/wgfleet/awg3.key   # openssl rand -base64 48 > /etc/wgfleet/awg3.key; chmod 600
```

- A file rather than `secret://`, because only a file travels in `--backup`.
- Set it once and never change it. Rotating it re-derives the key on every 3.x tunnel: master↔exit tunnels go dark for up to one reconcile interval each, and every client config in the field becomes invalid at once.
- `timers` needs no secret.

### The `full` rollout

- Do not set `full` until you can reach every user.
- The self-service portal cannot carry this one: it is reachable only from inside the tunnel, and a link fetched *before* the flip hands out the pre-3.x config.
- What it looks like from the user's side: the old client stops passing traffic within seconds, not at the next rekey, and nothing on the client says so. The interface stays **UP**, `awg show` keeps printing a "latest handshake" that just gets older, and on a phone the VPN toggle stays green. The report you will get is **"the VPN is connected but nothing loads"**.
- There is no ordering that avoids the outage window: the file that works cannot exist until the flip that breaks the old one. A botched flip is two rounds of re-handout, not one.

1. **Warn people first, and hand out nothing yet.** Tell them a new file is coming, that the tunnel will look connected and be dead until they import it, that the fix is to import the new file, and on what channel to expect it. Say it in those words. That channel must reach every one of them.

2. **Set `full`, validate, restart.** The configs are rendered from the live spec, so anything downloaded before this moment will never connect.

   ```yaml
           awg3: full
   ```

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   ```

3. **Wait for the master to converge**, then confirm header protection is live before handing anything out.

   ```bash
   awg showconf wg0 | grep -c HeaderProtectionKey   # must print 1
   ```

4. **Download and send.** Download every client's `.conf` from the Web UI and send them out.

5. **Stay available.** From step 2 until each person imports, they are offline.

---

## Troubleshooting

- **"Did I just cut everyone off?"** Check `awg show wg0 peers | wc -l` against your client count and `awg show wg0 public-key` against what it was before. If the key changed, the adoption failed — roll back (part 3) and read the agent log for `adopted the client interface key from wg-easy`.
- **"Can I undo this?"** Yes, until you issued a new client after the cutover. See [Rollback](#rollback); it needs the wg-easy database and image from pre-flight.

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
