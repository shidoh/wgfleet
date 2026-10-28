# AmneziaWG 3.x on the client interface

`fleet.masters[].client_awg.awg3` on the agent's client interface `wg0`.

| `awg3` | What it does | Re-import? | Reversible? |
|---|---|---|---|
| `off` | default | no | — |
| `timers` | randomises the 3.x timers | no client re-imports anything, and no config in the field becomes invalid | yes |
| `full` | adds header protection | **every client must re-import before it works again**; the new config cannot be delivered through the tunnel | **no** — reverting to `timers` breaks the config they just imported, in the same silent way |

## Enable

Optional, no deadline. Requires a 3.x kernel module on the master; with an older module the agent refuses the config and keeps the last-good one.

1. Upgrade the master's kernel module to 3.x (`prepare-node.sh --upgrade-awg`).
2. Set `awg3`, validate, restart the controller.

   ```yaml
           awg3: timers   # off | timers | full
   ```

   All keys: [configuration.md#client_awg-the-client-facing-amneziawg-listener](configuration.md#client_awg-the-client-facing-amneziawg-listener)

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

All keys: [configuration.md#3-fleet-fleet-wide-settings](configuration.md#3-fleet-fleet-wide-settings)

- A file rather than `secret://`, because only a file travels in `--backup`.
- Set it once and never change it. Rotating it re-derives the key on every 3.x tunnel: master↔exit tunnels go dark for up to one reconcile interval each, and every client config in the field becomes invalid at once.
- `timers` needs no secret.

### The `full` rollout

- Do not set `full` until you can reach every user.
- The self-service portal cannot carry this one to `.conf` holders: it is reachable only from inside the tunnel, and a link fetched *before* the flip hands out the pre-3.x config.
- Devices with a VLESS credential are the exception: the subscription refreshes over `<master>-vless` (within `Profile-Update-Interval: 24` h, or at once on a manual update) and brings the new AWG settings.
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

4. **Download and send.** Download every client's `.conf` from the console and send them out.

5. **Stay available.** From step 2 until each person imports, they are offline.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| interface will not come up, log says 3.x refused | module is older than the config asks for |
| "the VPN is connected but nothing loads" after `full` | the client still has a pre-`full` config — re-import |
| no `HeaderProtectionKey` in `awg showconf wg0` after `full` | the master has not converged yet — one reconcile pass |

## See also

- `CONFIGURATION.md` — every knob named here
- `SUPPORT-BUNDLE.md` — what to collect if you need help
