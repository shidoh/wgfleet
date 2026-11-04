# AmneziaWG 3.x on the client interface

`fleet.masters[].client_awg.awg3` on the agent's client interface `wg0`.

| `awg3` | Master's `wg0` | Client `.conf`, mihomo profile, lifeline configs | Re-import? | Reversible? |
|---|---|---|---|---|
| `off` | AmneziaWG 2.0 | AmneziaWG 2.0 | no | — |
| `timers` | adds `RekeyAfterTime` and `KeepaliveTimeout` ranges | unchanged, byte for byte the same as `off` | no | yes |
| `full` | adds the timers, `HeaderProtectionKey`, `RandomTrailers = on`, one padding size for S1–S4 and H1–H4 = 1–4 | the same shared values (mihomo: `version: 3`, `random-trailers: true`); no timers | subscriptions with a provider: no; `.conf` and lifeline: yes — see [The `full` rollout](#the-full-rollout) | **no** — reverting to `timers` breaks the configs devices just picked up, in the same silent way |

The timers are per end: a client on the default timers works against a `wg0` with randomised ones, so client configs never carry them. Apps that refuse AmneziaWG 3.x settings (AmneziaWG 2.x apps, AmneziaVPN before 5.0.0.5, older mihomo cores) keep working under `timers`.

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

   When `timers` lands the master rewrites and reloads its client interface, so clients reconnect on their own within about twenty seconds. Expect a blip, not an outage. Exits with a `lifeline` reload their reserve interface the same way. Nothing is handed out again: configs, the portal and subscriptions return what they returned under `off`.

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

What a device needs to follow the switch:

| Device | Follows without re-import? | How |
|---|---|---|
| mihomo app on a subscription, profile with a provider (`controller.client_profile_providers: true`, device has VLESS) | **yes** | the core re-fetches the AmneziaWG provider every 15 minutes over VLESS or the other master; check `provider` in the Devices page "Last download" column |
| mihomo app on a subscription, inline profile | yes, at the app's next profile update | Clash Verge Rev and FlClash: within a day, or "update" by hand |
| mihomo core using the profile URL as its own proxy provider (a router) | yes, at its next provider refresh | the portal serves it the inline form; refresh by hand: `PUT /providers/proxies/<name>` on its API |
| `.conf` (AmneziaWG app, awg-quick) | **no** | download the new `.conf` after the switch; the app must support AmneziaWG 3.1 |
| lifeline config | **no** | download again after the base master's switch |

A device that has not followed sees its AmneziaWG proxy to that master stop: the tunnel stays up, no handshake completes. A subscription falls through to the next proxy in `auto`.

**Several masters: one at a time.** A master on `full` goes first in every device's `auto` group. Switch the second master, wait for the subscribed devices to follow (`provider` downloads newer than the switch, handshakes on its `wg0`), then the base master. Devices that have not followed keep the base master on 2.0 meanwhile.

1. **Before.** `controller.client_profile_providers: true` rolled out, and every subscribed device shows a `provider` download. `.conf` holders told a new file is coming.

2. **Set `full` on one master, validate, restart.**

   ```yaml
           awg3: full
   ```

   ```bash
   wgfleet-controller --config /etc/wgfleet/controller.yaml --check-config
   systemctl restart wgfleet-controller
   ```

3. **Confirm the interface switched** (seconds after the restart):

   ```bash
   awg show wg0 | grep -c "header protection key"   # 1
   ```

   Dashboard: "AmneziaWG generation per interface". Alert `WgfleetAWGGenerationSwitchNoHandshake` fires if no peer handshakes for 10 minutes after the switch.

4. **Watch the devices follow** within 15 minutes: handshakes on that master's `wg0`, new `provider` downloads.

5. **Hand out `.conf` files** to the devices that need them.

6. **Next master.** The base master last; its switch also switches every exit's `lifeline`.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| interface will not come up, log says 3.x refused | module is older than the config asks for |
| "the VPN is connected but nothing loads" after `full` | the device still has a pre-`full` config: `.conf` — re-import; subscription — update the profile; router — refresh its provider |
| a router on the subscription never follows | it uses the profile URL as a proxy provider and fetched the provider form; the controller serves a bare core (`User-Agent: clash.meta/…`) the inline form — refresh its provider once |
| no `HeaderProtectionKey` in `awg showconf wg0` after `full` | the master has not converged yet — one reconcile pass |
| `full` set, but `wg0` and the configs stay on `timers`; the controller logs `client_awg.awg3 is full, but this master's agent is too old` | the master's agent is below wire 15 — upgrade it |
| clients on `full` connect but pages stall | the client app predates AmneziaWG 3.1 random trailers — update the app (AmneziaWG 3.1, or a mihomo core with `random-trailers`) |

## See also

- `CONFIGURATION.md` — every knob named here
- `SUPPORT-BUNDLE.md` — what to collect if you need help
