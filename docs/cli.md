# CLI reference

Every flag on both binaries. For what to *do* with them see
[operations.md](operations.md); for the config files they read see
[manifest.md](manifest.md).

---

## `wgfleet-controller`

| Flag | Default | Description |
|---|---|---|
| `--version` | | print build version (Version, Commit, BuildDate) and exit |
| `--check-config` | | validate the manifest and exit: 0 if the controller would start here, 1 with the reasons if not. Prints the file's sha256, master and exit counts, then the checks a restart makes before it serves — the secret provider, the CA, and whether the store's schema is newer than this build. Changes nothing: it does not create the store, run migrations, or self-heal the manifest's permissions. Run it before every restart — a manifest or a missing CA this binary refuses makes the controller exit at startup, and the unit's `Restart=on-failure` turns that into a crash loop of the whole control plane. The manifest verdict and the HOST verdict are printed separately, so validating a manifest from your laptop reports the host-local failures without calling the file bad. It also warns when the running controller is on a DIFFERENT manifest — that is, when this file has been edited but never applied |
| `--config` | `/etc/wgfleet/controller.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--store` | (from config) | override `controller.store` |
| `--init-pki` | | generate a CA at the configured pki paths, then exit |
| `--issue-node <id>` | | issue an mTLS bundle (`node.crt`/`node.key`/`ca.crt`) for a node, then exit |
| `--issue-out <dir>` | `pki/<id>` | output dir for `--issue-node` |
| `--provision <node>` | | SSH-bootstrap the named fleet node, then exit |
| `--plan` | | with `--provision`, `--upgrade-agent`, `--rolling-upgrade` or `--import-wg-easy`: dry-run, change nothing |
| `--agent-bin <path>` | (from config) | with `--provision` or `--upgrade-agent`: agent binary to install |
| `--controller-endpoint <addr>` | (from config) | with `--provision`: endpoint the agent will dial |
| `--upgrade-agent <node>` | | roll the agent binary forward over SSH on the named node, then exit |
| `--rolling-upgrade` | | roll every outdated EXIT agent forward one node at a time, reserve tier first, then exit. A node whose SSH will not open is left alone rather than downgraded |
| `--import-wg-easy <master>` | | copy the named master's wg-easy client credentials into the controller store, then exit. Run it ON the master (it reads a local SQLite file). Safe with the controller live; use `--plan` first, and read [client-migration.md](client-migration.md) before either |
| `--wg-easy-db <path>` | `/etc/wireguard/wg-easy.db` | with `--import-wg-easy`: where wg-easy's database lives |
| `--backup <out>` | | snapshot controller (+co-located master) state to an age-encrypted archive at `<out>`, then exit |
| `--restore <in>` | | restore controller state from an age-encrypted archive `<in>`, then exit (controller must be stopped) |
| `--age-recipient <rcpt>` | | with `--backup`: encrypt to this age recipient instead of prompting for a passphrase |
| `--plan` | | with `--restore`: show what would be laid down, change nothing |
| `--support-bundle` | | write a read-only diagnostic archive (no secrets, not encrypted) and exit; requires `--fleet` |
| `--fleet` | | with `--support-bundle`: collect the store inventory and walk every exit over SSH |
| `--note <text>` | | with `--support-bundle`: describe what went wrong; embedded in the archive and subject to the same secret checks as everything else |

No subcommand flags ⇒ serve the API + UI + metrics until signalled.

## `wgfleet-agent`

| Flag | Default | Description |
|---|---|---|
| `--version` | | print build version (Version, Commit, BuildDate) and exit |
| `--config` | `/etc/wgfleet/agent.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--plan` | | dry-run: render the full plan, change nothing |
| `--once` | | run a single reconcile pass and exit |
| `--public-ip <ip>` | | this node's public IP to advertise (peer endpoint) |
| `--mgmt-addr <ip>` | (from `agent.yaml`) | mgmt/ZT address (metrics + admin + DNS bind); overrides `agent.mgmt_addr` |
| `--state-dir <dir>` | | root managed files under `<dir>` instead of `/etc` (non-root/dev) |
| `--metrics <addr>` | `<mgmt_addr>:9301` | override the agent `/metrics` bind (mgmt/ZT only); `off` disables |
| `--support-bundle` | | write a read-only diagnostic archive for THIS node (no secrets, not encrypted) and exit; needs no controller, so it works when the control plane is down |
| `--note <text>` | | with `--support-bundle`: describe what went wrong; embedded in the archive and subject to the same secret checks as everything else |

No `--once` ⇒ run as a daemon, reconciling on the configured interval (default 30s).
