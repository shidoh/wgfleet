# CLI reference

Every flag on both binaries. Subcommands are mutually exclusive: passing two of
`--provision`, `--upgrade-agent`, `--rolling-upgrade`, `--import-wg-easy`, `--backup`,
`--restore` or `--certs` is refused by name. For what to *do* with them see
[operations.md](operations.md); for the config files they read see
[manifest.md](manifest.md).

---

## `wgfleet-controller`

| Flag | Default | Description |
|---|---|---|
| `--version` | | print build version (Version, Commit, BuildDate) and exit |
| `--check-config` | | validate the manifest and exit: 0 if the controller would start here, 1 with the reasons if not. Prints the file's sha256, master and exit counts, then the checks a restart makes before it serves — the secret provider, the CA, `fleet.awg3_key` (resolved, not merely referenced), and whether the store's schema is newer than this build. Changes nothing: it does not create the store, run migrations, or change the manifest's permissions. Run it before every restart — a manifest this binary refuses makes the unit's `Restart=on-failure` crash-loop the control plane. The manifest verdict and the HOST verdict are printed separately, so validating from your laptop reports host-local failures without calling the file bad. It also warns when the running controller is on a DIFFERENT manifest — edited but never applied, and when a master's `client_awg.exclude_from_tunnel` hides the client portal or `mgmt_subnet` from AWG |
| `--config` | `/etc/wgfleet/controller.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--log-level` | (from config, else `info`) | `trace` \| `debug` \| `info` \| `warn` \| `error`. Overrides `log_level` in the config. `SIGUSR1` makes a running process one level more verbose, `SIGUSR2` returns it to the configured level |
| `--store` | (from config) | override `controller.store` |
| `--init-pki` | | generate a CA at the configured pki paths, then exit |
| `--issue-node <id>` | | issue an mTLS bundle (`node.crt`/`node.key`/`ca.crt`) for a node, then exit |
| `--issue-out <dir>` | `pki/<id>` | output dir for `--issue-node` |
| `--provision <node>` | | SSH-bootstrap the named fleet node, then exit |
| `--plan` | | with `--provision`, `--upgrade-agent`, `--rolling-upgrade`, `--import-wg-easy` or `--restore`: dry-run, change nothing. A modifier, never a command: on its own, or with `--backup` or `--certs`, it is refused |
| `--agent-bin <path>` | (from config) | with `--provision`, `--upgrade-agent` or `--rolling-upgrade`: agent binary to install |
| `--controller-endpoint <addr>` | (from config) | with `--provision`: endpoint the agent will dial |
| `--upgrade-agent <node>` | | roll the agent binary forward over SSH on the named node, then exit |
| `--rolling-upgrade` | | roll every outdated EXIT agent forward one node at a time, reserve tier first, then exit. A node whose SSH will not open is left alone rather than downgraded. A node that fails does not stop the run: it is reported by name and the rollout moves to the next one |
| `--node-timeout <dur>` | `5m` | with `--rolling-upgrade`: how long ONE node has to accept the upload and restart before it is given up on. Guards against a path that accepts the connection and then goes silent, which otherwise holds the whole fleet behind one host |
| `--import-wg-easy <master>` | | copy the named master's wg-easy client credentials into the controller store, then exit. Run it ON the master (it reads a local SQLite file). Safe with the controller live; use `--plan` first, and read [client-migration.md](client-migration.md) before either |
| `--wg-easy-db <path>` | `/etc/wireguard/wg-easy.db` | with `--import-wg-easy`: where wg-easy's database lives |
| `--backup <out>` | | snapshot controller (+co-located master) state to an age-encrypted archive at `<out>`, then exit |
| `--restore <in>` | | restore controller state from an age-encrypted archive `<in>`, then exit (controller must be stopped) |
| `--age-recipient <rcpt>` | | with `--backup`: encrypt to this age recipient instead of prompting for a passphrase |
| `--age-identity <path>` | | with `--restore`: the age identity file for an archive encrypted to a recipient. Omit it for a passphrase-encrypted archive. **An archive written with `--age-recipient` cannot be restored without this**, including every archive the Web UI's backup button produces |
| `--set-admin-password` | | set or reset the Web UI admin password, then exit. Run it with the controller **stopped**: it opens the store directly. Reads the password from `--password-file` if given, else from `WGFLEET_ADMIN_PASSWORD` if set, else prompts; rotates the session secret, so every open console session is signed out |
| `--admin-user <name>` | `admin` | with `--set-admin-password`: which account to set |
| `--password-file <path>` | | with `--set-admin-password`: read the password from this file instead of prompting. The file is read, never written; delete it afterwards |
| `--certs check-expiration` | | print when the certificates ON THIS HOST expire — the fleet CA, and the agent's own certificate when this box runs one — then exit. Other nodes' certificates are renewed by their own agents; watch `wgfleet_agent_cert_expiry_timestamp_seconds` for the fleet-wide view |
| `--certs renew --node <id>` | | re-issue one node's certificate out of band and write it under `pki/<id>/`, then exit. For a certificate that has ALREADY expired, whose node can no longer open the mTLS channel a renewal would travel over. Prints the exact scp/ssh lines for that node. The old certificate is **not** revoked — there is no CRL — so both are valid until the old one expires. Delete the local copy afterwards; it is a live node identity |
| `--node <id>` | | with `--certs renew`: which node to re-issue for |
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
| `--log-level` | (from config, else `info`) | `trace` \| `debug` \| `info` \| `warn` \| `error`. Overrides `log_level` in the config. `SIGUSR1` makes a running process one level more verbose, `SIGUSR2` returns it to the configured level |
| `--plan` | | dry-run: render the full plan, change nothing |
| `--once` | | run a single reconcile pass and exit |
| `--public-ip <ip>` | | this node's public IP to advertise (peer endpoint) |
| `--mgmt-addr <ip>` | (from `agent.yaml`) | mgmt/ZT address (metrics + admin + DNS bind); overrides `agent.mgmt_addr` |
| `--state-dir <dir>` | | root managed files under `<dir>` instead of `/etc` (non-root/dev) |
| `--metrics <addr>` | `<mgmt_addr>:9301` | override the agent `/metrics` bind (mgmt/ZT only); `off` disables |
| `--support-bundle` | | write a read-only diagnostic archive for THIS node (no secrets, not encrypted) and exit; needs no controller, so it works when the control plane is down |
| `--note <text>` | | with `--support-bundle`: describe what went wrong; embedded in the archive and subject to the same secret checks as everything else |

No `--once` ⇒ run as a daemon, reconciling on the configured interval (default 30s).
