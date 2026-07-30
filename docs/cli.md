# CLI reference

Every flag on both binaries. For what to *do* with them see
[operations.md](operations.md); for the config files they read see
[manifest.md](manifest.md).

---

## `wgfleet-controller`

| Flag | Default | Description |
|---|---|---|
| `--version` | | print build version (Version, Commit, BuildDate) and exit |
| `--config` | `/etc/wgfleet/controller.yaml` | config path |
| `--log-format` | `text` | `text` \| `json` |
| `--store` | (from config) | override `controller.store` |
| `--init-pki` | | generate a CA at the configured pki paths, then exit |
| `--issue-node <id>` | | issue an mTLS bundle (`node.crt`/`node.key`/`ca.crt`) for a node, then exit |
| `--issue-out <dir>` | `pki/<id>` | output dir for `--issue-node` |
| `--provision <node>` | | SSH-bootstrap the named fleet node, then exit |
| `--plan` | | with `--provision` or `--upgrade-agent`: dry-run, change nothing |
| `--agent-bin <path>` | (from config) | with `--provision` or `--upgrade-agent`: agent binary to install |
| `--controller-endpoint <addr>` | (from config) | with `--provision`: endpoint the agent will dial |
| `--upgrade-agent <node>` | | roll the agent binary forward over SSH on the named node, then exit |
| `--backup <out>` | | snapshot controller (+co-located master) state to an age-encrypted archive at `<out>`, then exit |
| `--restore <in>` | | restore controller state from an age-encrypted archive `<in>`, then exit (controller must be stopped) |
| `--age-recipient <rcpt>` | | with `--backup`: encrypt to this age recipient instead of prompting for a passphrase |
| `--plan` | | with `--restore`: show what would be laid down, change nothing |

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

No `--once` ⇒ run as a daemon, reconciling on the configured interval (default 30s).
