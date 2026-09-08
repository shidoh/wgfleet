# Support bundle: what to send a maintainer with no server access

A read-only diagnostic archive you can hand to someone who cannot log into your
servers. Plain text, no secrets, and its contents are printed to the screen
before you send it anywhere.

## Two invocations

| Situation | Run |
|---|---|
| One node — you have a shell on it | `wgfleet-agent --support-bundle [--note "..."]` |
| Every exit, plus a fleet inventory — from the controller | `wgfleet-controller --support-bundle --fleet [--note "..."]` |

| Flag | Binary | Meaning |
|---|---|---|
| `--support-bundle` | agent, controller | write the archive, then exit |
| `--fleet` | controller | with `--support-bundle`: also render inventory from the store and walk every exit over SSH |
| `--note "..."` | agent, controller | free-form description of the problem, embedded in the manifest |

- Run either as root.
- Both write a `.tar.gz` into the current directory:
  ```
  wgfleet-support-<node>-<timestamp>.tar.gz          # agent
  wgfleet-support-fleet-<timestamp>.tar.gz           # controller --fleet
  ```
- The agent form runs locally and never dials the controller.
- The controller form does not require a healthy fleet: an exit it cannot
  reach over SSH becomes one entry in the archive saying so.
- `--fleet` collects nothing about the co-located master itself beyond one
  inventory line. If the problem looks master-side, also run
  `wgfleet-agent --support-bundle` on the master.

## What it collects

Per node:

| File | Contents |
|---|---|
| `identity.txt` | hostname, uptime, kernel (`uname -a`), current time (UTC), timezone, installed `wgfleet-agent`/`wgfleet-controller` version, nftables version, AmneziaWG module version + `srcversion` (on disk and loaded), AmneziaWG tools version, `dkms status`, apt holds, Docker + Compose version |
| `network.txt` | addresses, routes, routing rules, the AmneziaWG routing table, the namespace routing table, `awg show`, the nft firewall ruleset, listening sockets, conntrack count; on a master also: mihomo's network mode, the namespace move's recorded state, the ruleset and listeners inside the namespace, and the ZeroTier overlay status |
| `services.txt` | wgfleet's own unit status, every *failed* systemd unit on the node, running containers (`docker ps`) |
| `logs.txt` | bounded journal tails for `wgfleet-agent`/`wgfleet-controller` (last ~300 lines each), journal disk usage, root disk headroom, a per-unit line count over the last hour |
| `containers.txt` | bounded log tails from the containers wgfleet runs (mihomo, xray, blocky, wg-easy). A missing one on a node that does not run it is normal. |

- Every command is read-only. `awg showconf` / `wg showconf` are never run.
- `awg show` **is** run; it masks the private key but prints the AmneziaWG 3.x
  header protection key in full, which the redaction pass and the refusal
  gate (below) catch.
- In `--fleet` mode the controller adds its own inventory — every node's name,
  role, state, agent version, mgmt address, last-seen time, and
  drain/decommission flags — then walks every *exit's* SSH target from the
  fleet manifest and runs the identical per-node collection over SSH.
- Each captured section is capped at 256 KiB and the whole per-node bundle at
  8 MiB. Hitting the cap stops collection early and the manifest says so.

## What it never collects

Every file wgfleet manages that carries a secret:

- `controller.yaml` and `agent.yaml`
- the AmneziaWG/WARP tunnel configs and the reserve interface key (`lifeline.key`)
- mihomo/xray/wg-easy configs and databases
- this node's own private key
- the fleet CA's private key
- anything under a sops-encrypted path

`MANIFEST.txt` ends with a NOT COLLECTED section listing them.

Anything secret-shaped inside captured output (a `key: ...` or
`password: ...` line in a container's log) is masked to `<redacted>` before
the archive is written. If a value this node actually holds as a secret
survives verbatim anywhere, the tool refuses to write the archive — see "If
it refuses" below.

## Read it before you send it

Every run prints the archive's contents at the end, plus the two commands to
check for yourself:

```bash
tar tzf wgfleet-support-<node>-<timestamp>.tar.gz    # list what's inside
tar xzf wgfleet-support-<node>-<timestamp>.tar.gz    # unpack and read it
```

Everything in it is plain text. `MANIFEST.txt` indexes every file and, for
most entries, names the exact command that produced it (the `--fleet`
inventory is built in-process and shows no command).

## Read-only and unencrypted — both on purpose

Every collector is a read command; nothing on the node changes. The archive
is a plain gzip+tar, not encrypted, so you can inspect exactly what you are
about to send; it carries no secrets by construction.

## `--note`

`--note "what you were seeing"` is embedded in the archive's manifest.

| Note content | Result |
|---|---|
| ordinary text | embedded in `MANIFEST.txt` as-is |
| secret-shaped, e.g. `password: hunter2` | silently masked to `<redacted>` in `MANIFEST.txt` |
| the exact, unlabeled text of a secret this node holds | refused (see below) |

## If it refuses to write the archive

| Symptom | Cause | What to do |
|---|---|---|
| `refusing to write the bundle: <node>/<file>:<line> <reason>` | the exact value of a secret this node holds was found verbatim in the assembled output (including the note and a failed command's error text) after masking | report it, quoting the file and line from the message (never the value); do not edit the note or output to get past it |

Nothing partial is left on disk. This is a bug in a collector or in the
check, not a limit to work around.

## Fleet mode's secret-check gap

- The controller's exact-secret check covers only what the controller holds:
  its own CA private key and every exit's SSH bootstrap key.
- It cannot check an exit's *own* on-disk secrets (AmneziaWG key, xray key)
  against that exit's output, because it does not hold them and will not
  fetch them.
- The secret-shaped masking pass still runs on every exit's output.
- `wgfleet-agent --support-bundle` run directly on a node does not have this
  gap.

## Client-side problems

If the report is "it connects but nothing works" or "it's slow" and there is
no shell on any wgfleet node, use `client-diag.sh` from the client itself. It
ships in the same release archive, is read-only, and prints a plain-text
report you can read before sharing it:

```bash
./client-diag.sh                 # sensible defaults
QUICK=1 ./client-diag.sh         # skip throughput + the repeated-load loop
THROUGHPUT=1 ./client-diag.sh    # also measure tunnel vs. direct throughput
```
