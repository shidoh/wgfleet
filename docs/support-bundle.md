# Support bundle: what to send a maintainer with no server access

A read-only diagnostic archive you can hand to someone who cannot log into
your servers. Plain text, no secrets, and printed to the screen before you
send it anywhere.

## Two invocations

| Situation | Run |
|---|---|
| One node — you have a shell on it | `wgfleet-agent --support-bundle [--note "..."]` |
| The whole fleet — from the controller | `wgfleet-controller --support-bundle --fleet [--note "..."]` |

Run either as root, same as the rest of wgfleet. Both write a `.tar.gz` into
the current directory:

```
wgfleet-support-<node>-<timestamp>.tar.gz          # agent
wgfleet-support-fleet-<timestamp>.tar.gz           # controller --fleet
```

The agent form runs locally and never dials the controller — deliberate,
since a wedged node with no controller connectivity is exactly when you need
it. The controller form does not require a fully healthy fleet either: an
exit it cannot reach over SSH becomes one entry in the archive saying so,
instead of stopping the whole run.

## What it collects

Per node: hostname, uptime, kernel, current time; network state (addresses,
routes, routing rules, the AmneziaWG routing table, `awg show`, the nft
firewall ruleset, listening sockets, conntrack count); wgfleet's own unit
status plus every *failed* systemd unit fleet-wide, not just wgfleet's two;
the list of running containers (`docker ps`); bounded journal tails for
`wgfleet-agent`/`wgfleet-controller` (last ~300 lines each), journal disk
usage, root disk headroom, and a per-unit line count over the last hour so a
noisy unit that isn't wgfleet's still shows up; and bounded log tails from
the containers wgfleet runs (mihomo, xray, blocky, wg-easy — a missing one
on a node that doesn't run it is normal, not an error). A master
additionally reports its ZeroTier overlay status.

Every command is read-only. `awg showconf` / `wg showconf` — the commands
that print a private key — are never run; only `awg show`, which prints
`(hidden)` in their place.

In `--fleet` mode the controller adds one more section: its own inventory —
every node's name, role, state, agent version, mgmt address, last-seen time,
and drain/decommission flags, a strict subset of what the dashboard already
shows — then walks every exit's SSH target from the fleet manifest, running
the identical per-node collection over SSH.

Each captured section is capped at 256 KiB and the whole per-node bundle at
8 MiB; logs are the one thing that can turn "small text bundle" into
something nobody can read or send, so hitting the cap stops collection early
and the manifest says so rather than silently growing the archive.

## What it never collects

Every file wgfleet manages that carries a secret: `controller.yaml` and
`agent.yaml` themselves, the AmneziaWG/WARP tunnel configs, mihomo/xray/
wg-easy configs and databases, this node's own private key, the fleet CA's
private key, and anything under a sops-encrypted path. The archive's
`MANIFEST.txt` ends with a NOT COLLECTED section that spells this out
explicitly — you do not have to take this doc's word for it.

Beyond that fixed list: anything that *looks* secret-shaped inside output
the read-only commands above did capture — a `key: ...` or `password: ...`
line surfacing in a container's log, for instance — is masked to
`<redacted>` before the archive is written. And if a value this node
actually holds as a real secret survives verbatim anywhere in the
assembled output, the tool refuses to write the archive at all rather than
ship something redacted-in-passing. See "If it refuses" below.

## Read it before you send it

Every run prints the archive's contents at the end, plus the two commands to
check for yourself:

```bash
tar tzf wgfleet-support-<node>-<timestamp>.tar.gz    # list what's inside
tar xzf wgfleet-support-<node>-<timestamp>.tar.gz    # unpack and read it
```

Everything in it is plain text. `MANIFEST.txt` at the top indexes every
file with the exact command that produced it, so what you read matches what
actually ran.

## Read-only and unencrypted — both on purpose

Every collector is a read command; nothing on the node changes. The archive
itself is a plain gzip+tar, not encrypted, and that is deliberate: the whole
point of printing its contents and handing you `tar tzf`/`tar xzf` is that
you can look at exactly what you are about to send before you send it. An
encrypted archive would hide that from you as much as from anyone else. It
carries no secrets by construction (above), so there is nothing an
encryption layer would be protecting — only friction it would add.

## `--note`

`--note "what you were seeing"` is embedded in the archive's manifest and is
the fastest way to give a maintainer context. It goes through the exact same
checks as everything the tool collects on its own — paste a key or a
password into it by accident and the tool refuses the archive for the same
reason it would refuse a captured log line.

## If it refuses to write the archive

```
refusing to write the bundle: <node>/<file>:<line> <reason>
```

It found something secret-shaped — a value matching a real secret this node
holds, or text naming a secret-bearing field — and stopped before creating
anything. Nothing partial is left on disk; the file is only created after
this check passes. That is a bug in a collector, or in the check itself, not
a limit to work around: report it, quoting the file and line from the
message (never the value), rather than editing the note or the output to
get past it.

## Fleet mode's one gap

The controller's exact-secret check covers what the controller itself
holds directly — its own CA private key and every exit's SSH bootstrap key.
It cannot check an exit's *own* on-disk secrets (its AmneziaWG key, its
xray key) against that exit's collected output, because the controller does
not hold them, and fetching them over SSH just to check them would mean
collecting exactly the material this tool exists to never collect. The
secret-shaped masking pass above still runs on every exit's output
regardless. Running `wgfleet-agent --support-bundle` directly on a node does
not have this gap: it reads its own key material off local disk to check
against.

## Client-side problems

If the report is "it connects but nothing works" or "it's slow", and there
is no shell on any wgfleet node — just a phone or laptop with the tunnel
up — use `client-diag.sh` instead, run from the client itself. It ships in
the same release archive, is also read-only, and also prints a plain-text
report you can read before sharing it:

```bash
./client-diag.sh                 # sensible defaults
QUICK=1 ./client-diag.sh         # skip throughput + the repeated-load loop
THROUGHPUT=1 ./client-diag.sh    # also measure tunnel vs. direct throughput
```
