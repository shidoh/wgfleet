#!/bin/bash
# deploy-master.sh — build wgfleet binaries and install them on the co-located
# master node (controller + agent on one box), then restart the services.
#
# The master is onboarded MANUALLY — it hosts the control plane that would other-
# wise do the onboarding — so unlike exit nodes it has no SSH-provision or Web-UI
# "upgrade" path;
# this script is that equivalent. Exit agents update via the controller (Web UI
# upgrade button / `controller --upgrade-agent`).
#
# Cross-compiles on THIS machine (no Go toolchain needed on the master), copies
# over SSH, installs ETXTBSY-safe (staged temp + atomic rename over the running
# binary — a rename keeps the running process's old inode alive), then restarts.
# Idempotent and safe to re-run.
#
# Run it from the unpacked release archive (it uses the binaries sitting beside it),
# or from a repo root (it cross-builds them with make).
#
# Usage:
#   deploy/deploy-master.sh [user@host] [--agent|--controller|--both] [--arch ARCH] [--plan]
#
# Examples:
#   deploy/deploy-master.sh root@master-1.example.net               # both (default)
#   deploy/deploy-master.sh root@master-1.example.net --agent       # agent only
#   deploy/deploy-master.sh root@master-1.example.net --controller  # controller only
#   MASTER=root@master-1.example.net deploy/deploy-master.sh        # host via env
#
# Order note: when deploying BOTH, the agent is installed/restarted FIRST, then
# the controller. A controller restart re-reads the fleet manifest and serves a
# new spec; the (already-updated) agent then reconciles it correctly.
#
# EXCEPT when this build bumps the wire contract, where that order is a trap and
# the script flips it automatically (see wire_order_flip below).
#
# Transfer tuning (both optional, via env):
#   SCP_LIMIT=8000   # cap the copy at N kbit/s so interactive SSH stays usable
#   SCP_COMPRESS=0   # disable on-the-wire compression (on by default)

set -euo pipefail

# --- config -----------------------------------------------------------------
MASTER="${MASTER:-}"
ARCH="${ARCH:-amd64}"
WHAT="both"
PLAN=0
# Bandwidth cap for the binary copy, in kbit/s. Empty ⇒ unlimited. A ~28 MB
# binary pushed at line rate fills the uplink queue and makes interactive SSH to
# the same host unusable for the duration (observed live 2026-07-20: the box was
# idle at load 0.04 while ssh crawled — bufferbloat on the path, not the server).
SCP_LIMIT="${SCP_LIMIT:-}"
# On-the-wire compression. Go binaries compress well (~50%), so this roughly
# halves both transfer time and queue pressure. Set 0 to disable.
SCP_COMPRESS="${SCP_COMPRESS:-1}"

log()  { printf '\n\033[1;32m[deploy-master]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[deploy-master]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[deploy-master] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- args -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --agent)      WHAT="agent" ;;
    --controller) WHAT="controller" ;;
    --both)       WHAT="both" ;;
    --arch)       shift; ARCH="${1:?--arch needs a value}" ;;
    --plan|--dry-run) PLAN=1 ;;
    -h|--help)    sed -n '2,30p' "$0"; exit 0 ;;
    *@*)          MASTER="$1" ;;
    *)            die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

[ -n "$MASTER" ] || die "no master ssh target — pass user@host or set MASTER="
# Either shape is fine: a repo checkout (we build), or the unpacked release archive
# (the binaries are already here). Requiring a Makefile made this script unusable for
# every tarball-only operator, while three docs named it as THE master upgrade path.
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f Makefile ] && [ -d cmd/wgfleet-agent ]; then :
elif [ -f "$_here/wgfleet-agent" ] || [ -f "$_here/wgfleet-controller" ]; then :
else
  die "run this from a wgfleet repo root, or from the unpacked release archive (where the binaries are)"
fi
command -v go  >/dev/null 2>&1 || die "go toolchain not found (needed to cross-build)"
command -v scp >/dev/null 2>&1 || die "scp not found"

# component -> (dist artifact, service name, installed path)
agent_dist="dist/wgfleet-agent-linux-${ARCH}"
controller_dist="dist/wgfleet-controller-linux-${ARCH}"

# build_one <make-target> <dist-artifact> <archive-name>
#
# Two ways to get a binary, matching install.sh: from the release archive, where a
# prebuilt binary sits next to this script and there is no Makefile or source at all,
# or from a repo checkout, where we cross-build it. The archive case used to be
# impossible — the script ran `make` unconditionally and every documented master
# upgrade path told a tarball-only operator to run it.
build_one() {
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$here/$3" ]; then
    log "using $3 from this directory (release archive)"
    mkdir -p "$(dirname "$2")"
    cp -f "$here/$3" "$2"
    return
  fi
  command -v make >/dev/null 2>&1 || die "no $3 beside this script and no make to build one — \
run this from the release archive (where the binaries are) or from a repo checkout"
  log "building $2 (GOARCH=$ARCH)"
  make "$1" ARCH="$ARCH" >/dev/null
  [ -f "$2" ] || die "build did not produce $2"
}

# local_sha256 <file> — portable digest (macOS shasum / Linux sha256sum).
local_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# ssh_run <remote-script> — run over SSH, allocating a tty only when we HAVE one.
#
# This used to always pass -t. Without a controlling terminal (a CI job, a
# background invocation, a tool driving the script) sshd's tty request hangs
# instead of failing, and the deploy stalls mid-way with the binary already staged
# — observed live 2026-07-19, where killing the stuck run truncated the in-flight
# copy and left a half-written binary on the master.
ssh_run() {
  if [ -t 1 ]; then ssh -t "$MASTER" "$1"; else ssh "$MASTER" "$1"; fi
}

# deploy_one <dist-artifact> <bin-name> <service>
deploy_one() {
  local dist="$1" bin="$2" svc="$3"
  local staged="/tmp/${bin}.deploy.$$"
  local want; want="$(local_sha256 "$dist")"
  if [ "$PLAN" -eq 1 ]; then
    warn "[plan] would scp $dist -> $MASTER:$staged (sha256 ${want:0:12})"
    warn "[plan] would: verify sha256, snapshot /usr/local/bin/$bin -> .prev, install, restart $svc"
    warn "[plan] would: roll back to .prev if $svc does not come up"
    return 0
  fi
  local scp_opts="-q"
  [ "$SCP_COMPRESS" = "1" ] && scp_opts="$scp_opts -C"
  [ -n "$SCP_LIMIT" ] && scp_opts="$scp_opts -l $SCP_LIMIT"
  log "uploading $bin to $MASTER (sha256 ${want:0:12}${SCP_LIMIT:+, capped ${SCP_LIMIT}kbit/s})"
  # shellcheck disable=SC2086 # scp_opts is a deliberate word-split option list
  scp $scp_opts "$dist" "$MASTER:$staged"
  log "verifying, snapshotting and installing /usr/local/bin/$bin, restarting $svc"
  ssh_run "
    set -e

    # VERIFY BEFORE INSTALLING. An interrupted transfer leaves a truncated binary
    # that is indistinguishable from success at the command level: scp exits 0, the
    # file exists, and the service then dies with SIGSEGV on a partial ELF. That is
    # not hypothetical — it crash-looped this master 42 times on 2026-07-19.
    got=\$(sha256sum '$staged' | cut -d' ' -f1)
    if [ \"\$got\" != '$want' ]; then
      rm -f '$staged'
      echo \"sha256 mismatch for $bin: got \$got want $want — refusing to install\" >&2
      exit 1
    fi

    # Snapshot for rollback. The exits get this from the rolling updater; the
    # master is deployed by this script instead, and without a snapshot its only
    # recovery path is a rebuild from source.
    if [ -f '/usr/local/bin/${bin}' ]; then
      sudo cp -f '/usr/local/bin/${bin}' '/usr/local/bin/${bin}.prev'
    fi

    sudo install -o root -g root -m 0755 '$staged' '/usr/local/bin/${bin}.new'
    sudo mv -f '/usr/local/bin/${bin}.new' '/usr/local/bin/${bin}'
    rm -f '$staged'
    sudo systemctl restart '$svc'
    sleep 3

    # Roll back on a service that will not come up. Restarting straight into a bad
    # binary is how a routine deploy becomes an outage on the one node that also
    # runs the controller.
    if ! systemctl is-active --quiet '$svc'; then
      if [ -f '/usr/local/bin/${bin}.prev' ]; then
        echo \"  $svc failed to start — rolling back to .prev\" >&2
        # install + mv, not cp, for the same reason the install above uses them:
        # cp writes IN PLACE, and a crash-looping unit alternates between running and
        # its RestartSec gap, so the recovery path itself returns ETXTBSY on roughly a
        # coin flip — and `set -e` then aborts before the restart, leaving the node on
        # the bad binary with a non-zero exit that reads like a rollback was tried.
        # A rename is atomic and never touches the running image.
        sudo install -o root -g root -m 0755 '/usr/local/bin/${bin}.prev' '/usr/local/bin/${bin}.rollback'
        sudo mv -f '/usr/local/bin/${bin}.rollback' '/usr/local/bin/${bin}'
        sudo systemctl restart '$svc'
        sleep 2
        echo \"  after rollback: \$(systemctl is-active $svc)\" >&2
      else
        echo \"  $svc failed to start and there is no .prev to roll back to\" >&2
      fi
      exit 1
    fi
    echo \"  $svc: \$(systemctl is-active $svc)\"
    /usr/local/bin/${bin} --version
  "
}

# --- build ------------------------------------------------------------------
case "$WHAT" in
  agent)      build_one agent-linux      "$agent_dist" wgfleet-agent ;;
  controller) build_one controller-linux "$controller_dist" wgfleet-controller ;;
  both)       build_one agent-linux "$agent_dist" wgfleet-agent; build_one controller-linux "$controller_dist" wgfleet-controller ;;
esac

# local_wire — the wire contract this working tree builds, read from source.
# The built binary is a Linux cross-build we cannot execute here, so parse the
# constant instead.
local_wire() {
  # BRE only — \+ is a GNU extension and this script runs from a macOS shell too.
  sed -n 's/.*WireContractVersion uint32 = \([0-9][0-9]*\).*/\1/p' internal/api/wire.go | head -1
}

# remote_wire — the wire contract the master's INSTALLED controller serves.
# Empty when it cannot be determined (no binary, older build with no such line);
# callers must treat empty as "unknown" and fall back to the safe order.
remote_wire() {
  ssh "$MASTER" '/usr/local/bin/wgfleet-controller --version 2>/dev/null' 2>/dev/null |
    sed -n 's/.*wire-contract version \([0-9][0-9]*\).*/\1/p' | head -1
}

# wire_order_flip — is the controller's wire contract moving FORWARD in this
# deploy? If so, the default agent-first order is a trap and must be reversed.
#
# The asymmetry is in api.CheckWire:
#   agent NEWER than controller → WireAgentTooNew → controller REFUSES the agent
#                                 a spec entirely; the node stops converging.
#   agent OLDER than controller → WireCompatible (down to MinSupportedWire) →
#                                 the agent keeps reconciling, simply ignoring
#                                 fields it does not know.
#
# So on a bump, controller-first is safe to interrupt at ANY point, while
# agent-first leaves a hard-dead agent if the controller copy fails. That is not
# hypothetical: it stranded this master for ~10 minutes on 2026-07-20 when a
# 28 MB controller upload stalled after the agent had already been installed.
wire_order_flip() {
  local lw rw
  lw="$(local_wire)"
  rw="$(remote_wire)"
  [ -n "$lw" ] && [ -n "$rw" ] || { warn "wire version undetermined (local='${lw:-?}' remote='${rw:-?}') — using controller-first as the safe default"; return 0; }
  [ "$lw" -gt "$rw" ]
}

# --- deploy -----------------------------------------------------------------
case "$WHAT" in
  agent)      deploy_one "$agent_dist"      wgfleet-agent      wgfleet-agent ;;
  controller) deploy_one "$controller_dist" wgfleet-controller wgfleet-controller ;;
  both)
    # Decide the order ONCE (the probe is read-only, so it runs in plan mode too
    # — a plan that showed a different order than the real run would be worse
    # than no plan at all).
    if wire_order_flip; then
      log "wire contract moves forward ($(remote_wire) -> $(local_wire)) — deploying CONTROLLER FIRST (see wire_order_flip)"
      deploy_one "$controller_dist" wgfleet-controller wgfleet-controller
      deploy_one "$agent_dist"      wgfleet-agent      wgfleet-agent
    else
      log "wire contract unchanged — deploying agent first (default order)"
      deploy_one "$agent_dist"      wgfleet-agent      wgfleet-agent
      deploy_one "$controller_dist" wgfleet-controller wgfleet-controller
    fi
    ;;
esac

[ "$PLAN" -eq 1 ] && { log "plan only — nothing changed"; exit 0; }
log "done — $WHAT updated on $MASTER"

# Deploying ONLY the controller leaves controller.agent_bin on the old build, and
# that binary — not this controller — is what a rolling upgrade pushes to exits.
# The rollout selects against it too, so the fleet correctly reads as "nothing to
# roll" rather than looping on an upgrade that installs the version each node
# already had. Say so, because "the controller is newer than the fleet" otherwise
# looks like the rollout is broken.
if [ "$WHAT" = "controller" ]; then
  warn "controller only — the agent binary on $MASTER is unchanged, so a rolling
  upgrade still ships that older build to the exits. Re-run with --agent (or
  --both) before rolling the fleet."
fi
