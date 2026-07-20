#!/bin/bash
# deploy-master.sh — build wgfleet binaries and install them on the co-located
# master node (controller + agent on one box), then restart the services.
#
# The master is onboarded MANUALLY (co-located control plane, docs/DESIGN.md open
# Q#4), so unlike exit nodes it has no SSH-provision / Web-UI "upgrade" path —
# this script is its equivalent. Exit agents update via the controller (Web UI
# upgrade button / `controller --upgrade-agent`).
#
# Cross-compiles on THIS machine (no Go toolchain needed on the master), copies
# over SSH, installs ETXTBSY-safe (staged temp + atomic rename over the running
# binary — a rename keeps the running process's old inode alive), then restarts.
# Idempotent and safe to re-run.
#
# Run from the repo root (it shells out to the Makefile cross-build targets).
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

set -euo pipefail

# --- config -----------------------------------------------------------------
MASTER="${MASTER:-}"
ARCH="${ARCH:-amd64}"
WHAT="both"
PLAN=0

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
[ -f Makefile ] && [ -d cmd/wgfleet-agent ] || die "run from the wgfleet repo root"
command -v go  >/dev/null 2>&1 || die "go toolchain not found (needed to cross-build)"
command -v scp >/dev/null 2>&1 || die "scp not found"

# component -> (dist artifact, service name, installed path)
agent_dist="dist/wgfleet-agent-linux-${ARCH}"
controller_dist="dist/wgfleet-controller-linux-${ARCH}"

# build_one <make-target> <dist-artifact>
build_one() {
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
  log "uploading $bin to $MASTER (sha256 ${want:0:12})"
  scp -q "$dist" "$MASTER:$staged"
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
        sudo cp -f '/usr/local/bin/${bin}.prev' '/usr/local/bin/${bin}'
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
  agent)      build_one agent-linux      "$agent_dist" ;;
  controller) build_one controller-linux "$controller_dist" ;;
  both)       build_one agent-linux "$agent_dist"; build_one controller-linux "$controller_dist" ;;
esac

# --- deploy (agent first, then controller — see order note) -----------------
case "$WHAT" in
  agent)      deploy_one "$agent_dist"      wgfleet-agent      wgfleet-agent ;;
  controller) deploy_one "$controller_dist" wgfleet-controller wgfleet-controller ;;
  both)
    deploy_one "$agent_dist"      wgfleet-agent      wgfleet-agent
    deploy_one "$controller_dist" wgfleet-controller wgfleet-controller
    ;;
esac

[ "$PLAN" -eq 1 ] && { log "plan only — nothing changed"; exit 0; }
log "done — $WHAT updated on $MASTER"
