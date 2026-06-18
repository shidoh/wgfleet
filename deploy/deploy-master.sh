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

# deploy_one <dist-artifact> <bin-name> <service>
deploy_one() {
  local dist="$1" bin="$2" svc="$3"
  local staged="/tmp/${bin}.deploy.$$"
  if [ "$PLAN" -eq 1 ]; then
    warn "[plan] would scp $dist -> $MASTER:$staged"
    warn "[plan] would: sudo mv -f $staged /usr/local/bin/$bin && sudo systemctl restart $svc"
    return 0
  fi
  log "uploading $bin to $MASTER"
  scp -q "$dist" "$MASTER:$staged"
  log "installing /usr/local/bin/$bin and restarting $svc (sudo on master)"
  # -t for a tty so sudo can prompt if NOPASSWD is not configured.
  ssh -t "$MASTER" "
    set -e
    sudo install -o root -g root -m 0755 '$staged' '/usr/local/bin/${bin}.new'
    sudo mv -f '/usr/local/bin/${bin}.new' '/usr/local/bin/${bin}'
    rm -f '$staged'
    sudo systemctl restart '$svc'
    sleep 1
    systemctl is-active '$svc' >/dev/null && echo \"  $svc: \$(systemctl is-active $svc)\"
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
