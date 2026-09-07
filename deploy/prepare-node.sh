#!/bin/bash
# wgfleet node OS-prep — run ONCE on a fresh Ubuntu VM before provisioning.
#
# It handles only the environmental bits the wgfleet provisioner deliberately
# does NOT do: building the AmneziaWG kernel module via DKMS, capping the systemd
# journal, and joining the ZeroTier management overlay (which needs out-of-band
# authorization). Everything else — hardening, nftables, apt deps, Docker, wgcf,
# the agent — is the provisioner's job (`controller --provision`).
#
# Idempotent: safe to re-run. Doubles as cloud-init user-data (it begins with a
# shebang, which cloud-init executes verbatim).
#
# Usage:
#   sudo ./prepare-node.sh <zerotier-network-id>
#   # or, as cloud-init user-data, set the network id below:
#   ZT_NETWORK=8056c2e21c000001 ./prepare-node.sh
#
#   # Upgrade an already-prepared node's AmneziaWG module + tools to the newest
#   # PPA build (bounces every AWG interface on the node for a few seconds):
#   sudo ./prepare-node.sh --upgrade-awg
#
# After this runs and the node is AUTHORIZED in ZeroTier Central (assign it the
# managed IP you put in the fleet manifest as mgmt_addr), run the provisioner.

set -euo pipefail

ZT_NETWORK="${ZT_NETWORK:-}"
UPGRADE_AWG="${UPGRADE_AWG:-0}"
for arg in "$@"; do
  case "$arg" in
    --upgrade-awg) UPGRADE_AWG=1 ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
    *) ZT_NETWORK="$arg" ;;
  esac
done

log()  { printf '\n\033[1;32m[prepare-node]\033[0m %s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\n\033[1;33m[prepare-node] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[1;31m[prepare-node] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# module_loaded <name> — is this kernel module currently loaded?
#
# NOT `lsmod | grep -q <name>`. Under `set -o pipefail`, `grep -q` exits at the
# first match and closes the pipe; lsmod then dies of SIGPIPE (141) with output
# still unwritten, and the pipeline reports 141 even though the match SUCCEEDED.
# Whether it happens depends on how early the module appears in lsmod's output
# and how much is left to write — so the identical check passes on one host and
# fails on the next. It cost a real debugging session on a node where the module
# was loaded and healthy the entire time, and the error it produced ("module
# built but not loaded") pointed at exactly the wrong thing.
#
# awk consumes all of stdin, so there is no SIGPIPE, and it matches column 1
# exactly — also more correct than `grep -w`, which would match the name where
# it appears in some OTHER module's "Used by" column.
module_loaded() {
  lsmod | awk -v m="$1" '$1 == m { found = 1 } END { exit !found }'
}

# zt_joined <network-id> — is this node already a member of that ZeroTier network?
# Same SIGPIPE reasoning as module_loaded: never `| grep -q` under pipefail.
zt_joined() {
  zerotier-cli listnetworks 2>/dev/null | awk -v n="$1" 'index($0, n) { found = 1 } END { exit !found }'
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v apt-get >/dev/null 2>&1 || die "this script targets Debian/Ubuntu (apt-get not found)"

export DEBIAN_FRONTEND=noninteractive

# --- 1. AmneziaWG kernel module (DKMS) --------------------------------------
# This is the hard pre-flight the provisioner checks but will not build itself:
# DKMS compiles against the running kernel, so it needs matching headers and can
# fail in environment-specific ways — better here, before reconcile, than mid-
# provision.
AWG_PKGS="amneziawg-dkms amneziawg-tools"

awg_add_ppa() {
  apt-get update -y
  # software-properties-common provides add-apt-repository on minimal images.
  apt-get install -y software-properties-common
  add-apt-repository -y ppa:amnezia/ppa
  apt-get update -y
}

# awg_pkg_versions — "<installed> <candidate>" for amneziawg-dkms, "(none)" when
# absent. The PPA never bumps the upstream version (always 1.0.0); what moves is
# the Debian revision, e.g. 1.0.0-0~202609061402+4569c4c — build date + commit.
awg_pkg_versions() {
  apt-cache policy amneziawg-dkms 2>/dev/null | awk '
    /Installed:/ { i = $2 } /Candidate:/ { c = $2 }
    END { printf "%s %s\n", (i == "" ? "(none)" : i), (c == "" ? "(none)" : c) }'
}

# awg_install — the module + tools as ONE apt transaction, held or not.
#
# --allow-change-held-packages is not optional. The agent pins these three
# packages on every reconcile pass (~30s): the tools and the module must stay on
# one AmneziaWG generation, and an unattended upgrade of one without the other
# leaves `awg setconf` failing. So "apt-mark unhold && apt-get install" loses the
# race with the agent — by the time apt-get update has finished, the hold is back
# and apt refuses with "Held packages were changed and -y was used". Seen on a
# tester's node 2026-09-07. Telling apt the hold may be changed is the honest way
# through: both packages move together, and the agent re-pins the new version.
awg_install() {
  # shellcheck disable=SC2086
  apt-get install -y --allow-change-held-packages dkms build-essential \
    "linux-headers-$(uname -r)" linux-headers-generic \
    $AWG_PKGS \
    || die "AmneziaWG DKMS build failed — check that linux-headers-$(uname -r) is available for this kernel (DKMS log: /var/lib/dkms/amneziawg/1.0.0/build/make.log)"
}

# awg_reload — swap the loaded module for the one on disk. Removing the module
# deletes every AmneziaWG interface on the node (the kernel does that, not us);
# the agent rebuilds them on its next pass. Say so before doing it.
#
# Compared by srcversion (a hash of the module's source), NOT by version: upstream
# rebuilds the PPA from master without bumping MODULE_VERSION, so two different
# builds routinely both say "3.1.20260812". Judging by that string kept the old
# code loaded after a successful package upgrade (Lima rehearsal, 2026-09-07).
awg_reload() {
  local loaded ondisk out
  loaded=$(cat /sys/module/amneziawg/srcversion 2>/dev/null || echo none)
  ondisk=$(modinfo -F srcversion amneziawg 2>/dev/null || echo unknown)
  if [ "$loaded" = "$ondisk" ]; then
    info "loaded module already matches disk (srcversion $loaded) — no reload needed"
    return 0
  fi
  warn "reloading amneziawg (srcversion $loaded -> $ondisk): every AWG interface on this node goes down for a few seconds until the agent rebuilds it"
  out=$(modprobe -r amneziawg 2>&1) || die "could not unload amneziawg: ${out:-no output} — reboot to pick up the new module"
  out=$(modprobe amneziawg 2>&1) || die "new amneziawg module failed to load: ${out:-no output}"
}

# awg_state — one line of what is loaded and what tools are installed.
awg_state() {
  printf 'module %s (srcversion %s), tools %s' \
    "$(cat /sys/module/amneziawg/version 2>/dev/null || echo none)" \
    "$(cat /sys/module/amneziawg/srcversion 2>/dev/null || echo none)" \
    "$(awg --version 2>/dev/null || echo none)"
}

if [ "$UPGRADE_AWG" = 1 ]; then
  log "upgrading AmneziaWG module + tools to the newest PPA build"
  info "before: $(awg_state)"
  if ! grep -rqs "amnezia/ppa" /etc/apt/sources.list.d/; then
    awg_add_ppa
  else
    apt-get update -y
  fi
  read -r AWG_INSTALLED AWG_CANDIDATE <<<"$(awg_pkg_versions)"
  if [ "$AWG_INSTALLED" = "$AWG_CANDIDATE" ]; then
    log "amneziawg-dkms already at the newest PPA build ($AWG_INSTALLED)"
  else
    info "amneziawg-dkms: $AWG_INSTALLED -> $AWG_CANDIDATE"
    awg_install
  fi
  awg_reload
  info "after:  $(awg_state)"
elif module_loaded amneziawg; then
  log "AmneziaWG kernel module already loaded — skipping DKMS build"
  info "version: $(modinfo -F version amneziawg 2>/dev/null || echo unknown)   kernel: $(uname -r)"
  info "(re-running does not upgrade it; for that: $0 --upgrade-awg)"
elif modinfo amneziawg >/dev/null 2>&1; then
  log "AmneziaWG kernel module built but not loaded — skipping DKMS build, will modprobe below"
else
  log "installing AmneziaWG kernel module via DKMS"
  awg_add_ppa
  # Headers for the RUNNING kernel AND the meta-package, so a later kernel upgrade
  # pulls matching headers and DKMS auto-rebuilds the module for it (otherwise an
  # apt/unattended kernel bump leaves AWG missing under the new kernel). Plus the
  # toolchain (build-essential/dkms), which minimal/cloud images such as Lima lack.
  awg_install
fi

# Ensure the module is loaded NOW (it may be built but not inserted — e.g. after a
# kernel change or reboot — which is exactly what trips the provisioner pre-flight)
# and on every future boot.
# nftables.service is masked, not merely disabled.
#
# The ruleset on every node belongs to the agent, which writes it and applies it
# itself. What ships with the distro is /etc/nftables.conf, and its first line is
# `flush ruleset` — so anything that enables that unit (a hand, a package
# reconfiguration on upgrade, somebody else's playbook) wipes the fleet's rules on
# the next boot, before the agent has run. Masking makes enabling it fail loudly
# instead of succeeding quietly.
if systemctl list-unit-files nftables.service >/dev/null 2>&1; then
  systemctl mask nftables.service >/dev/null 2>&1 || true
  log "nftables.service masked (the agent owns the ruleset)"
fi

modprobe amneziawg 2>/dev/null || true
if [ ! -f /etc/modules-load.d/amneziawg.conf ]; then
  echo amneziawg > /etc/modules-load.d/amneziawg.conf
  log "module set to load on boot (/etc/modules-load.d/amneziawg.conf)"
fi

modinfo amneziawg >/dev/null 2>&1 || die "AmneziaWG module not built for $(uname -r) — re-run after installing linux-headers-$(uname -r)"
if ! module_loaded amneziawg; then
  # Show the evidence rather than asserting a cause. The previous version of this
  # check claimed "modprobe failed" without ever looking at modprobe's output.
  warn "AmneziaWG module is not loaded. Evidence:"
  info "running kernel: $(uname -r)"
  info "modprobe says:  $(modprobe amneziawg 2>&1 || true)"
  info "dkms status:"
  dkms status 2>/dev/null | grep -i amnezia | sed 's/^/      /' || info "      (no amneziawg entry)"
  info "module file:    $(modinfo -n amneziawg 2>/dev/null || echo "not found for $(uname -r)")"
  die "AmneziaWG module could not be loaded — see the evidence above"
fi
log "AmneziaWG module OK"
info "version: $(modinfo -F version amneziawg 2>/dev/null || echo unknown)   kernel: $(uname -r)"

# --- 2. Journal size cap ------------------------------------------------------
# systemd's default is uncapped (up to 10% of the filesystem), which is the wrong
# default for an exit: a unit or container stuck in a log-spewing failure loop
# fills the disk, and a full disk on an exit takes its data plane down with it.
# The cap matters more than the steady-state size — journals here sit well under
# it, so this only ever bites during exactly the failure it is meant to contain.
# Left alone if the operator already dropped in their own tuning.
if [ ! -f /etc/systemd/journald.conf.d/wgfleet.conf ]; then
  log "capping systemd journal (200M, keep 1G free, 2 weeks)"
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/wgfleet.conf <<'EOF'
# Installed by wgfleet prepare-node.sh. See the rationale in that script.
[Journal]
SystemMaxUse=200M
SystemKeepFree=1G
MaxRetentionSec=2week
EOF
  systemctl restart systemd-journald
else
  log "journal cap already configured — leaving /etc/systemd/journald.conf.d/wgfleet.conf alone"
fi

# --- 3. ZeroTier management overlay -----------------------------------------
# The controller/agent and all admin/metrics surfaces live on this overlay, never
# the public interface. Joining needs the network id; AUTHORIZATION is a manual
# step in ZeroTier Central (and is where you assign the managed IP that becomes
# the node's mgmt_addr in the fleet manifest).
if command -v zerotier-cli >/dev/null 2>&1; then
  log "ZeroTier already installed"
else
  log "installing ZeroTier"
  curl -fsSL https://install.zerotier.com | bash
fi

if [ -n "$ZT_NETWORK" ]; then
  if zt_joined "$ZT_NETWORK"; then
    log "already joined ZeroTier network $ZT_NETWORK"
  else
    log "joining ZeroTier network $ZT_NETWORK"
    zerotier-cli join "$ZT_NETWORK"
  fi
  log "ZeroTier node id: $(zerotier-cli info 2>/dev/null | awk '{print $3}')"
  cat <<EOF

  NEXT: authorize this node in ZeroTier Central (https://my.zerotier.com),
  assign it the managed IP you will use as mgmt_addr in fleet.yaml, then run:

      wgfleet-controller --provision <node-name> --plan   # review
      wgfleet-controller --provision <node-name>          # apply

EOF
else
  log "no ZeroTier network id given (arg or ZT_NETWORK) — skipping join"
  log "join manually later: zerotier-cli join <network-id>"
fi

# A closing summary of what is now TRUE on this box. The operator is about to
# hand these values to the provisioner or paste them into a bug report, and
# re-deriving them by hand is exactly the friction this script should absorb.
log "OS prep complete — summary"
info "host:        $(hostname)"
info "os:          $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo unknown)"
info "kernel:      $(uname -r) ($(uname -m))"
info "amneziawg:   loaded, version $(modinfo -F version amneziawg 2>/dev/null || echo unknown)"
info "journal cap: $(grep -h '^SystemMaxUse' /etc/systemd/journald.conf.d/wgfleet.conf 2>/dev/null | cut -d= -f2 || echo 'not set')"
if command -v zerotier-cli >/dev/null 2>&1; then
  info "zerotier:    node $(zerotier-cli info 2>/dev/null | awk '{print $3}'), networks: $(zerotier-cli listnetworks 2>/dev/null | awk 'NR>1 {printf "%s ", $3}' || echo none)"
  info "zt address:  $(ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^zt/ {print $4; exit}' || echo '(none yet — authorize in ZeroTier Central)')"
else
  info "zerotier:    not installed"
fi
info ""
info "Node is ready for 'wgfleet-controller --provision'."
