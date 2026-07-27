#!/bin/bash
# wgfleet node OS-prep — run ONCE on a fresh Ubuntu VM before provisioning.
#
# It handles only the environmental / kernel-risky bits the wgfleet provisioner
# deliberately does NOT do: building the AmneziaWG kernel
# module via DKMS, and joining the ZeroTier management overlay (which needs
# out-of-band authorization). Everything else — hardening, nftables, apt deps,
# Docker, wgcf, the agent — is the provisioner's job (`controller --provision`).
#
# Idempotent: safe to re-run. Doubles as cloud-init user-data (it begins with a
# shebang, which cloud-init executes verbatim).
#
# Usage:
#   sudo ./prepare-node.sh <zerotier-network-id>
#   # or, as cloud-init user-data, set the network id below:
#   ZT_NETWORK=8056c2e21c000001 ./prepare-node.sh
#
# After this runs and the node is AUTHORIZED in ZeroTier Central (assign it the
# managed IP you put in the fleet manifest as mgmt_addr), run the provisioner.

set -euo pipefail

ZT_NETWORK="${1:-${ZT_NETWORK:-}}"

log() { printf '\n\033[1;32m[prepare-node]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[prepare-node] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v apt-get >/dev/null 2>&1 || die "this script targets Debian/Ubuntu (apt-get not found)"

export DEBIAN_FRONTEND=noninteractive

# --- 1. AmneziaWG kernel module (DKMS) --------------------------------------
# This is the hard pre-flight the provisioner checks but will not build itself:
# DKMS compiles against the running kernel, so it needs matching headers and can
# fail in environment-specific ways — better here, before reconcile, than mid-
# provision.
if lsmod | grep -qw amneziawg || modinfo amneziawg >/dev/null 2>&1; then
  log "AmneziaWG kernel module already present — skipping DKMS build"
else
  log "installing AmneziaWG kernel module via DKMS"
  apt-get update -y
  # software-properties-common provides add-apt-repository on minimal images.
  apt-get install -y software-properties-common
  add-apt-repository -y ppa:amnezia/ppa
  apt-get update -y
  # Headers for the RUNNING kernel AND the meta-package, so a later kernel upgrade
  # pulls matching headers and DKMS auto-rebuilds the module for it (otherwise an
  # apt/unattended kernel bump leaves AWG missing under the new kernel). Plus the
  # toolchain (build-essential/dkms), which minimal/cloud images such as Lima lack.
  apt-get install -y dkms build-essential \
    "linux-headers-$(uname -r)" linux-headers-generic \
    amneziawg-dkms amneziawg-tools \
    || die "AmneziaWG DKMS build failed — check that linux-headers-$(uname -r) is available for this kernel"
fi

# Ensure the module is loaded NOW (it may be built but not inserted — e.g. after a
# kernel change or reboot — which is exactly what trips the provisioner pre-flight)
# and on every future boot.
modprobe amneziawg 2>/dev/null || true
if [ ! -f /etc/modules-load.d/amneziawg.conf ]; then
  echo amneziawg > /etc/modules-load.d/amneziawg.conf
  log "module set to load on boot (/etc/modules-load.d/amneziawg.conf)"
fi

modinfo amneziawg >/dev/null 2>&1 || die "AmneziaWG module not built for $(uname -r) — re-run after installing linux-headers-$(uname -r)"
lsmod | grep -qw amneziawg || die "AmneziaWG module built but not loaded (modprobe failed)"
log "AmneziaWG module OK (loaded for kernel $(uname -r))"

# --- 2. ZeroTier management overlay -----------------------------------------
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
  if zerotier-cli listnetworks 2>/dev/null | grep -q "$ZT_NETWORK"; then
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

log "OS prep complete — node is ready for 'controller --provision'"
