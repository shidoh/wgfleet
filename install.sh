#!/usr/bin/env bash
# wgfleet master bootstrap — installer for the FIRST master node.
#
# Two ways to run it, same result:
#
#   A) from the release archive (recommended — see INSTALL.md in the archive):
#        tar xzf wgfleet-<version>-linux-amd64.tar.gz && cd wgfleet-linux-amd64
#        sudo ./install.sh
#      Binaries sitting next to this script are installed as-is; nothing is
#      downloaded.
#
#   B) one-line, straight off the internet:
#        curl -fsSL https://raw.githubusercontent.com/shidoh/wgfleet/main/install.sh | sudo bash
#      This downloads the release archive for this arch and verifies it against
#      the release SHA256SUMS before installing.
#
# What it does (idempotent, safe to re-run):
#   1. installs host deps (AmneziaWG kernel module via DKMS, ZeroTier, Docker)
#   2. installs controller + agent to /usr/local/bin (from the archive it runs
#      in, or downloaded + checksum-verified)
#   3. creates /etc/wgfleet and /var/lib/wgfleet
#   4. installs the controller + agent systemd units (left DISABLED)
#   5. drops controller.yaml / agent.yaml templates (only if absent)
#   6. prints the remaining operator steps (the parts that need YOUR input:
#      ZeroTier authorization, real addresses, CA init, starting the services)
#
# It deliberately does NOT start anything: the master needs a filled-in config
# and a locally-issued mTLS identity first. Those steps are printed at the end.
#
# Options (environment variables):
#   WGFLEET_VERSION=vX.Y.Z   install a specific release (default: latest)
#   ZT_NETWORK=<16-hex>      ZeroTier network id to join (else join manually later)
#   PUBLIC_IP=<ip>           master public IP (seeds the config template)
#   MGMT_ADDR=<zt-ip>        master mgmt/ZeroTier IP (seeds the config template)
#   SKIP_DEPS=1              skip Docker/ZeroTier/AmneziaWG (binaries + config only)
#
# Supports Debian/Ubuntu (apt) on linux/amd64 and linux/arm64.

set -euo pipefail

REPO="shidoh/wgfleet"
PREFIX="/usr/local/bin"
ETC="/etc/wgfleet"
VAR="/var/lib/wgfleet"
UNITDIR="/etc/systemd/system"

VERSION="${WGFLEET_VERSION:-latest}"
ZT_NETWORK="${ZT_NETWORK:-}"
PUBLIC_IP="${PUBLIC_IP:-}"
MGMT_ADDR="${MGMT_ADDR:-}"
SKIP_DEPS="${SKIP_DEPS:-0}"

# ---------------------------------------------------------------------------
c_g=$'\033[1;32m'; c_y=$'\033[1;33m'; c_r=$'\033[1;31m'; c_0=$'\033[0m'
log()  { printf '\n%s[wgfleet]%s %s\n' "$c_g" "$c_0" "$*"; }
warn() { printf '\n%s[wgfleet]%s %s\n' "$c_y" "$c_0" "$*"; }
die()  { printf '\n%s[wgfleet] ERROR:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }

# module_loaded <name> / zt_joined <network-id>
#
# NOT `lsmod | grep -q` or `zerotier-cli listnetworks | grep -q`. Under
# `set -o pipefail`, `grep -q` exits at the first match and closes the pipe; the
# producer then dies of SIGPIPE (141) with output still unwritten, and the
# pipeline reports 141 even though the match SUCCEEDED. Whether it happens
# depends on how early the match appears and how much is left to write, so the
# identical check passes on one host and fails on the next. awk consumes all of
# stdin, so there is no SIGPIPE; matching lsmod's column 1 exactly is also more
# correct than `grep -w`, which would match the name in another module's
# "Used by" column.
module_loaded() {
  lsmod | awk -v m="$1" '$1 == m { found = 1 } END { exit !found }'
}
zt_joined() {
  zerotier-cli listnetworks 2>/dev/null | awk -v n="$1" 'index($0, n) { found = 1 } END { exit !found }'
}

[ "$(id -u)" -eq 0 ] || die "run as root (e.g. pipe to 'sudo bash')"
command -v apt-get >/dev/null 2>&1 || die "this installer targets Debian/Ubuntu (apt-get not found)"
command -v curl    >/dev/null 2>&1 || { apt-get update -y && apt-get install -y curl; }

case "$(uname -m)" in
  x86_64|amd64)        ARCH=amd64 ;;
  aarch64|arm64)       ARCH=arm64 ;;
  *) die "unsupported architecture '$(uname -m)' (need x86_64 or aarch64)" ;;
esac
log "target: linux/$ARCH, wgfleet version: $VERSION"

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. host dependencies
# ---------------------------------------------------------------------------
install_deps() {
  # --- AmneziaWG kernel module (DKMS) — client-facing interface needs it ---
  if module_loaded amneziawg || modinfo amneziawg >/dev/null 2>&1; then
    log "AmneziaWG kernel module already present"
  else
    log "installing AmneziaWG kernel module (DKMS)"
    apt-get update -y
    apt-get install -y software-properties-common
    add-apt-repository -y ppa:amnezia/ppa
    apt-get update -y
    apt-get install -y dkms build-essential \
      "linux-headers-$(uname -r)" linux-headers-generic \
      amneziawg-dkms amneziawg-tools \
      || die "AmneziaWG DKMS build failed — ensure linux-headers-$(uname -r) is available, then re-run"
  fi
  modprobe amneziawg 2>/dev/null || true
  [ -f /etc/modules-load.d/amneziawg.conf ] || echo amneziawg > /etc/modules-load.d/amneziawg.conf
  modinfo amneziawg >/dev/null 2>&1 || die "AmneziaWG module not built for $(uname -r)"

  # --- ZeroTier management overlay ---
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
  fi

  # --- Docker (mihomo + wg-easy run in containers) ---
  if command -v docker >/dev/null 2>&1; then
    log "Docker already installed"
  else
    log "installing Docker"
    curl -fsSL https://get.docker.com | sh
  fi
}

if [ "$SKIP_DEPS" = "1" ]; then
  warn "SKIP_DEPS=1 — not installing Docker/ZeroTier/AmneziaWG (run deploy/prepare-node.sh yourself)"
else
  install_deps
fi

# ---------------------------------------------------------------------------
# 2. install the binaries — from the archive we live in, or downloaded
# ---------------------------------------------------------------------------
# When piped from curl, BASH_SOURCE is unset/stdin, so src stays empty and we
# fall through to the download path.
src=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]:-}" ]; then
  src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "$src" ] && [ -f "$src/wgfleet-controller" ] && [ -f "$src/wgfleet-agent" ]; then
  # --- local mode: running from an unpacked release archive ---
  log "installing from the local archive ($src)"
  [ -f "$src/VERSION" ] && log "archive build: $(cat "$src/VERSION")"
  install -m 0755 "$src/wgfleet-controller" "$PREFIX/wgfleet-controller"
  install -m 0755 "$src/wgfleet-agent"      "$PREFIX/wgfleet-agent"
else
  # --- remote mode: fetch the release archive and verify it ---
  # Release assets are named per-version (wgfleet-<version>-linux-<arch>.tar.gz),
  # so we need the concrete tag even for "latest". Resolve it from the
  # /releases/latest redirect, whose effective URL ends in /tag/<version>.
  if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSLo /dev/null -w '%{url_effective}' \
      "https://github.com/${REPO}/releases/latest" | sed 's#.*/tag/##')"
    [ -n "$VERSION" ] || die "could not resolve the latest release version"
    log "latest release resolves to $VERSION"
  fi
  base="https://github.com/${REPO}/releases/download/${VERSION}"

  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  tgz="wgfleet-${VERSION}-linux-${ARCH}.tar.gz"

  log "downloading $tgz + checksums from $base"
  for f in "$tgz" SHA256SUMS; do
    curl -fSL --retry 3 -o "$tmp/$f" "$base/$f" \
      || die "download failed: $base/$f (is the repo public and a release published?)"
  done

  log "verifying SHA256 checksum"
  ( cd "$tmp" && grep -E "  ${tgz}\$" SHA256SUMS | sha256sum -c - ) \
    || die "checksum verification FAILED — refusing to install"

  tar -xzf "$tmp/$tgz" -C "$tmp"
  unpacked="$tmp/wgfleet-linux-${ARCH}"
  [ -f "$unpacked/wgfleet-controller" ] || die "unexpected archive layout in $tgz"
  install -m 0755 "$unpacked/wgfleet-controller" "$PREFIX/wgfleet-controller"
  install -m 0755 "$unpacked/wgfleet-agent"      "$PREFIX/wgfleet-agent"
fi

log "installed: $("$PREFIX/wgfleet-controller" --version 2>/dev/null || echo wgfleet-controller)"

# ---------------------------------------------------------------------------
# 3. directories
# ---------------------------------------------------------------------------
install -d -m 0755 "$ETC"
install -d -m 0700 "$VAR"

# Fully annotated reference configs, for when the minimal template below is not
# enough (exit definitions, mihomo tuning, transports, ...). Reference only —
# nothing reads them.
if [ -n "$src" ] && [ -d "$src/examples" ]; then
  install -d -m 0755 "$ETC/examples"
  install -m 0644 "$src"/examples/*.yaml "$ETC/examples/"
  log "copied reference configs to $ETC/examples/"
fi

# ---------------------------------------------------------------------------
# 4. systemd units (left disabled — config + PKI come first)
# ---------------------------------------------------------------------------
cat > "$UNITDIR/wgfleet-controller.service" <<'UNIT'
[Unit]
Description=wgfleet controller
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/wgfleet-controller --config /etc/wgfleet/controller.yaml --log-format json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT

cat > "$UNITDIR/wgfleet-agent.service" <<'UNIT'
[Unit]
Description=wgfleet agent (master)
After=network-online.target wgfleet-controller.service docker.service
Wants=network-online.target wgfleet-controller.service

[Service]
# Generic unit: mgmt_addr / public_ip come from agent.yaml + the fleet manifest.
ExecStart=/usr/local/bin/wgfleet-agent --config /etc/wgfleet/agent.yaml --log-format json
Restart=on-failure
RestartSec=5
# The agent manages AmneziaWG interfaces, nftables and policy routing.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT

# Non-fatal: containers/WSL have the unit files but no running systemd, and there
# is no reason to abort the rest of the install (configs, next steps) over it.
systemctl daemon-reload 2>/dev/null \
  && log "installed systemd units (disabled): wgfleet-controller, wgfleet-agent" \
  || warn "systemd not available here — units written to $UNITDIR but not reloaded"

# ---------------------------------------------------------------------------
# 5. config templates (never overwrite an existing config)
# ---------------------------------------------------------------------------
mgmt="${MGMT_ADDR:-<mgmt-zt-ip>}"
pub="${PUBLIC_IP:-<public-ip>}"
zt="${ZT_NETWORK:-<zt-network-id>}"

if [ ! -e "$ETC/controller.yaml" ]; then
  cat > "$ETC/controller.yaml" <<YAML
# wgfleet controller config (co-located controller + master). Replace every
# <placeholder>. The mgmt address is the master's ZeroTier IP (assigned when you
# authorize the node in ZeroTier Central). Every option: CONFIGURATION.md.
controller:
  listen:  "${mgmt}:8443"        # agents dial this; seeds the cert SAN
  webui:   "127.0.0.1:9000"      # mgmt/ZT or loopback only
  store:   "${VAR}/state.db"
  metrics: "127.0.0.1:9300"
  pki:
    ca_cert: "${ETC}/ca.crt"
    ca_key:  "file://${ETC}/ca.key"   # file:// so the CLI can sign certs; keep it chmod 600

fleet:
  zerotier_network: "${zt}"      # 16-hex mgmt overlay id; exits join it during provisioning
  masters:
    - name: master-1
      mgmt_addr: "${mgmt}"       # same ZT address as controller.listen host
      public_ip: "${pub}"        # seeds wg-easy first run (INIT_HOST)
      client_awg: { listen_port: 443, address_pool: 10.80.0.0/24 }
      routing:    { direct_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16], balance: health }
      compose:    { wg_easy_web_port: 51821 }   # mihomo pinned to a safe default (v1.19.30); do NOT set :latest or "Alpha"
  exits: []                      # add exits later, then: wgfleet-controller --provision <name>
YAML
  chmod 0600 "$ETC/controller.yaml"   # holds WG/REALITY private keys + passwords once populated
  log "wrote $ETC/controller.yaml (template)"
else
  warn "$ETC/controller.yaml exists — left untouched"
fi

if [ ! -e "$ETC/agent.yaml" ]; then
  cat > "$ETC/agent.yaml" <<YAML
# wgfleet agent config for the co-located master.
agent:
  role: master
  controller: "${mgmt}:8443"     # the local controller, via the node's own ZT IP
  node_id: "master-1"            # MUST match masters[].name and the issued cert CN
  mgmt_addr: "${mgmt}"           # ZT address; agent binds /metrics to <mgmt>:9301
  reconcile_interval: 30s
  identity:
    cert: "${ETC}/node.crt"
    key:  "${ETC}/node.key"
    ca:   "${ETC}/ca.crt"        # REQUIRED — verifies the controller (written by --issue-node)
YAML
  chmod 0644 "$ETC/agent.yaml"
  log "wrote $ETC/agent.yaml (template)"
else
  warn "$ETC/agent.yaml exists — left untouched"
fi

# ---------------------------------------------------------------------------
# 6. next steps
# ---------------------------------------------------------------------------
cat <<EOF

$c_g==============================================================$c_0
$c_g wgfleet master bootstrap complete — a few operator steps remain$c_0
$c_g==============================================================$c_0

1. ZeroTier: authorize THIS node at https://my.zerotier.com and assign it a
   stable managed IP. That IP is your <mgmt-zt-ip>.
     zerotier-cli listnetworks
$( [ -z "$ZT_NETWORK" ] && echo "   (join first:  zerotier-cli join <zt-network-id>)" )

2. Edit the config and replace every <placeholder>:
     \$EDITOR $ETC/controller.yaml      # mgmt IP, public IP, ZT network id
     \$EDITOR $ETC/agent.yaml           # same mgmt IP

3. Initialise the CA and issue the master's local mTLS identity:
     wgfleet-controller --config $ETC/controller.yaml --init-pki
     wgfleet-controller --config $ETC/controller.yaml \\
         --issue-node master-1 --issue-out $ETC
     chmod 600 $ETC/ca.key

4. Set the Web UI admin password:
     wgfleet-controller --config $ETC/controller.yaml --set-admin-password

5. Start the services:
     systemctl enable --now wgfleet-controller wgfleet-agent
     systemctl status wgfleet-controller wgfleet-agent

6. Open the Web UI over SSH/ZT at http://127.0.0.1:9000 — the master goes
   Reconciling -> Ready once wg-easy + mihomo are up. Add exits from there or:
     wgfleet-controller --config $ETC/controller.yaml --provision <exit> --plan

7. Add your exit servers — see step 7 of the quickstart.

Full walkthrough:  INSTALL.md       (in this archive)
Configuration:     CONFIGURATION.md (in this archive)
License:           LICENSE (AGPL-3.0) + DISCLAIMER.md
EOF
