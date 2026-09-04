#!/usr/bin/env bash
# Run a command inside one of the master's network namespaces.
#
# Moving mihomo and the client-path prober into namespaces of their own is what
# removes the port collision that black-holed client QUIC — but it also means
# `ss`, `tcpdump` and `nft list ruleset` on the master now show half the picture.
# That cost is real, and this is it paid: one command instead of remembering
# nsenter and a container PID at three in the morning.
#
#   deploy/mihomo-ns.sh ss -lunp                 # mihomo's namespace
#   deploy/mihomo-ns.sh nft list ruleset
#   deploy/mihomo-ns.sh --synth ip -br addr show # the prober's namespace
#   deploy/mihomo-ns.sh --synth curl -v https://cp.cloudflare.com/generate_204
set -euo pipefail

HOLDER=wgfleet-netns
SYNTH_NS=wgfleet-synth

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

[ $# -eq 0 ] && usage 1
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then usage 0; fi

if [ "$1" = "--synth" ]; then
  shift
  [ $# -eq 0 ] && usage 1
  exec ip netns exec "$SYNTH_NS" "$@"
fi

pid=$(docker inspect -f '{{.State.Pid}}' "$HOLDER" 2>/dev/null || true)
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  echo "wgfleet: the namespace holder '$HOLDER' is not running." >&2
  echo "         mihomo is on host networking; use the plain command instead." >&2
  exit 1
fi
exec nsenter --net="/proc/$pid/ns/net" "$@"
