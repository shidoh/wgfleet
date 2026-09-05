#!/bin/bash
# netns-move-check.sh — assert that a master which moved client interception into
# mihomo's namespace is STEADY there, and that nothing it was carrying was lost.
#
# It exists because two live attempts failed in ways no point-in-time check saw:
#
#   2026-09-05 #1  a self-heal probe still aimed at the host restarted mihomo every
#                  pass; each restart re-initialised its userspace WireGuard devices
#                  and three exits fell out of the balancer in three minutes.
#   2026-09-05 #2  the veth was sized to the CLIENT tunnel (1360) while the uplink
#                  is 1500, so mihomo's own tunnel packets did not fit. WireGuard
#                  handshakes are 148 bytes and passed, so every tunnel reported UP
#                  while carrying nothing; four exits died and the tier failed over.
#
# Both were invisible to a snapshot: the first needs WATCHING, the second needs a
# BIG packet. Neither is something you notice by looking at a dashboard.
#
# Run it BEFORE the switch to take the baseline, then again AFTER:
#     netns-move-check.sh --baseline
#     ... flip the knob ...
#     netns-move-check.sh 180
set -u
STATE=/run/netns-move-check.before.json
WINDOW="${1:-180}"
fail=0
ok()  { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fail=1; }

api_addr() {
  # The operator-facing address keeps working across the move (a DNAT redirects it),
  # so it is the right one to ask from here either way.
  grep -oE '^external-controller:.*' /etc/mihomo/config.yaml 2>/dev/null |
    sed 's/.*external-controller:[[:space:]]*//;s/"//g'
}
api_secret() {
  grep -oE '^[[:space:]]*secret:.*' /etc/mihomo/config.yaml 2>/dev/null |
    head -1 | sed 's/.*secret:[[:space:]]*//;s/"//g'
}
# live_tunnels prints "<name> <alive>" for every master↔exit proxy.
live_tunnels() {
  curl -s --max-time 6 -H "Authorization: Bearer $(api_secret)" \
       "http://$(api_addr)/proxies" 2>/dev/null |
  python3 -c '
import sys, json
try: d = json.load(sys.stdin)["proxies"]
except Exception: sys.exit(1)
for k, v in sorted(d.items()):
    if v.get("type") in ("WireGuard", "Vless"):
        print(k, "1" if v.get("alive") else "0")
'
}

if [ "$WINDOW" = "--baseline" ]; then
  live_tunnels > "$STATE" || { echo "cannot read the proxy list — is mihomo up?"; exit 1; }
  printf 'baseline: %s tunnel(s), %s alive → %s\n' \
    "$(wc -l < "$STATE")" "$(grep -c ' 1$' "$STATE")" "$STATE"
  exit 0
fi

ns_of() { local p; p=$(docker inspect -f '{{.State.Pid}}' "$1" 2>/dev/null); [ -n "$p" ] && [ "$p" != 0 ] && readlink "/proc/$p/ns/net"; }

echo "watching for ${WINDOW}s"
start_mihomo=$(docker inspect -f '{{.State.StartedAt}}' mihomo 2>/dev/null)
start_holder=$(docker inspect -f '{{.State.StartedAt}}' wgfleet-netns 2>/dev/null)
restarts=0
deadline=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  now=$(docker inspect -f '{{.State.StartedAt}}' mihomo 2>/dev/null)
  [ "$now" != "$start_mihomo" ] && { restarts=$((restarts+1)); start_mihomo="$now"; }
  sleep 10
done

# 1. The failure of attempt #1: a restart is invisible to a snapshot.
[ "$restarts" -eq 0 ] && ok "mihomo did not restart in ${WINDOW}s" \
  || bad "mihomo restarted ${restarts}x — a self-heal is fighting the move"

# A throttled self-heal is the same defect with the symptom suppressed.
journalctl -u wgfleet-agent --since "-${WINDOW}s" --no-pager -o cat 2>/dev/null |
  grep -q "restart throttled" \
  && bad "a self-heal is being throttled — it wants to restart mihomo every pass" \
  || ok "no self-heal is asking to restart mihomo"

# 2. The failure of attempt #2: small packets pass, big ones do not.
peer=$(ip -br addr show mih-host 2>/dev/null | grep -oE '100\.[0-9.]+' | head -1)
peer="${peer%.*}.2"
nspath=$(docker inspect -f '{{.State.Pid}}' wgfleet-netns 2>/dev/null)
if [ -n "$nspath" ] && [ "$nspath" != 0 ]; then
  up=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [a-z0-9]+' | head -1 | cut -d' ' -f2)
  mtu=$(ip link show "$up" 2>/dev/null | grep -oE 'mtu [0-9]+' | cut -d' ' -f2)
  probe=$(( ${mtu:-1500} - 68 ))   # IP+ICMP headers, with room for the uplink's own
  if nsenter --net="/proc/$nspath/ns/net" ping -c1 -W3 -M do -s "$probe" -q 1.1.1.1 >/dev/null 2>&1; then
    ok "a ${probe}-byte packet leaves the namespace (uplink mtu ${mtu:-?})"
  else
    bad "a ${probe}-byte packet does NOT leave the namespace — the veth is narrower than the uplink (mtu ${mtu:-?}); handshakes will pass and tunnels will carry nothing"
  fi
fi

# 3. mihomo where it should be, and reachable.
if [ -n "$(ns_of mihomo)" ] && [ "$(ns_of mihomo)" = "$(ns_of wgfleet-netns)" ]; then
  ok "mihomo shares the holder's namespace"
else
  bad "mihomo is not in the holder's namespace ($(ns_of mihomo) vs $(ns_of wgfleet-netns))"
fi
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$(api_addr)/" 2>/dev/null)
case "$code" in
  200|401|404) ok "the control API still answers at $(api_addr)" ;;
  *) bad "the control API is unreachable at $(api_addr) (http=$code) — the dashboard moved with mihomo" ;;
esac

# 4. The failure BOTH attempts ended in: exits dropping out of the balancer.
#    Compared against the baseline, not eyeballed.
if [ -s "$STATE" ]; then
  now_t=$(mktemp); live_tunnels > "$now_t"
  lost=0
  while read -r name was; do
    [ "$was" = "1" ] || continue
    is=$(awk -v n="$name" '$1==n{print $2}' "$now_t")
    [ "$is" = "1" ] || { bad "tunnel $name was alive before the move and is not now"; lost=1; }
  done < "$STATE"
  [ "$lost" -eq 0 ] && ok "every tunnel that was alive before the move still is"
  rm -f "$now_t"
else
  bad "no baseline: run '$0 --baseline' BEFORE flipping, or this check is blind"
fi

[ "$start_holder" = "$(docker inspect -f '{{.State.StartedAt}}' wgfleet-netns 2>/dev/null)" ] \
  && ok "the namespace holder did not restart" \
  || bad "the holder restarted — mihomo is now in an orphaned namespace"

exit "$fail"
