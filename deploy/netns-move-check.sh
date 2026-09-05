#!/bin/bash
# netns-move-check.sh — assert that a master which has moved client interception
# into mihomo's namespace is actually STEADY there.
#
# It exists because the stand rehearsal on 2026-09-05 was green while the thing it
# was rehearsing was broken. Every structural check passed — mihomo was in the
# namespace, the rules were right, the client-path probes were green — and none of
# them asked the one question that mattered: is mihomo being restarted? It was,
# every pass, because a self-heal probe was still looking at the host. Three exits
# fell out of the balancer on the live fleet within three minutes of the switch.
#
# A container restart is invisible to every point-in-time check. Only a check that
# WATCHES can see it, so this one watches.
#
# Usage:  netns-move-check.sh [seconds]   (default 180)
set -u
WINDOW="${1:-180}"
fail=0
say() { printf '%s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fail=1; }
ok()  { printf '  ok    %s\n' "$*"; }

pid_of() { docker inspect -f '{{.State.Pid}}' "$1" 2>/dev/null; }
ns_of()  { local p; p=$(pid_of "$1"); [ -n "$p" ] && [ "$p" != 0 ] && readlink "/proc/$p/ns/net"; }

say "watching for ${WINDOW}s"
start_mihomo=$(docker inspect -f '{{.State.StartedAt}}' mihomo 2>/dev/null)
start_holder=$(docker inspect -f '{{.State.StartedAt}}' wgfleet-netns 2>/dev/null)
restarts_seen=0
deadline=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  now_mihomo=$(docker inspect -f '{{.State.StartedAt}}' mihomo 2>/dev/null)
  [ "$now_mihomo" != "$start_mihomo" ] && { restarts_seen=$((restarts_seen+1)); start_mihomo="$now_mihomo"; }
  sleep 10
done

# 1. The one the rehearsal missed.
if [ "$restarts_seen" -eq 0 ]; then
  ok "mihomo did not restart in ${WINDOW}s"
else
  bad "mihomo restarted ${restarts_seen}x in ${WINDOW}s — a self-heal is fighting the move"
fi

# 2. Nothing may be asking for a restart it does not get, either: a throttled
#    self-heal is the same defect with the symptom suppressed.
if journalctl -u wgfleet-agent --since "-${WINDOW}s" --no-pager -o cat 2>/dev/null |
     grep -q "restart throttled"; then
  bad "a self-heal is being throttled — it wants to restart mihomo every pass"
else
  ok "no self-heal is asking to restart mihomo"
fi

# 3. mihomo is in the holder's namespace, not merely in one.
if [ "$(ns_of mihomo)" = "$(ns_of wgfleet-netns)" ] && [ -n "$(ns_of mihomo)" ]; then
  ok "mihomo shares the holder's namespace"
else
  bad "mihomo is not in the holder's namespace ($(ns_of mihomo) vs $(ns_of wgfleet-netns))"
fi

# 4. The agent can still steer mihomo: a moved API nobody can reach is a data
#    plane nobody can drain, reload or fail over.
peer=$(ip -br addr show mih-host 2>/dev/null | grep -oE '100\.[0-9.]+' | head -1)
peer="${peer%.*}.2"
if curl -s -o /dev/null --max-time 5 "http://${peer}:9090/" ; then
  ok "Clash API answers at ${peer}:9090"
else
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${peer}:9090/" 2>/dev/null)
  [ "$code" = "401" ] && ok "Clash API answers at ${peer}:9090 (401, needs the secret)" \
                      || bad "Clash API unreachable at ${peer}:9090 (http=$code)"
fi

# 5. Every exit tunnel is alive. This is what the operator noticed first and what
#    no automated check was watching.
say "  exits: check wg-best members in the dashboard or /proxies — a restart of"
say "         mihomo wedges its userspace WireGuard devices, and they do not"
say "         always come back on their own."

[ "$start_holder" = "$(docker inspect -f '{{.State.StartedAt}}' wgfleet-netns 2>/dev/null)" ] \
  && ok "the namespace holder did not restart" \
  || bad "the holder restarted — mihomo is now in an orphaned namespace"

exit "$fail"
