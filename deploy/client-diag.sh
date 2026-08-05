#!/usr/bin/env bash
# wgfleet client-side tunnel diagnostics — portable across Android (Termux),
# macOS and Linux. Run it FROM a VPN client while the AmneziaWG tunnel is up to
# capture a snapshot of everything that historically broke this setup:
#
#   - PMTU / MSS black-holes — nested AmneziaWG + WARP tunnels shrink the usable
#     packet size, and a path that silently drops anything over that size is the
#     #1 source of "works but every request lags / empty reply from server /
#     Telegram stuck".
#   - Egress path: is traffic actually leaving via Cloudflare WARP?
#   - DNS resolution + which resolver answers.
#   - Latency / packet loss to the master and to the open internet.
#   - Intermittent TCP/TLS failures under repeated load.
#   - Throughput (no iperf required).
#
# It is READ-ONLY: it never changes routes, interfaces or config. Safe to re-run.
# Output is printed (colorised) AND written to a plain-text report you can share.
#
# Usage:
#   ./client-diag.sh                 # autodetect, sensible defaults
#   MASTER=10.80.0.1 ./client-diag.sh
#   QUICK=1 ./client-diag.sh         # skip throughput + heavy loops
#   THROUGHPUT=1 ./client-diag.sh    # also run the throughput download (off by default)
#   ./client-diag.sh --help
#
# Termux first run:  pkg install bash curl iputils-ping dnsutils
# (the script works with whatever subset is installed; missing tools are skipped)

set -u

# ---------------------------------------------------------------------------
# config (override via env)
# ---------------------------------------------------------------------------
MASTER="${MASTER:-}"                       # tunnel gateway / master tunnel IP; autodetected if empty
QUICK="${QUICK:-0}"                         # 1 = skip throughput + repeated-load loop
THROUGHPUT="${THROUGHPUT:-0}"              # 1 = run the throughput download (off by default: slowest probe, least diagnostic — PMTU/MSS/egress are already pinpointed above)
LOOP_COUNT="${LOOP_COUNT:-15}"             # repeated-request samples for the flakiness probe
DL_BYTES="${DL_BYTES:-10000000}"           # throughput test size (10 MB)
CURL_MAXTIME="${CURL_MAXTIME:-15}"         # per-request hard timeout (s)
DL_MAXTIME="${DL_MAXTIME:-20}"             # throughput hard cap (s) — bounds the download
DL_STALL_SECS="${DL_STALL_SECS:-8}"        # abort the download if it stalls this long
DL_STALL_BPS="${DL_STALL_BPS:-20000}"      # "stalled" = slower than this many bytes/s

# TLS hosts to exercise (mix of CDN-fronted + commonly-blocked-in-RU targets)
TLS_HOSTS="${TLS_HOSTS:-www.google.com github.com www.cloudflare.com api.telegram.org www.youtube.com}"
# PMTU sweep: tested as MTU values; payload = mtu - 28 (20 IP + 8 ICMP)
MTU_CANDIDATES="${MTU_CANDIDATES:-1280 1320 1360 1380 1400 1420 1440 1460 1500}"
PING_HOST="${PING_HOST:-1.1.1.1}"

JSON="${JSON:-0}"
for a in "$@"; do
  case "$a" in
    -h|--help)  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --json)     JSON=1 ;;
    --quick)    QUICK=1 ;;
    *) printf 'unknown arg: %s (try --help)\n' "$a" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# output plumbing
# ---------------------------------------------------------------------------
# colour only on an interactive TTY and never in JSON mode
if [ -t 1 ] && [ "$JSON" != "1" ]; then
  C_HEAD='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_DIM='\033[2m'; C_0='\033[0m'
else
  C_HEAD=''; C_OK=''; C_WARN=''; C_ERR=''; C_DIM=''; C_0=''
fi

REPORT="${REPORT:-${TMPDIR:-/tmp}/wgfleet-clientdiag-$(date +%Y%m%d-%H%M%S).txt}"
: > "$REPORT" 2>/dev/null || REPORT="./wgfleet-clientdiag.txt"

# JSON accumulator: flat key<TAB>value map, emitted as one object at the end.
JSON_TMP="${TMPDIR:-/tmp}/wgfleet-clientdiag-json.$$"
: > "$JSON_TMP" 2>/dev/null || JSON_TMP="./wgfleet-clientdiag-json.$$"
jset() { printf '%s\t%s\n' "$1" "$2" >> "$JSON_TMP"; }   # jset key value

# everything goes to the report (plain); to stdout too, UNLESS in JSON mode
# (there stdout must stay pure JSON, so human lines go to the report + stderr).
# ESC built via ANSI-C quoting so stripping works on BSD sed (macOS) too.
ESC=$'\033'
say()  {
  local plain; plain="$(printf '%b' "$*" | sed "s/${ESC}\[[0-9;]*m//g")"
  printf '%s\n' "$plain" >> "$REPORT"
  if [ "$JSON" = "1" ]; then printf '%s\n' "$plain" >&2; else printf '%b\n' "$*"; fi
}
sect() { say ""; say "${C_HEAD}== $* ==${C_0}"; }
ok()   { say "  ${C_OK}[ ok ]${C_0} $*"; }
warn() { say "  ${C_WARN}[warn]${C_0} $*"; }
err()  { say "  ${C_ERR}[fail]${C_0} $*"; }
kv()   { say "  ${C_DIM}$1:${C_0} $2"; }
have() { command -v "$1" >/dev/null 2>&1; }

# emit the accumulated map as one flat JSON object (numbers unquoted, empty->null)
emit_json() {
  printf '{\n'
  local first=1 key val
  while IFS=$'\t' read -r key val; do
    [ -z "$key" ] && continue
    [ "$first" = 1 ] && first=0 || printf ',\n'
    printf '  "%s": ' "$key"
    if [ -z "$val" ]; then
      printf 'null'
    elif printf '%s' "$val" | grep -Eq '^-?[0-9]+(\.[0-9]+)?$'; then
      printf '%s' "$val"                       # number
    else
      val="$(printf '%s' "$val" | sed 's/\\/\\\\/g; s/"/\\"/g')"
      printf '"%s"' "$val"                      # string
    fi
  done < "$JSON_TMP"
  printf '\n}\n'
}

# detect a usable physical (non-tunnel) interface + its IPv4, for direct compare
PHYS_IFACE=""; PHYS_IP=""
detect_phys() {
  if have ip; then
    while read -r idx name _; do
      case "$name" in lo|*tun*|*tap*|wg*|awg*|zt*|utun*|gif*|stf*) continue ;; esac
      local a; a="$(ip -4 -o addr show dev "$name" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
      [ -n "$a" ] && { PHYS_IFACE="$name"; PHYS_IP="$a"; return; }
    done < <(ip -o link 2>/dev/null | awk -F': ' '{print NR" "$2}')
  elif have ifconfig; then
    local name a
    for name in $(ifconfig -l 2>/dev/null); do
      case "$name" in lo*|*tun*|*tap*|utun*|gif*|stf*|awdl*|llw*|bridge*|ap*|anpi*) continue ;; esac
      a="$(ifconfig "$name" 2>/dev/null | awk '/inet /{print $2; exit}')"
      [ -n "$a" ] && { PHYS_IFACE="$name"; PHYS_IP="$a"; return; }
    done
  fi
}

# egress identity, optionally bound to a source IP/interface. echoes "ip warp colo org"
egress_probe() {  # egress_probe [curl-bind-arg...]
  have curl || { echo " "; return 1; }
  local tr ip warp colo
  tr="$(run_to "$CURL_MAXTIME" curl -fsS --max-time "$CURL_MAXTIME" "$@" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)"
  [ -z "$tr" ] && { echo " "; return 1; }
  ip="$(printf '%s\n' "$tr"   | awk -F= '/^ip=/{print $2}')"
  warp="$(printf '%s\n' "$tr" | awk -F= '/^warp=/{print $2}')"
  colo="$(printf '%s\n' "$tr" | awk -F= '/^colo=/{print $2}')"
  printf '%s %s %s\n' "${ip:-?}" "${warp:-?}" "${colo:-?}"
}

# download throughput in Mbit/s, optionally bound. echoes "mbit secs httpcode"
# Self-contained hard cap with LIVE progress: curl runs in the background writing its
# -w result to a temp file; we poll it once a second, printing a dot to stderr so the
# user SEES it working (the report stays clean — dots never enter $()-captured stdout),
# and SIGTERM/SIGKILL it if it overruns. This neither relies on timeout(1) (absent on
# stock macOS) nor leaves the user staring at a frozen "downloading…" line. curl's own
# --connect-timeout / --max-time / --speed-time guards still abort a dead path sooner.
dl_speed() {  # dl_speed [curl-bind-arg...]
  have curl || { echo "0 0 000"; return 1; }
  local res bps rest secs code
  # Plain FOREGROUND curl. Its own --max-time is the authoritative hard cap and is
  # honoured reliably (verified), so the call cannot outlast DL_MAXTIME. We deliberately
  # do NOT background curl or spawn a dot-printer: a background job inside a $()-capture
  # keeps the substitution's stdout fd open until it is reaped, which on macOS bash 3.2
  # could hang the whole call long after curl finished — that was the real "hangs on
  # throughput" cause. --connect-timeout / --speed-time / --speed-limit abort a dead or
  # stalled path even sooner.
  res="$(curl -sS -o /dev/null \
    --connect-timeout 10 --max-time "$DL_MAXTIME" \
    --speed-time "$DL_STALL_SECS" --speed-limit "$DL_STALL_BPS" "$@" \
    -w '%{speed_download}:%{time_total}:%{http_code}' \
    "https://speed.cloudflare.com/__down?bytes=$DL_BYTES" 2>/dev/null)"
  bps="${res%%:*}"; rest="${res#*:}"; secs="${rest%%:*}"; code="${res##*:}"
  # Mbit/s = bytes/s * 8 / 1e6, computed in pure shell arithmetic — NOT awk. The old
  # `awk "BEGIN{printf ...}"` was the actual cause of the throughput hang: macOS bash
  # brace-expanded `{printf "%.1f", N}` into a malformed `awk 'BEGINprintf...'` with no
  # input file, so awk blocked on stdin forever. Integer math with one decimal needs no
  # subprocess and cannot hang. Strip any fractional part / junk to a bare integer first.
  bps="${bps%%.*}"; bps="${bps//[!0-9]/}"; bps="${bps:-0}"
  case "$secs" in ''|*[!0-9.]*) secs=0  ;; esac
  case "$code" in ''|*[!0-9]*)  code=000 ;; esac
  local mbit_x10=$(( bps * 8 / 100000 ))   # = Mbit/s * 10
  printf '%s %s %s\n' "$((mbit_x10/10)).$((mbit_x10%10))" "$secs" "$code"
}

# run a command with a HARD wall-clock cap. Prefer a real timeout(1)/gtimeout(1);
# otherwise (e.g. stock macOS, which ships neither) fall back to a portable
# background+watchdog that SIGTERMs then SIGKILLs the command. Without this fallback
# a stalled curl/ping on a black-holed path hangs forever — the "script hangs on the
# throughput check" symptom — because there is nothing to bound it. The command's
# stdout still flows to the caller's $(...) capture; only the watchdog is silenced.
TO=""
if have timeout; then TO="timeout"; elif have gtimeout; then TO="gtimeout"; fi
run_to() {
  local s="$1"; shift
  if [ -n "$TO" ]; then "$TO" "$s" "$@"; return $?; fi
  "$@" &
  local pid=$!
  ( sleep "$s"; kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  local watcher=$!
  wait "$pid" 2>/dev/null; local rc=$?
  kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
  return $rc
}

# ---------------------------------------------------------------------------
# platform detection
# ---------------------------------------------------------------------------
OS="unknown"; PLAT="unknown"
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)
    OS="linux"
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then PLAT="termux"; fi
    ;;
esac
[ "$PLAT" = "unknown" ] && PLAT="$OS"

sect "Environment"
kv "host"      "$(hostname 2>/dev/null || echo '?')"
kv "platform"  "$PLAT ($(uname -srm 2>/dev/null))"
kv "date"      "$(date 2>/dev/null)"
kv "report"    "$REPORT"
jset platform "$PLAT"
jset host "$(hostname 2>/dev/null)"
jset date "$(date 2>/dev/null)"
[ -z "$TO" ] && warn "no 'timeout' helper found — some probes may hang on a dead path"

# ---------------------------------------------------------------------------
# local network state: interfaces, MTU, routes, default gateway
# ---------------------------------------------------------------------------
sect "Local network / tunnel interface"

GW=""
if have ip; then
  GW="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  say "$(ip -brief addr 2>/dev/null | sed 's/^/  /')"
  say "  ${C_DIM}-- mtu --${C_0}"
  say "$(ip -o link 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print "  "$2" mtu "$(i+1)}}' | tr -d ':')"
  say "  ${C_DIM}-- default route --${C_0}"
  say "$(ip route show default 2>/dev/null | sed 's/^/  /')"
elif have ifconfig; then
  GW="$(route -n get default 2>/dev/null | awk '/gateway/{print $2; exit}')"
  say "$(ifconfig 2>/dev/null | awk '/^[a-z]/{i=$1} /inet |mtu/{print "  "i" "$0}' | sed 's/[[:space:]]\{2,\}/ /g')"
  say "  ${C_DIM}-- default route --${C_0}"
  say "$(netstat -rn 2>/dev/null | awk 'NR<=2 || /^default/{print "  "$0}')"
fi
[ -n "$GW" ] && kv "default gateway" "$GW"

# best-effort WireGuard/AmneziaWG handshake introspection (CLI clients only)
WG_BIN=""
for b in awg wg; do have "$b" && { WG_BIN="$b"; break; }; done
if [ -n "$WG_BIN" ]; then
  say "  ${C_DIM}-- $WG_BIN show --${C_0}"
  out="$($WG_BIN show all 2>/dev/null || $WG_BIN show 2>/dev/null)"
  if [ -n "$out" ]; then
    say "$(printf '%s\n' "$out" | sed 's/^/  /')"
    hs="$(printf '%s\n' "$out" | awk -F': ' '/latest handshake/{print $2}' | head -1)"
    [ -n "$hs" ] && { kv "latest handshake" "$hs"; jset wg_latest_handshake "$hs"; }
  else
    warn "$WG_BIN present but no interface visible (GUI client keeps it in its own netns?)"
  fi
else
  kv "wg/awg CLI" "not installed (GUI client — handshake introspection skipped)"
fi

# autodetect master if not supplied
if [ -z "$MASTER" ] && [ -n "$GW" ]; then MASTER="$GW"; fi
kv "master/gateway under test" "${MASTER:-<unknown>}"
jset default_gateway "$GW"
jset master "$MASTER"

# ---------------------------------------------------------------------------
# reachability + latency: master tunnel IP and open internet
# ---------------------------------------------------------------------------
sect "Reachability & latency"

ping_n() {  # ping_n <host> <count>
  local host="$1" cnt="${2:-5}" out rc
  if [ "$OS" = "macos" ]; then
    out="$(run_to 12 ping -c "$cnt" -t 8 "$host" 2>&1)"; rc=$?
  else
    out="$(run_to 12 ping -c "$cnt" -W 2 "$host" 2>&1)"; rc=$?
  fi
  printf '%s\n' "$out"
  return $rc
}

rtt_avg() { printf '%s\n' "$1" | grep -Eo '[0-9.]+/[0-9.]+/[0-9.]+' | head -1 | cut -d/ -f2; }
loss_pct() { printf '%s\n' "$1" | grep -Eo '[0-9.]+% packet loss' | head -1 | grep -Eo '^[0-9.]+'; }

if [ -n "$MASTER" ]; then
  out="$(ping_n "$MASTER" 5)"
  line="$(printf '%s\n' "$out" | grep -E 'min/avg|rtt|round-trip' | head -1)"
  loss="$(printf '%s\n' "$out" | grep -Eo '[0-9.]+% packet loss' | head -1)"
  if printf '%s\n' "$out" | grep -qE 'min/avg|rtt|round-trip'; then
    ok "master $MASTER reachable — ${line#*= } (loss: ${loss:-?})"
    jset master_rtt_avg_ms "$(rtt_avg "$out")"; jset master_loss_pct "$(loss_pct "$out")"
  else
    err "master $MASTER not answering ICMP (may be filtered) — ${loss:-no reply}"
    jset master_loss_pct "$(loss_pct "$out")"
  fi
fi

out="$(ping_n "$PING_HOST" 5)"
line="$(printf '%s\n' "$out" | grep -E 'min/avg|rtt|round-trip' | head -1)"
loss="$(printf '%s\n' "$out" | grep -Eo '[0-9.]+% packet loss' | head -1)"
if printf '%s\n' "$out" | grep -qE 'min/avg|rtt|round-trip'; then
  ok "internet ($PING_HOST) via tunnel — ${line#*= } (loss: ${loss:-?})"
  jset inet_rtt_avg_ms "$(rtt_avg "$out")"; jset inet_loss_pct "$(loss_pct "$out")"
else
  err "no ICMP to $PING_HOST through tunnel (loss: ${loss:-100%})"
  jset inet_loss_pct "$(loss_pct "$out")"
fi

# traceroute is informative but optional/slow
if [ "$QUICK" != "1" ] && have traceroute; then
  say "  ${C_DIM}-- traceroute $PING_HOST (first 8 hops) --${C_0}"
  say "$(run_to 25 traceroute -m 8 -w 2 "$PING_HOST" 2>&1 | sed 's/^/  /')"
fi

# ---------------------------------------------------------------------------
# PMTU sweep — the headline check for this project
# ---------------------------------------------------------------------------
sect "Path MTU (DF-bit sweep) — black-hole detector"
say "  ${C_DIM}largest ICMP packet that survives with DF set; project clamps client path to ~1320 MTU${C_0}"

ping_df() {  # ping_df <host> <mtu>  -> returns 0 if a full-size DF packet gets through
  local host="$1" mtu="$2" payload=$(( $2 - 28 ))
  if [ "$OS" = "macos" ]; then
    run_to 6 ping -c 1 -t 4 -D -s "$payload" "$host" >/dev/null 2>&1
  else
    run_to 6 ping -c 1 -W 2 -M do -s "$payload" "$host" >/dev/null 2>&1
  fi
}

pmtu_sweep() {  # pmtu_sweep <host> <label> <json_key>
  local host="$1" label="$2" jkey="$3" best=0 m map=""
  [ -z "$host" ] && { warn "no host for $label PMTU sweep"; return; }
  for m in $MTU_CANDIDATES; do
    if ping_df "$host" "$m"; then best="$m"; map="$map ${m}✓"; else map="$map ${m}✗"; fi
  done
  kv "$label sweep" "$map"
  jset "$jkey" "$best"
  if [ "$best" -ge 1400 ]; then
    ok "$label effective PMTU ≈ $best (healthy)"
  elif [ "$best" -ge 1280 ]; then
    warn "$label effective PMTU ≈ $best (tight — expected with nested AWG+WARP; MSS clamp must cover this)"
  elif [ "$best" -gt 0 ]; then
    warn "$label effective PMTU ≈ $best (very low)"
  else
    err "$label: even smallest probe blocked — host may not answer ICMP, or hard MTU black-hole"
  fi
}

pmtu_sweep "$PING_HOST" "internet" pmtu_internet
[ -n "$MASTER" ] && pmtu_sweep "$MASTER" "master" pmtu_master

# ---------------------------------------------------------------------------
# egress: are we actually exiting via Cloudflare WARP?
# ---------------------------------------------------------------------------
sect "Egress path (is traffic leaving via Cloudflare WARP?)"

TUN_EGRESS_IP=""
if have curl; then
  read -r eip warpf colo <<EOF
$(egress_probe)
EOF
  if [ -n "$eip" ] && [ "$eip" != "?" ]; then
    TUN_EGRESS_IP="$eip"
    kv "egress IP"   "$eip"
    kv "CF colo"     "${colo:-?}"
    jset egress_ip "$eip"; jset egress_warp "$warpf"; jset egress_colo "$colo"
    case "$warpf" in
      on|plus) ok "Cloudflare reports warp=$warpf — egress IS through WARP" ;;
      off)     warn "Cloudflare reports warp=off — egress is the datacenter IP (direct fallback or WARP down)" ;;
      *)       kv "warp" "${warpf:-unknown}" ;;
    esac
  else
    err "could not reach cloudflare trace endpoint (TLS/egress problem?)"
  fi
  # second opinion / geo
  geo="$(run_to "$CURL_MAXTIME" curl -fsS --max-time "$CURL_MAXTIME" https://ipinfo.io/json 2>/dev/null)"
  if [ -n "$geo" ]; then
    org="$(printf '%s' "$geo" | tr -d '\n ' | sed -E 's/.*"ip":"([^"]*)".*"org":"([^"]*)".*"country":"([^"]*)".*/\1  \2  \3/')"
    kv "ipinfo" "$org"
    jset egress_org "$(printf '%s' "$geo" | tr -d '\n ' | sed -E 's/.*"org":"([^"]*)".*/\1/')"
    jset egress_country "$(printf '%s' "$geo" | tr -d '\n ' | sed -E 's/.*"country":"([^"]*)".*/\1/')"
  fi
else
  err "curl not installed — cannot test egress (Termux: pkg install curl)"
fi

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
sect "DNS resolution"

# which resolver is configured
RESOLVERS=""
if [ "$OS" = "macos" ] && have scutil; then
  RESOLVERS="$(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')"
elif [ -r /etc/resolv.conf ]; then
  RESOLVERS="$(awk '/^nameserver/{print $2}' /etc/resolv.conf | tr '\n' ' ')"
fi
[ -n "$RESOLVERS" ] && { kv "resolvers" "$RESOLVERS"; jset dns_resolvers "$RESOLVERS"; }

DNS_OK=0; DNS_TOTAL=0
dns_q() {  # dns_q <name>
  local name="$1" t0 t1 res
  DNS_TOTAL=$((DNS_TOTAL+1))
  t0=$(date +%s 2>/dev/null)
  if have dig;       then res="$(run_to 8 dig +short +time=3 +tries=1 "$name" A 2>/dev/null | grep -E '^[0-9]' | tr '\n' ' ')";
  elif have nslookup;then res="$(run_to 8 nslookup "$name" 2>/dev/null | awk '/^Address: /{print $2}' | tr '\n' ' ')";
  elif have host;    then res="$(run_to 8 host "$name" 2>/dev/null | awk '/has address/{print $4}' | tr '\n' ' ')";
  elif have getent;  then res="$(run_to 8 getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')";
  else warn "no DNS tool (dig/nslookup/host/getent) — install dnsutils"; return; fi
  t1=$(date +%s 2>/dev/null)
  if [ -n "$res" ]; then ok "$name -> ${res}($((t1-t0))s)"; DNS_OK=$((DNS_OK+1)); else err "$name did not resolve"; fi
}
for n in google.com github.com api.telegram.org; do dns_q "$n"; done
jset dns_resolved "$DNS_OK"; jset dns_queried "$DNS_TOTAL"

# ---------------------------------------------------------------------------
# TLS connectivity + timing to multiple hosts
# ---------------------------------------------------------------------------
sect "TLS connectivity & timing"
TLS_OK=0; TLS_TOTAL=0
if have curl; then
  for h in $TLS_HOSTS; do
    TLS_TOTAL=$((TLS_TOTAL+1))
    res="$(run_to "$CURL_MAXTIME" curl -sS -o /dev/null --max-time "$CURL_MAXTIME" \
      -w '%{http_code} dns=%{time_namelookup}s conn=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s' \
      "https://$h/" 2>&1)"
    rc=$?
    code="${res%% *}"
    hk="$(printf '%s' "$h" | tr '.-' '__')"
    ttfb="$(printf '%s' "$res" | grep -Eo 'ttfb=[0-9.]+' | cut -d= -f2)"
    jset "tls_${hk}_code" "$code"; jset "tls_${hk}_ttfb_s" "$ttfb"
    if [ "$rc" -eq 0 ] && [ "$code" != "000" ]; then
      ok "$h  $res"; TLS_OK=$((TLS_OK+1))
    else
      err "$h  FAILED (rc=$rc) ${res}"
    fi
  done
  jset tls_ok "$TLS_OK"; jset tls_total "$TLS_TOTAL"
else
  err "curl not installed"
fi

# ---------------------------------------------------------------------------
# intermittent-failure probe (the 'empty reply / random timeouts' symptom)
# ---------------------------------------------------------------------------
if [ "$QUICK" != "1" ] && have curl; then
  sect "Stability under repeated load ($LOOP_COUNT requests)"
  target="https://www.google.com/generate_204"
  fails=0; tmax=0; tsum=0; i=0
  while [ "$i" -lt "$LOOP_COUNT" ]; do
    i=$((i+1))
    t="$(run_to "$CURL_MAXTIME" curl -sS -o /dev/null --max-time "$CURL_MAXTIME" -w '%{http_code}:%{time_total}' "$target" 2>/dev/null)"
    code="${t%%:*}"; dt="${t##*:}"
    if [ "$code" = "204" ] || [ "$code" = "200" ]; then
      ms="$(awk "BEGIN{printf \"%d\", ${dt:-0}*1000}")"
      tsum=$((tsum+ms)); [ "$ms" -gt "$tmax" ] && tmax=$ms
      printf '.'
    else
      fails=$((fails+1)); printf 'X'
    fi
  done
  printf '\n'
  avg=0; [ "$i" -gt "$fails" ] && avg=$((tsum/(i-fails)))
  say "  samples=$i  failures=$fails  avg=${avg}ms  worst=${tmax}ms"
  jset stability_samples "$i"; jset stability_failures "$fails"
  jset stability_avg_ms "$avg"; jset stability_worst_ms "$tmax"
  if [ "$fails" -eq 0 ] && [ "$tmax" -lt 1500 ]; then
    ok "stable — no failures, no latency spikes"
  elif [ "$fails" -eq 0 ]; then
    warn "no hard failures but latency spikes (worst ${tmax}ms) — classic PMTU/MSS or LB-flap symptom"
  else
    err "$fails/$i requests failed — intermittent path problem (correlate with PMTU sweep & egress section)"
  fi
fi

# ---------------------------------------------------------------------------
# throughput (no iperf needed) — Cloudflare speed endpoint, exits via tunnel
# ---------------------------------------------------------------------------
TUN_MBIT=""
if [ "$THROUGHPUT" = "1" ] && [ "$QUICK" != "1" ] && have curl; then
  sect "Throughput (download ~$((DL_BYTES/1000000)) MB via tunnel)"
  say "  ${C_DIM}downloading… (foreground curl, hard-capped at ~${DL_MAXTIME}s)${C_0}"
  read -r mbit secs code <<EOF
$(dl_speed)
EOF
  if [ "$code" != "000" ]; then
    TUN_MBIT="$mbit"
    ok "download ≈ ${mbit} Mbit/s over ${secs}s"
    jset throughput_tunnel_mbit "$mbit"
    kv "note" "ZT-bound paths are CPU-limited on the master; see the comparison below"
  else
    err "throughput test failed — egress or PMTU likely"
  fi
fi

# ---------------------------------------------------------------------------
# tunnel vs direct comparison — isolate the tunnel's contribution
# ---------------------------------------------------------------------------
# Bind probes to the physical interface so they bypass the VPN default route,
# then SELF-VALIDATE the bypass by checking the egress IP actually changed.
# Without root we cannot guarantee a bypass; we report honestly when it fails.
if [ "$THROUGHPUT" = "1" ] && [ "$QUICK" != "1" ] && have curl; then
  sect "Tunnel vs direct (binds to physical interface; self-validated)"
  detect_phys
  if [ -z "$PHYS_IP" ]; then
    warn "no physical interface with an IPv4 found — cannot run the direct comparison"
  else
    kv "physical iface" "$PHYS_IFACE ($PHYS_IP)"
    jset phys_iface "$PHYS_IFACE"
    read -r dip dwarp dcolo <<EOF
$(egress_probe --interface "$PHYS_IP")
EOF
    if [ -z "$dip" ] || [ "$dip" = "?" ]; then
      warn "direct probe could not reach the internet bound to $PHYS_IP"
      if [ "$OS" = "macos" ]; then
        warn "(expected on macOS without root: --interface binds source-IP only, VPN still owns the route)"
      else
        warn "(captive portal, or the physical link has no direct internet)"
      fi
      jset compare_bypass_worked false
    elif [ -n "$TUN_EGRESS_IP" ] && [ "$dip" = "$TUN_EGRESS_IP" ]; then
      warn "direct egress IP ($dip) == tunnel egress IP — bypass did NOT take effect"
      warn "(VPN owns the route and we are non-root; comparison not possible on this client)"
      jset compare_bypass_worked false
    else
      ok "bypass confirmed — direct egress $dip (warp=$dwarp) vs tunnel egress ${TUN_EGRESS_IP:-?}"
      jset compare_bypass_worked true
      jset direct_egress_ip "$dip"
      # throughput direct (curl --interface binds source; ping can't, x-platform)
      read -r dmbit dsecs dcode <<EOF2
$(dl_speed --interface "$PHYS_IP")
EOF2
      if [ "$dcode" != "000" ]; then
        ok "direct download   ≈ ${dmbit} Mbit/s"
        jset throughput_direct_mbit "$dmbit"
        if [ -n "$TUN_MBIT" ]; then
          ok "tunnel download   ≈ ${TUN_MBIT} Mbit/s"
          ratio="$(awk "BEGIN{ if(${dmbit:-0}>0) printf \"%.0f\", ${TUN_MBIT:-0}*100/${dmbit}; else print 0 }")"
          jset throughput_tunnel_pct_of_direct "$ratio"
          if [ "$ratio" -ge 70 ]; then
            ok "tunnel delivers ${ratio}% of direct — overhead is modest"
          elif [ "$ratio" -ge 30 ]; then
            warn "tunnel delivers only ${ratio}% of direct — significant tunnel/CPU overhead (ZT single-core on master?)"
          else
            err "tunnel delivers ${ratio}% of direct — severe bottleneck (CPU/MTU/LB-flap — see other sections)"
          fi
        fi
      else
        warn "direct throughput test failed"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
if [ "$THROUGHPUT" != "1" ] && [ "$QUICK" != "1" ]; then
  sect "Throughput"
  kv "skipped" "set THROUGHPUT=1 to run the download/comparison (off by default so the script always finishes fast)"
fi

# ---------------------------------------------------------------------------
say ""
say "${C_HEAD}== Done ==${C_0}"
say "Full report saved to: ${C_OK}$REPORT${C_0}"
say "Share it with:  ${C_DIM}cat '$REPORT'${C_0}  (or send the file)"

if [ "$JSON" = "1" ]; then emit_json; fi
rm -f "$JSON_TMP" 2>/dev/null
