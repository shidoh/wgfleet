#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel.
#
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
#     .github/telegram-notify.sh <tag> <release-notes.md> <dist-dir>
#
# Posts the changelog as a message, then attaches the build archives
# (tar.gz + SHA256SUMS) as documents via sendMediaGroup. If any archive
# exceeds Telegram's 50 MB bot-upload limit, the upload is skipped and the
# message points at the GitHub Release assets instead (the message always
# carries the release URL, so nothing is lost).
#
# Requires: curl. Preinstalled on ubuntu-latest runners.

set -euo pipefail

TAG="${1:?usage: telegram-notify.sh <tag> <release-notes.md> <dist-dir>}"
NOTES_FILE="${2:?missing release-notes file}"
DIST_DIR="${3:?missing dist dir}"

: "${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN is required}"
: "${TELEGRAM_CHAT_ID:?TELEGRAM_CHAT_ID is required}"

REPO_URL="${REPO_URL:-https://github.com/shidoh/wgfleet}"
RELEASE_URL="$REPO_URL/releases/tag/$TAG"
API="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}"

MAX_BYTES=$((50 * 1024 * 1024))   # Telegram bot sendDocument upload ceiling
TG_MSG_LIMIT=4096                 # Telegram sendMessage text ceiling (chars)

# --- Changelog message --------------------------------------------------------
# Plain text (no parse_mode) sidesteps MarkdownV2 escaping; Telegram auto-links
# bare URLs. Strip Markdown noise that renders poorly as plain text: ATX
# headers, bold markers, inline-code backticks. Bullets and links stay intact.
BODY="$(sed -E \
  -e 's/^#+[[:space:]]*//' \
  -e 's/\*\*//g' \
  -e 's/`//g' \
  "$NOTES_FILE")"

MESSAGE="$(printf '🚀 wgfleet %s\n\n%s\n\n%s' "$TAG" "$BODY" "$RELEASE_URL")"

# Telegram rejects messages over 4096 chars — truncate on a safe boundary and
# keep the release link as the tail so the full changelog stays reachable.
if [ "${#MESSAGE}" -gt "$TG_MSG_LIMIT" ]; then
  MESSAGE="$(printf '%s' "$MESSAGE" | cut -c1-3900)"$'\n\n…\n\n'"Full changelog: $RELEASE_URL"
fi

echo "Sending changelog message to Telegram chat ${TELEGRAM_CHAT_ID}"
curl -fsS -X POST "$API/sendMessage" \
  --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
  --data-urlencode "text=${MESSAGE}" \
  --data-urlencode "disable_web_page_preview=true" \
  >/dev/null

# --- Build archives -----------------------------------------------------------
FILES=()
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/SHA256SUMS; do
  [ -f "$f" ] && FILES+=("$f")
done

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "No build archives found in ${DIST_DIR} — changelog posted, nothing to attach."
  exit 0
fi

# Any oversized archive → skip the upload entirely; the message already links to
# the GitHub Release, where the assets live without a size limit.
for f in "${FILES[@]}"; do
  sz="$(stat -c%s "$f")"
  if [ "$sz" -gt "$MAX_BYTES" ]; then
    echo "Archive $(basename "$f") is ${sz} bytes (> 50 MB Telegram limit) — skipping upload; assets remain on the GitHub Release."
    exit 0
  fi
done

echo "Attaching ${#FILES[@]} archive(s) to Telegram"

if [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup needs 2..10 items; a lone file goes via sendDocument.
  # --form-string for chat_id: a value like "@channel" would otherwise be read
  # by curl -F as an "@file" upload reference (curl error 26).
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    -F "document=@${FILES[0]}" \
    >/dev/null
  exit 0
fi

# Build the media array (attach:// references) and the matching -F file parts.
media_json='['
for i in "${!FILES[@]}"; do
  [ "$i" -eq 0 ] || media_json+=','
  media_json+="{\"type\":\"document\",\"media\":\"attach://file${i}\"}"
done
media_json+=']'

# --form-string for chat_id/media: curl -F reads a value starting with "@" (a
# "@channel" chat id) or "<" as a local file, which fails (curl error 26). Only
# the actual file parts below use -F "@path".
curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}" --form-string "media=${media_json}")
for i in "${!FILES[@]}"; do
  curl_args+=(-F "file${i}=@${FILES[$i]}")
done

curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
echo "Telegram announcement complete."
