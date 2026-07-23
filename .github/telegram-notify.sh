#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel — as a SINGLE message.
#
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
#     .github/telegram-notify.sh <tag> <release-notes.md> <dist-dir>
#
# Sends the build archives (tar.gz + SHA256SUMS) as one document album via
# sendMediaGroup, with the changelog attached as the album caption: an HTML
# header plus the changelog inside a collapsible <blockquote expandable> so a
# long release note stays tidy. If an archive exceeds Telegram's 50 MB
# bot-upload limit (or none is found), the changelog is posted on its own with
# sendMessage. No repository links — the repo is private.
#
# Requires: curl, jq. Both are preinstalled on ubuntu-latest runners.

set -euo pipefail

TAG="${1:?usage: telegram-notify.sh <tag> <release-notes.md> <dist-dir>}"
NOTES_FILE="${2:?missing release-notes file}"
DIST_DIR="${3:?missing dist dir}"

: "${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN is required}"
: "${TELEGRAM_CHAT_ID:?TELEGRAM_CHAT_ID is required}"

API="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}"
MAX_BYTES=$((50 * 1024 * 1024))   # Telegram bot sendDocument upload ceiling
CAPTION_BUDGET=950                # Telegram caption ceiling is 1024; leave headroom

# --- Build the HTML caption ---------------------------------------------------
# escape_html: neutralize &, <, > so they don't collide with our own HTML tags.
escape_html() { sed -E -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# Drop the repo compare-link footer (private repo — the link is useless here),
# then keep whole changelog lines until the caption budget is spent. Truncating
# on line boundaries never splits a **bold** / `code` marker mid-token, which
# would otherwise yield unbalanced HTML tags that Telegram rejects.
RAW="$(grep -vE '^\*\*Full Changelog\*\*:' "$NOTES_FILE" | sed -E '/^[[:space:]]*$/d')"
BODY=""
truncated=0
while IFS= read -r line; do
  if [ $(( ${#BODY} + ${#line} + 1 )) -gt "$CAPTION_BUDGET" ]; then
    truncated=1
    break
  fi
  BODY+="${line}"$'\n'
done <<< "$RAW"
[ "$truncated" -eq 1 ] && BODY+="…"$'\n'

# Markdown -> Telegram HTML. Escape first, then map markers to tags so the tags
# we add are never re-escaped. Section headers (### / ####) become bold lines.
# NB: the '|' delimiter is required — a '#' delimiter would collide with the
# literal '#' in the ^#+ header pattern (ambiguous on both GNU and BSD sed).
BODY_HTML="$(printf '%s' "$BODY" | escape_html | sed -E \
  -e 's|^#+[[:space:]]*(.*)$|<b>\1</b>|' \
  -e 's|\*\*([^*]+)\*\*|<b>\1</b>|g' \
  -e 's|`([^`]+)`|<code>\1</code>|g')"

TAG_HTML="$(printf '%s' "$TAG" | escape_html)"
CAPTION="$(printf '🚀 <b>wgfleet %s</b>\n<blockquote expandable>%s</blockquote>' \
  "$TAG_HTML" "$BODY_HTML")"

# --- Collect build archives ---------------------------------------------------
FILES=()
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/SHA256SUMS; do
  [ -f "$f" ] && FILES+=("$f")
done

# Fall back to a caption-only message when there is nothing (small enough) to
# attach: no files, or any file over the 50 MB bot-upload limit.
send_caption_only() {
  echo "Posting changelog-only message (reason: $1)"
  curl -fsS -X POST "$API/sendMessage" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "text=${CAPTION}" \
    --form-string "parse_mode=HTML" \
    --form-string "disable_web_page_preview=true" \
    >/dev/null
}

if [ "${#FILES[@]}" -eq 0 ]; then
  send_caption_only "no archives found in ${DIST_DIR}"
  exit 0
fi
for f in "${FILES[@]}"; do
  if [ "$(stat -c%s "$f")" -gt "$MAX_BYTES" ]; then
    send_caption_only "$(basename "$f") exceeds the 50 MB Telegram limit"
    exit 0
  fi
done

# --- Single combined message: archives + changelog caption --------------------
echo "Sending ${#FILES[@]} archive(s) + changelog as one Telegram message"

if [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup requires 2..10 items; a lone file goes via sendDocument.
  # --form-string keeps curl from reading a leading "@" (as in "@channel") or
  # "<" value as a local file (curl error 26); only real files use -F "@path".
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "caption=${CAPTION}" \
    --form-string "parse_mode=HTML" \
    -F "document=@${FILES[0]}" \
    >/dev/null
  echo "Telegram announcement complete."
  exit 0
fi

# The caption rides on the first album item. jq builds the media array so the
# multi-line HTML caption is JSON-escaped correctly.
media_json="$(jq -cn --arg cap "$CAPTION" '
  [ $ARGS.positional | to_entries[]
    | { type: "document", media: ("attach://file" + (.key | tostring)) } ]
  | .[0].caption = $cap
  | .[0].parse_mode = "HTML"
' --args "${FILES[@]}")"

curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}" --form-string "media=${media_json}")
for i in "${!FILES[@]}"; do
  curl_args+=(-F "file${i}=@${FILES[$i]}")
done

curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
echo "Telegram announcement complete."
