#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel.
#
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
#     .github/telegram-notify.sh <tag> <release-notes.md> <dist-dir>
#
# Sends the build archives (tar.gz + SHA256SUMS) as one document album, captioned
# with an HTML header plus the release highlights (the annotated tag's message,
# put there by release-notes.sh), and then posts the changelog itself as
# follow-up messages. Without highlights the caption is just the header — the
# name and the version — never an empty bubble.
#
# Why two steps: a Telegram caption is capped at 1024 characters, a message at
# 4096. A whole changelog does not fit in a caption, and anything that does not
# fit used to be dropped — the channel saw the first ten commits of the Features
# section and nothing else. The highlights (short by construction) ride along
# with the files; the changelog is chunked across as many messages as it needs,
# split on line boundaries so a **bold** or `code` marker is never cut in half.
#
# TELEGRAM_DRY_RUN=1 prints every message that would be sent and calls no API.
# No repository links — the repo is private.
#
# Requires: curl, jq. Both are preinstalled on ubuntu-latest runners.

set -euo pipefail

TAG="${1:?usage: telegram-notify.sh <tag> <release-notes.md> <dist-dir>}"
NOTES_FILE="${2:?missing release-notes file}"
DIST_DIR="${3:?missing dist dir}"

DRY_RUN="${TELEGRAM_DRY_RUN:-}"
if [ -z "$DRY_RUN" ]; then
  : "${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN is required}"
  : "${TELEGRAM_CHAT_ID:?TELEGRAM_CHAT_ID is required}"
fi

API="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN:-dry-run}"
MAX_BYTES=$((50 * 1024 * 1024))   # Telegram bot sendDocument upload ceiling
CAPTION_BUDGET=900                # caption ceiling is 1024; leave headroom
MESSAGE_BUDGET=3500               # message ceiling is 4096; leave headroom

# --- Markdown -> Telegram HTML ------------------------------------------------
# escape_html: neutralize &, <, > so they don't collide with our own HTML tags.
escape_html() { sed -E -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# to_html: escape first, then map markers to tags so the tags we add are never
# re-escaped. Section headers (## / ###) become bold lines. Runs of blank lines
# collapse to one, and a bullet wrapped across source lines is rejoined so it
# reads as a single line in Telegram.
to_html() {
  awk '
    /^[[:space:]]*$/ { if (buf != "") { print buf; buf = "" } blank++; next }
    /^[-*] / || /^#/ {
      if (buf != "") print buf
      if (blank && NR > 1) print ""
      blank = 0; buf = $0; next
    }
    {
      sub(/^[[:space:]]+/, "")
      if (buf != "") buf = buf " " $0; else buf = $0
      blank = 0
    }
    END { if (buf != "") print buf }
  ' | escape_html | sed -E \
    -e 's|^#+[[:space:]]*(.*)$|<b>\1</b>|' \
    -e 's|\*\*([^*]+)\*\*|<b>\1</b>|g' \
    -e 's|`([^`]+)`|<code>\1</code>|g'
}

# --- Split the notes: highlights ride with the files, changelog follows --------
NOTES="$(grep -vE '^\*\*Full Changelog\*\*:' "$NOTES_FILE")"
LEAD="$(awk '/^## Changelog/ { exit } { print }' <<<"$NOTES")"
REST="$(awk '/^## Changelog/ { f = 1 } f' <<<"$NOTES")"
# Notes without a "## Changelog" heading: everything is changelog, no highlights.
if [ -z "$(tr -d '[:space:]' <<<"$REST")" ]; then
  LEAD=""
  REST="$NOTES"
fi

LEAD_HTML="$(to_html <<<"$LEAD")"
REST_HTML="$(to_html <<<"$REST")"

# fit: keep whole lines while they fit the budget; mark a cut with an ellipsis.
# Only the caption is ever cut — the changelog is chunked, never truncated.
fit() {
  local budget="$1" out="" line
  while IFS= read -r line; do
    if [ $(( ${#out} + ${#line} + 1 )) -gt "$budget" ]; then
      out+="…"$'\n'
      break
    fi
    out+="${line}"$'\n'
  done
  printf '%s' "$out"
}

TAG_HTML="$(printf '%s' "$TAG" | escape_html)"
# Header layout: the app name on its own line, then the release version alone on
# a dedicated bold line so it reads as the most prominent token. Telegram bot
# messages have no font-size control, so "bigger" comes from weight + a line to
# itself + a distinct emoji, not an actual larger font.
CAPTION="$(printf '🚀 <b>wgfleet</b>\n\n🏷 <b>%s</b>' "$TAG_HTML")"
if [ -n "$(tr -d '[:space:]' <<<"$LEAD_HTML")" ]; then
  CAPTION+="$(printf '\n\n%s' "$(fit "$CAPTION_BUDGET" <<<"$LEAD_HTML")")"
fi

# --- Senders ------------------------------------------------------------------
send_message() {
  local text="$1"
  if [ -n "$DRY_RUN" ]; then
    printf '\n----- sendMessage (%d chars) -----\n%s\n' "${#text}" "$text"
    return 0
  fi
  curl -fsS -X POST "$API/sendMessage" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "text=${text}" \
    --form-string "parse_mode=HTML" \
    --form-string "disable_web_page_preview=true" \
    >/dev/null
}

# send_changelog: the whole changelog, in as many messages as it takes. Each
# chunk is its own expandable blockquote so a long list stays collapsed.
send_changelog() {
  [ -n "$(tr -d '[:space:]' <<<"$REST_HTML")" ] || return 0
  local chunk="" line part=0
  flush_chunk() {
    [ -n "$(tr -d '[:space:]' <<<"$chunk")" ] || return 0
    part=$((part + 1))
    local head=""
    [ "$part" -gt 1 ] && head=$'<b>Changelog (cont.)</b>\n'
    send_message "$(printf '%s<blockquote expandable>%s</blockquote>' "$head" "$chunk")"
    chunk=""
  }
  while IFS= read -r line; do
    if [ $(( ${#chunk} + ${#line} + 1 )) -gt "$MESSAGE_BUDGET" ]; then
      flush_chunk
    fi
    chunk+="${line}"$'\n'
  done <<<"$REST_HTML"
  flush_chunk
}

send_caption_only() {
  echo "Posting header-only message (reason: $1)"
  send_message "$CAPTION"
}

# --- Collect build archives ---------------------------------------------------
FILES=()
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/SHA256SUMS; do
  [ -f "$f" ] && FILES+=("$f")
done

# Fall back to a message without attachments when there is nothing (small
# enough) to attach: no files, or any file over the 50 MB bot-upload limit.
oversized=""
for f in "${FILES[@]:-}"; do
  [ -n "$f" ] || continue
  if [ "$(wc -c < "$f")" -gt "$MAX_BYTES" ]; then
    oversized="$(basename "$f")"
    break
  fi
done

if [ "${#FILES[@]}" -eq 0 ]; then
  send_caption_only "no archives found in ${DIST_DIR}"
  send_changelog
  echo "Telegram announcement complete."
  exit 0
fi
if [ -n "$oversized" ]; then
  send_caption_only "${oversized} exceeds the 50 MB Telegram limit"
  send_changelog
  echo "Telegram announcement complete."
  exit 0
fi

# --- Archives + captioned header, then the changelog --------------------------
if [ -n "$(tr -d '[:space:]' <<<"$LEAD_HTML")" ]; then
  echo "Sending ${#FILES[@]} archive(s) with the highlights, then the changelog"
else
  echo "Sending ${#FILES[@]} archive(s) (no highlights), then the changelog"
fi

if [ -n "$DRY_RUN" ]; then
  printf '\n----- album caption (%d chars, %d file(s)) -----\n%s\n' \
    "${#CAPTION}" "${#FILES[@]}" "$CAPTION"
elif [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup requires 2..10 items; a lone file goes via sendDocument.
  # --form-string keeps curl from reading a leading "@" (as in "@channel") or
  # "<" value as a local file (curl error 26); only real files use -F "@path".
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "caption=${CAPTION}" \
    --form-string "parse_mode=HTML" \
    -F "document=@${FILES[0]}" \
    >/dev/null
else
  # The caption rides on the LAST album item: in a document album each file is
  # its own bubble, so a caption on the first item renders text sandwiched
  # between the files. Anchoring it to the last item puts it below all files.
  # jq builds the media array so the multi-line HTML caption is JSON-escaped.
  media_json="$(jq -cn --arg cap "$CAPTION" '
    [ $ARGS.positional | to_entries[]
      | { type: "document", media: ("attach://file" + (.key | tostring)) } ]
    | .[-1].caption = $cap
    | .[-1].parse_mode = "HTML"
  ' --args "${FILES[@]}")"

  curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}" --form-string "media=${media_json}")
  for i in "${!FILES[@]}"; do
    curl_args+=(-F "file${i}=@${FILES[$i]}")
  done

  curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
fi

send_changelog
echo "Telegram announcement complete."
