#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel — as ONE message.
#
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
#     .github/telegram-notify.sh <tag> <release-notes.md> <dist-dir>
#
# Sends the announcement as a text message — version, highlights, and a count of
# what the changelog holds — and then the files right behind it: the build
# archives, SHA256SUMS, and the release notes as CHANGELOG-<tag>.md. The album is
# sent silently, so the pair costs the channel ONE notification.
#
# Text first, files second, and not as a caption, because a document album has no
# single caption to speak of: each file is its own bubble and a caption belongs to
# the bubble it is attached to. On the first item it renders BETWEEN the files, on
# the last one it lands under four download rows, and either way the channel
# preview shows a file name instead of the announcement. There is no
# show_caption_above_media for documents.
#
# The changelog is attached rather than posted because a message is 4096
# characters and a full changelog is not: v0.2.2's was 5.9 KB. That leaves exactly
# three options — cut it, hide it, or attach it. This attaches it.
#
# The two that were tried first are worth naming, because both look reasonable
# until you see them in a channel:
#   * splitting the changelog across messages produced a second bubble opening
#     mid-list, which reads as debris;
#   * <blockquote expandable> collapses to THREE LINES, so a quote that began
#     with "Changelog" + a blank line + "Features" showed the reader one word.
# Telegram has no list markup either, hence "•" — bullets are a convention here,
# not a feature.
#
# TELEGRAM_DRY_RUN=1 prints the message that would be sent and calls no API.
# No repository links — the repo is private, so a "full changelog" link would be
# useless to every subscriber; the file is the link.
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
MAX_BYTES=$((50 * 1024 * 1024))   # Telegram bot upload ceiling, per file
TEXT_BUDGET=3500                  # the ceiling is 4096; the highlights use a fraction

# --- Markdown -> Telegram HTML ------------------------------------------------
# escape_html: neutralize &, <, > so they don't collide with our own HTML tags.
escape_html() { sed -E -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# to_html renders the highlights the way a channel post reads best: one bullet per
# line (Telegram wraps for us, so a hard-wrapped source line must be rejoined),
# a blank line BETWEEN bullets so they do not run together into a wall of text,
# "•" instead of "-", and headings as bold lines.
to_html() {
  awk '
    function flush() { if (buf != "") { if (out++) print ""; print buf; buf = "" } }
    /^[[:space:]]*$/ { flush(); next }
    /^[-*][[:space:]]/ { flush(); sub(/^[-*][[:space:]]+/, "• "); buf = $0; next }
    /^#/ { flush(); buf = $0; next }
    { sub(/^[[:space:]]+/, ""); buf = (buf == "" ? $0 : buf " " $0) }
    END { flush() }
  ' | escape_html | sed -E \
    -e 's|^#+[[:space:]]*(.*)$|<b>\1</b>|' \
    -e 's|\*\*([^*]+)\*\*|<b>\1</b>|g' \
    -e 's|`([^`]+)`|<code>\1</code>|g'
}

# fit keeps whole lines while they fit the budget, marking a cut with an ellipsis.
# Only the announcement is ever cut, and never at the cost of information: the
# full notes ride along as a file.
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

# --- Split the notes: highlights go in the caption, the rest is the file -------
NOTES="$(grep -vE '^\*\*Full Changelog\*\*:' "$NOTES_FILE")"
LEAD="$(awk '/^## Changelog/ { exit } { print }' <<<"$NOTES")"
REST="$(awk '/^## Changelog/ { f = 1 } f' <<<"$NOTES")"
# Notes without a "## Changelog" heading: it is all changelog, and there are no
# highlights to lift into the caption.
if [ -z "$(tr -d '[:space:]' <<<"$REST")" ]; then
  LEAD=""
  REST="$NOTES"
fi
# Drop the "Highlights" heading itself: the caption is short enough that a section
# title only takes space from the thing it titles.
LEAD_HTML="$(sed -E '/^##[[:space:]]*Highlights[[:space:]]*$/d' <<<"$LEAD" | to_html)"

# summary_line counts what the attached changelog holds, per section, so the
# reader can tell at a glance whether opening it is worth it.
summary_line() {
  awk '
    /^###[[:space:]]/ {
      name = $0
      sub(/^###[[:space:]]*/, "", name)
      order[++n] = name
      next
    }
    /^-[[:space:]]/ { count[order[n]]++; total++ }
    END {
      # Section titles read as headings, not as counted nouns: "4 documentation"
      # is not a sentence. Anything unmapped falls back to its lowercased title.
      label["Breaking Changes"] = "breaking"; label["Features"] = "features"
      label["Bug Fixes"] = "fixes";           label["Performance"] = "perf"
      label["Refactoring"] = "refactors";     label["Documentation"] = "docs"
      label["Build System"] = "build";        label["Other Changes"] = "other"

      if (total == 0) exit
      printf "%d change%s: ", total, (total == 1 ? "" : "s")
      for (i = 1; i <= n; i++) {
        name = order[i]
        if (count[name] == 0) continue
        printf "%s%d %s", (shown++ ? ", " : ""), count[name],
          (name in label ? label[name] : tolower(name))
      }
      printf "\n"
    }
  ' <<<"$REST"
}

TAG_HTML="$(printf '%s' "$TAG" | escape_html)"
NOTES_NAME="CHANGELOG-${TAG}.md"

# The header is one line: the product and the version, which is what a reader
# scrolling a channel needs to identify the post. Telegram bot messages have no
# font-size control, so prominence comes from weight, position and an emoji.
ANNOUNCEMENT="$(printf '🚀 <b>wgfleet %s</b>' "$TAG_HTML")"
if [ -n "$(tr -d '[:space:]' <<<"$LEAD_HTML")" ]; then
  ANNOUNCEMENT+="$(printf '\n\n%s' "$(fit "$TEXT_BUDGET" <<<"$LEAD_HTML")")"
fi
SUMMARY="$(summary_line)"
if [ -n "$SUMMARY" ]; then
  ANNOUNCEMENT+="$(printf '\n\n%s — full changelog in <code>%s</code>' \
    "$(printf '%s' "$SUMMARY" | escape_html)" "$(printf '%s' "$NOTES_NAME" | escape_html)")"
fi

# --- Collect what the album carries -------------------------------------------
# The notes go in as a file of their own, named for the tag so it is still
# identifiable once it is sitting in somebody's downloads.
NOTES_DOC="$(mktemp -d)/${NOTES_NAME}"
cp "$NOTES_FILE" "$NOTES_DOC"

FILES=()
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/SHA256SUMS; do
  [ -f "$f" ] || continue
  if [ "$(wc -c < "$f")" -gt "$MAX_BYTES" ]; then
    echo "skipping $(basename "$f"): over the 50 MB Telegram limit"
    continue
  fi
  FILES+=("$f")
done
FILES+=("$NOTES_DOC")

send_message() {
  if [ -n "$DRY_RUN" ]; then
    printf '\n----- sendMessage (%d chars) -----\n%s\n' "${#1}" "$1"
    return 0
  fi
  curl -fsS -X POST "$API/sendMessage" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "text=$1" \
    --form-string "parse_mode=HTML" \
    --form-string "disable_web_page_preview=true" \
    >/dev/null
}

if [ -n "$DRY_RUN" ]; then
  printf '\n----- sendMessage (%d chars) -----\n%s\n' "${#ANNOUNCEMENT}" "$ANNOUNCEMENT"
  printf '\n----- album, silent: %d file(s), no caption -----\n' "${#FILES[@]}"
  for f in "${FILES[@]}"; do printf '  %s\n' "$(basename "$f")"; done
  echo "Telegram announcement complete (dry run)."
  exit 0
fi

echo "Posting the announcement, then ${#FILES[@]} file(s) silently behind it"
send_message "$ANNOUNCEMENT"

if [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup requires 2..10 items; a lone file goes via sendDocument.
  # --form-string keeps curl from reading a leading "@" (as in "@channel") or
  # "<" value as a local file (curl error 26); only real files use -F "@path".
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "disable_notification=true" \
    -F "document=@${FILES[0]}" \
    >/dev/null
else
  media_json="$(jq -cn '
    [ $ARGS.positional | to_entries[]
      | { type: "document", media: ("attach://file" + (.key | tostring)) } ]
  ' --args "${FILES[@]}")"

  curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}"
             --form-string "media=${media_json}"
             --form-string "disable_notification=true")
  for i in "${!FILES[@]}"; do
    curl_args+=(-F "file${i}=@${FILES[$i]}")
  done

  curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
fi

echo "Telegram announcement complete."
