#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel — as ONE message: the files as
# an album, the announcement as the album's caption.
#
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
#     .github/telegram-notify.sh <tag> <release-notes.md> <dist-dir>
#
# One sendMediaGroup: the changelog (CHANGELOG-<tag>.md) first so the caption and
# the notes sit together, then the build archives and SHA256SUMS. The caption —
# version, highlights, and a count of what the changelog holds — rides on the
# first item, so the channel gets a single post and a single notification with the
# text and the files together. (An earlier version sent the text as its own
# message ahead of a silent album; the operator wanted them as one message, not
# two, so the announcement is a caption now.)
#
# The changelog is a FILE, not inline text, because a message/caption is capped
# (4096 for a message, 1024 for a caption) and a full changelog is not: v0.2.2's
# was 5.9 KB. So the caption carries the highlights + a per-section count, and the
# whole changelog rides along as the attached file.
#
# Constraints worth naming (all seen in a real channel):
#   * a document album caption lives on ONE item and is limited to 1024 chars,
#     hence the highlights-only caption + the changelog as a file;
#   * there is no show_caption_above_media for documents, so the caption renders
#     with the first bubble — putting the changelog first keeps that coherent;
#   * <blockquote expandable> collapses to THREE LINES, so it is not used;
#   * Telegram has no list markup, hence "•" — a convention here, not a feature.
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
CAPTION_BUDGET=900               # the caption ceiling is 1024; leave room for header + summary

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
    -e 's|(^\|[^*])\*([^*]+)\*([^*]\|$)|\1<i>\2</i>\3|g' \
    -e 's|\*\*([^*]+)\*\*|<b>\1</b>|g' \
    -e 's|`([^`]+)`|<code>\1</code>|g'
}

# chunks splits text into whole-line pieces of at most $1 chars, NUL-separated.
# Nothing is dropped: a message that does not fit one Telegram message becomes
# two. (The alternative — cutting with an ellipsis — is what v0.2.4's announcement
# got: one highlight of eleven, then "…", because the highlights were the caption
# of a document album and a caption is capped at 1024.)
chunks() {
  local budget="$1" out="" line
  while IFS= read -r line; do
    if [ -n "$out" ] && [ $(( ${#out} + ${#line} + 1 )) -gt "$budget" ]; then
      printf '%s\0' "$out"; out=""
    fi
    out+="${line}"$'\n'
  done
  [ -n "$out" ] && printf '%s\0' "$out"
}

# fit keeps whole lines while they fit the budget, marking a cut with an ellipsis.
# Used only for the SHORT caption on the album, never for the highlights.
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
HEADER="$(printf '🚀 <b>wgfleet %s</b>' "$TAG_HTML")"
SUMMARY="$(summary_line)"
SUMMARY_HTML=""
if [ -n "$SUMMARY" ]; then
  SUMMARY_HTML="$(printf '%s — full changelog in <code>%s</code>' \
    "$(printf '%s' "$SUMMARY" | escape_html)" "$(printf '%s' "$NOTES_NAME" | escape_html)")"
fi
HAVE_LEAD=""
[ -n "$(tr -d '[:space:]' <<<"$LEAD_HTML")" ] && HAVE_LEAD=1

# Two shapes, chosen by size. Highlights that fit a caption ride on the album as
# before — one post. Highlights that do not are a text message of their own
# (4096 per message, split by whole lines, nothing cut), and the album follows
# with a short caption: header, counts, and where the highlights are.
ANNOUNCEMENT="$HEADER"
[ -n "$HAVE_LEAD" ] && ANNOUNCEMENT+="$(printf '\n\n%s' "$LEAD_HTML")"
[ -n "$SUMMARY_HTML" ] && ANNOUNCEMENT+="$(printf '\n\n%s' "$SUMMARY_HTML")"
TEXTS=()
if [ "${#ANNOUNCEMENT}" -gt 1024 ] && [ -n "$HAVE_LEAD" ]; then
  while IFS= read -r -d '' part; do TEXTS+=("$part"); done < <(chunks 4000 <<<"$(printf '%s\n\n%s' "$HEADER" "$LEAD_HTML")")
  ANNOUNCEMENT="$HEADER"
  [ -n "$SUMMARY_HTML" ] && ANNOUNCEMENT+="$(printf '\n\n%s' "$SUMMARY_HTML")"
  ANNOUNCEMENT+="$(printf '\n\nHighlights are in the message above.')"
fi

# --- Collect what the album carries -------------------------------------------
# The notes go in as a file of their own, named for the tag so it is still
# identifiable once it is sitting in somebody's downloads.
NOTES_DOC="$(mktemp -d)/${NOTES_NAME}"
cp "$NOTES_FILE" "$NOTES_DOC"

# The notes go first: the caption lives on the first item, so the highlights and
# the full changelog file sit together, then the archives and checksums follow.
FILES=("$NOTES_DOC")
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/SHA256SUMS; do
  [ -f "$f" ] || continue
  if [ "$(wc -c < "$f")" -gt "$MAX_BYTES" ]; then
    echo "skipping $(basename "$f"): over the 50 MB Telegram limit"
    continue
  fi
  FILES+=("$f")
done

# Hard cap the caption at Telegram's 1024. With long highlights already moved to
# their own message this only guards the header + summary; it must never fail.
if [ "${#ANNOUNCEMENT}" -gt 1024 ]; then
  ANNOUNCEMENT="$(printf '%s' "$ANNOUNCEMENT" | fit 1000)…"
fi

caption_json_note() { :; }

if [ -n "$DRY_RUN" ]; then
  for t in "${TEXTS[@]}"; do
    printf '\n----- text message (%d chars) -----\n%s\n' "${#t}" "$t"
  done
  printf '\n----- album: sendMediaGroup, %d file(s), caption on the first -----\n' "${#FILES[@]}"
  printf 'caption (%d chars):\n%s\n\nfiles (first carries the caption):\n' "${#ANNOUNCEMENT}" "$ANNOUNCEMENT"
  for f in "${FILES[@]}"; do printf '  %s\n' "$(basename "$f")"; done
  echo "Telegram announcement complete (dry run)."
  exit 0
fi

for t in "${TEXTS[@]}"; do
  curl -fsS -X POST "$API/sendMessage" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "text=${t}" \
    --form-string "parse_mode=HTML" \
    --form-string "disable_web_page_preview=true" \
    >/dev/null
done
echo "Posting the album: ${#FILES[@]} file(s), ${#TEXTS[@]} highlight message(s) before it"

if [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup requires 2..10 items; a lone file goes via sendDocument, caption
  # and all. --form-string keeps curl from reading a leading "@"/"<" as a file.
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "caption=${ANNOUNCEMENT}" \
    --form-string "parse_mode=HTML" \
    -F "document=@${FILES[0]}" \
    >/dev/null
else
  # Caption + parse_mode ride on the FIRST media item only; it becomes the album's
  # caption. `as $e` keeps the index in scope after the object is built.
  media_json="$(jq -cn --arg cap "$ANNOUNCEMENT" '
    [ $ARGS.positional | to_entries[] as $e
      | { type: "document", media: ("attach://file" + ($e.key | tostring)) }
        + ( if $e.key == 0 then { caption: $cap, parse_mode: "HTML" } else {} end )
    ]
  ' --args "${FILES[@]}")"

  curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}"
             --form-string "media=${media_json}")
  for i in "${!FILES[@]}"; do
    curl_args+=(-F "file${i}=@${FILES[$i]}")
  done

  curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
fi

echo "Telegram announcement complete."
