#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel: one album with the build
# archives and SHA256SUMS, captioned with the version and the URL of the
# release's section of the public changelog on the docs site. The caption sits
# on the LAST file so it renders after the files, not between them, and the URL
# is written out in full because a hidden link is not clickable there.
#
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
#     .github/telegram-notify.sh <tag> <dist-dir> [changelog.md]
#
# The changelog itself is not repeated here: it lives on the site and inside the
# archive as CHANGELOG.md, and a Telegram caption is capped at 1024 characters.
# DOCS_URL overrides the site base (default https://shidoh.github.io/wgfleet-docs).
# TELEGRAM_DRY_RUN=1 prints what would be sent and calls no API.
#
# Requires: curl, jq.
set -euo pipefail

TAG="${1:?usage: telegram-notify.sh <tag> <dist-dir> [changelog.md]}"
DIST_DIR="${2:?missing dist dir}"
CHANGELOG="${3:-docs/changelog.md}"
DRY_RUN="${TELEGRAM_DRY_RUN:-}"
DOCS_URL="${DOCS_URL:-https://shidoh.github.io/wgfleet-docs}"
if [ -z "$DRY_RUN" ]; then
  : "${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN is required}"
  : "${TELEGRAM_CHAT_ID:?TELEGRAM_CHAT_ID is required}"
fi
API="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN:-dry-run}"
MAX_BYTES=$((50 * 1024 * 1024))   # Telegram bot upload ceiling, per file

# anchor_for finds the release's heading in the changelog ("## vX.Y.Z — DATE")
# and turns it into the slug mkdocs generates: lowercase, drop everything but
# letters, digits, spaces and hyphens, collapse runs of spaces/hyphens into one
# hyphen. Empty when the heading is absent (the link then opens the page).
anchor_for() {
  local heading
  heading="$(grep -m1 -E "^## ${TAG//./\\.}( |$)" "$CHANGELOG" 2>/dev/null | sed -E 's/^##[[:space:]]+//')"
  [ -n "$heading" ] || return 0
  printf '%s' "$heading" | tr '[:upper:]' '[:lower:]' \
    | sed -E -e 's/[^a-z0-9 -]//g' -e 's/[[:space:]-]+/-/g' -e 's/^-+//' -e 's/-+$//'
}

PAGE="${DOCS_URL%/}/docs/changelog/"
ANCHOR="$(anchor_for)"
LINK="$PAGE${ANCHOR:+#$ANCHOR}"

# The link is written out in full rather than hidden behind a word: an album
# caption keeps a <a href=…> entity, but the channel view does not make it
# clickable. A bare URL left to Telegram's auto-detection turned out unreliable
# too — it can arrive as plain text. So the caption is plain text and its
# formatting is sent explicitly as caption_entities: bold for the title, and the
# same `url` entity auto-detection would produce, placed on the URL ourselves.
# Offsets and lengths are in UTF-16 code units, as the Bot API counts them (the
# rocket emoji is two).
TITLE="wgfleet $TAG"
CAPTION="$(printf '🚀 %s\n\nWhat changed:\n%s' "$TITLE" "$LINK")"
ENTITIES="$(jq -cn --arg cap "$CAPTION" --arg title "$TITLE" --arg link "$LINK" '
  def u16: explode | map(if . > 65535 then 2 else 1 end) | add // 0;
  [ { type: "bold", offset: ("🚀 " | u16), length: ($title | u16) },
    { type: "url", offset: (($cap | u16) - ($link | u16)), length: ($link | u16) } ]')"

FILES=()
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/SHA256SUMS; do
  [ -f "$f" ] || continue
  if [ "$(wc -c < "$f")" -gt "$MAX_BYTES" ]; then
    echo "skipping $(basename "$f"): over the 50 MB Telegram limit"
    continue
  fi
  FILES+=("$f")
done
[ "${#FILES[@]}" -gt 0 ] || { echo "nothing to send: no archives in $DIST_DIR" >&2; exit 1; }

if [ -n "$DRY_RUN" ]; then
  printf -- '----- album: %d file(s), caption on the LAST -----\nfiles:\n' "${#FILES[@]}"
  for f in "${FILES[@]}"; do printf '  %s\n' "$(basename "$f")"; done
  printf 'caption:\n%s\nentities: %s\n' "$CAPTION" "$ENTITIES"
  echo "Telegram announcement complete (dry run)."
  exit 0
fi

# Wait for the docs site to actually serve this release's section before posting a
# link to it. The release build and this announcement both run on a tag push, but
# the docs deploy (to the gh-pages repo) and GitHub Pages' CDN lag behind by
# minutes, so an immediate post can link to a page that still shows the previous
# content. Poll for the section's anchor for up to ~10 minutes, then post anyway
# rather than hold the release indefinitely. Skipped when the heading is absent
# (the link just opens the page) or when WAIT_FOR_DOCS=0.
if [ -n "$ANCHOR" ] && [ "${WAIT_FOR_DOCS:-1}" != "0" ]; then
  live=""
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 10 "$PAGE" 2>/dev/null | grep -q "id=\"$ANCHOR\""; then
      live=1
      echo "docs section #$ANCHOR is live"
      break
    fi
    sleep 10
  done
  [ -n "$live" ] || echo "WARNING: docs section #$ANCHOR not live after ~10 min; posting anyway"
fi

echo "Posting the album: ${#FILES[@]} file(s), changelog link $LINK"
if [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup needs 2..10 items; a lone file goes via sendDocument.
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "caption=${CAPTION}" \
    --form-string "caption_entities=${ENTITIES}" \
    -F "document=@${FILES[0]}" \
    >/dev/null
else
  # A document album renders as one bubble per file, and the caption is drawn
  # with the file that carries it. On the FIRST file it lands between that file
  # and the rest ("file, text, more files"); on the LAST it follows every file.
  last=$(( ${#FILES[@]} - 1 ))
  media_json="$(jq -cn --arg cap "$CAPTION" --argjson ents "$ENTITIES" --argjson last "$last" '
    [ $ARGS.positional | to_entries[] as $e
      | { type: "document", media: ("attach://file" + ($e.key | tostring)) }
        + ( if $e.key == $last then { caption: $cap, caption_entities: $ents } else {} end )
    ]
  ' --args "${FILES[@]}")"
  curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}" --form-string "media=${media_json}")
  for i in "${!FILES[@]}"; do
    curl_args+=(-F "file${i}=@${FILES[$i]}")
  done
  curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
fi
echo "Telegram announcement complete."
