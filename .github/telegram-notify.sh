#!/usr/bin/env bash
# Announce a wgfleet release in a Telegram channel: one album with the build
# archives and SHA256SUMS, captioned with the version and a link to the
# release's section of the public changelog on the docs site.
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

escape_html() { sed -E -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

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

CAPTION="$(printf '🚀 <b>wgfleet %s</b>\n\nWhat changed: <a href="%s">changelog</a>\nThe same text ships inside the archive as CHANGELOG.md.' \
  "$(printf '%s' "$TAG" | escape_html)" "$(printf '%s' "$LINK" | escape_html)")"

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
  printf -- '----- album: %d file(s), caption on the first -----\n%s\n\nfiles:\n' "${#FILES[@]}" "$CAPTION"
  for f in "${FILES[@]}"; do printf '  %s\n' "$(basename "$f")"; done
  echo "Telegram announcement complete (dry run)."
  exit 0
fi

echo "Posting the album: ${#FILES[@]} file(s), changelog link $LINK"
if [ "${#FILES[@]}" -eq 1 ]; then
  # sendMediaGroup needs 2..10 items; a lone file goes via sendDocument.
  curl -fsS -X POST "$API/sendDocument" \
    --form-string "chat_id=${TELEGRAM_CHAT_ID}" \
    --form-string "caption=${CAPTION}" \
    --form-string "parse_mode=HTML" \
    -F "document=@${FILES[0]}" \
    >/dev/null
else
  # The caption rides on the first item and becomes the album's caption.
  media_json="$(jq -cn --arg cap "$CAPTION" '
    [ $ARGS.positional | to_entries[] as $e
      | { type: "document", media: ("attach://file" + ($e.key | tostring)) }
        + ( if $e.key == 0 then { caption: $cap, parse_mode: "HTML" } else {} end )
    ]
  ' --args "${FILES[@]}")"
  curl_args=(--form-string "chat_id=${TELEGRAM_CHAT_ID}" --form-string "media=${media_json}")
  for i in "${!FILES[@]}"; do
    curl_args+=(-F "file${i}=@${FILES[$i]}")
  done
  curl -fsS -X POST "$API/sendMediaGroup" "${curl_args[@]}" >/dev/null
fi
echo "Telegram announcement complete."
