#!/usr/bin/env bash
# Generate a categorized release changelog from Conventional Commits.
#
#   .github/release-notes.sh <current-ref> [<previous-ref>]
#
# Groups commits between <previous-ref> and <current-ref> by their conventional
# type (feat/fix/perf/…) into titled sections. If <previous-ref> is omitted, the
# nearest tag before <current-ref> is used (and the full history for a first
# release). Prints Markdown to stdout, suitable for `gh release create --notes-file`.
#
# Above the generated list it prints a "Highlights" section, taken verbatim from
# the message of the ANNOTATED tag being released:
#
#   git tag -a v0.2.2 -m '- **Client UDP reaches the client again.** …'
#   git tag -a v0.2.2 -F /tmp/highlights.md      # or from a file
#
# Which changes deserve attention is an editorial call the commit log cannot
# make, so it is written by hand — but at the moment of release, and nowhere in
# the working tree. A lightweight tag carries no message (%(contents) would
# hand back the commit subject instead), so it simply gets no highlights, and
# says so on stderr. Preview before pushing: create the tag locally, then run
# this script with it.

set -euo pipefail

REPO_URL="https://github.com/shidoh/wgfleet"

CUR="${1:?usage: release-notes.sh <current-ref> [previous-ref]}"
PREV="${2:-}"

if [ -z "$PREV" ]; then
  PREV="$(git describe --tags --abbrev=0 "${CUR}^" 2>/dev/null || true)"
fi

if [ -n "$PREV" ]; then
  RANGE="${PREV}..${CUR}"
else
  RANGE="$CUR"   # first release: everything reachable from CUR
fi

# highlights_for: the message of an annotated tag, if that is what this tag is.
# Signed tags carry the signature inside %(contents); drop it.
highlights_for() {
  local tag="$1"
  git rev-parse -q --verify "refs/tags/${tag}" >/dev/null || return 0
  [ "$(git cat-file -t "refs/tags/${tag}" 2>/dev/null)" = "tag" ] || return 0
  git tag -l --format='%(contents)' "$tag" \
    | awk '/^-----BEGIN [A-Z ]*SIGNATURE-----$/ { exit } { print }'
}

# The tag being released. RELEASE_TAG is set by the workflow, which runs this
# before the tag ref exists on a manual dispatch; then there is nothing to read.
HIGHLIGHTS="$(highlights_for "${RELEASE_TAG:-$CUR}" | sed -e '/./,$!d')"
HIGHLIGHTS="$(printf '%s' "$HIGHLIGHTS" | sed -e :a -e '/^\n*$/{$d;N;};/\n$/ba')"

# The public changelog on the docs site, linked to this release's section when
# docs/changelog.md has one (the anchor mirrors mkdocs' slug of "## vX — DATE").
DOCS_URL="${DOCS_URL:-https://shidoh.github.io/wgfleet-docs}"
changelog_link() {
  local tag="$1" heading anchor
  heading="$(grep -m1 -E "^## ${tag//./\\.}( |$)" docs/changelog.md 2>/dev/null | sed -E 's/^##[[:space:]]+//')"
  anchor="$(printf '%s' "$heading" | tr '[:upper:]' '[:lower:]' \
    | sed -E -e 's/[^a-z0-9 -]//g' -e 's/[[:space:]-]+/-/g' -e 's/^-+//' -e 's/-+$//')"
  printf '%s/docs/changelog/%s' "${DOCS_URL%/}" "${anchor:+#$anchor}"
}
printf 'Changelog: %s\n\n' "$(changelog_link "${RELEASE_TAG:-$CUR}")"

if printf '%s' "$HIGHLIGHTS" | grep -q '[^[:space:]]'; then
  printf '## Highlights\n\n%s\n\n' "$HIGHLIGHTS"
else
  echo "release-notes: no annotated-tag message for ${RELEASE_TAG:-$CUR}, no highlights section" >&2
fi

# sha <TAB> subject, one per line, oldest→newest reversed to newest→oldest default.
BODY="$(git log --no-merges --reverse --pretty=format:'%h%x09%s' "$RANGE" | awk -v repo="$REPO_URL" '
function flush(key, title,   n, i) {
  n = idx[key]
  if (n == 0) return
  printf "### %s\n\n", title
  for (i = 1; i <= n; i++) printf "%s\n", bucket[key, i]
  printf "\n"
}
{
  sha = $1
  # subject is everything after the first tab
  subj = $0; sub(/^[^\t]*\t/, "", subj)

  type = "other"; scope = ""; breaking = 0; desc = subj
  if (match(subj, /^[a-z]+(\([^)]*\))?!?:[ ]*/)) {
    head = substr(subj, 1, RLENGTH)
    desc = substr(subj, RLENGTH + 1)
    if (head ~ /!:/) breaking = 1
    # type = leading lowercase letters
    match(head, /^[a-z]+/); type = substr(head, 1, RLENGTH)
    # scope = inside (...)
    if (match(head, /\([^)]*\)/)) scope = substr(head, RSTART + 1, RLENGTH - 2)
  }

  # render one bullet
  if (scope != "") line = sprintf("- **%s:** %s (`%s`)", scope, desc, sha)
  else             line = sprintf("- %s (`%s`)", desc, sha)

  key = breaking ? "breaking" : type
  # fold unknown types into "other"
  if (key != "breaking" && key !~ /^(feat|fix|perf|refactor|docs|test|build|ci|chore)$/) key = "other"

  idx[key]++
  bucket[key, idx[key]] = line
}
END {
  flush("breaking", "Breaking Changes")
  flush("feat",     "Features")
  flush("fix",      "Bug Fixes")
  flush("perf",     "Performance")
  flush("refactor", "Refactoring")
  flush("docs",     "Documentation")
  flush("build",    "Build System")
  flush("other",    "Other Changes")
  # test, ci, and chore commits are intentionally excluded from the changelog
  # (still recognized as their type above, so they do not leak into "Other").
}
')"

# Fallback: if every commit in the range was filtered out (e.g. a release with
# only chore/ci/test commits) or there were no commits at all, emit a placeholder
# line instead of an empty body.
printf '## Changelog\n\n'
if printf '%s' "$BODY" | grep -q '[^[:space:]]'; then
  printf '%s\n' "$BODY"
else
  printf '_Maintenance release — no user-facing changes._\n'
fi

# Footer: a compare link when there is a previous tag to compare against.
# RELEASE_TAG overrides the link target name (useful when CUR is HEAD on a manual
# run before the tag ref exists).
if [ -n "$PREV" ]; then
  printf '\n**Full Changelog**: %s/compare/%s...%s\n' "$REPO_URL" "$PREV" "${RELEASE_TAG:-$CUR}"
fi
