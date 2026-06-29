#!/usr/bin/env bash
# Generate a categorized release changelog from Conventional Commits.
#
#   .github/release-notes.sh <current-ref> [<previous-ref>]
#
# Groups commits between <previous-ref> and <current-ref> by their conventional
# type (feat/fix/perf/…) into titled sections. If <previous-ref> is omitted, the
# nearest tag before <current-ref> is used (and the full history for a first
# release). Prints Markdown to stdout, suitable for `gh release create --notes-file`.

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

# sha <TAB> subject, one per line, oldest→newest reversed to newest→oldest default.
git log --no-merges --reverse --pretty=format:'%h%x09%s' "$RANGE" | awk -v repo="$REPO_URL" '
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
'

# Footer: a compare link when there is a previous tag to compare against.
# RELEASE_TAG overrides the link target name (useful when CUR is HEAD on a manual
# run before the tag ref exists).
if [ -n "$PREV" ]; then
  printf '**Full Changelog**: %s/compare/%s...%s\n' "$REPO_URL" "$PREV" "${RELEASE_TAG:-$CUR}"
fi
