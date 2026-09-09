#!/usr/bin/env bash
#
# close_duplicate_issues.sh — auto-detect and close GitHub issues that
# share an identical title with an earlier (lower-numbered) issue.
#
# Why this exists: an earlier, non-idempotent run of one of the
# create_known_issues_fase*.sh scripts created duplicate issues (known
# instance as of Fase 6: #39, #40, #41, #43, #46 duplicate earlier
# issues with the same title). Rather than hardcode that specific
# mapping (fragile -- breaks the moment GitHub's numbering doesn't
# match what was true when this script was written), this script
# re-derives the mapping every time it runs, straight from `gh issue
# list`: for every title that appears more than once among OPEN
# issues, the lowest-numbered issue is kept open as the original, and
# every higher-numbered issue with that exact title gets closed with a
# "duplicate of #<original>" comment.
#
# Safe to re-run: an issue that's already closed is skipped (gh issue
# list only pulls --state open by default here), so running this
# twice in a row is a no-op the second time.
#
# Usage:
#   chmod +x close_duplicate_issues.sh
#   ./close_duplicate_issues.sh            # do it for real
#   ./close_duplicate_issues.sh --dry-run  # only print what it would do

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "jq not found. Install it (apt-get install -y jq) -- needed to group issues by title."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Fetching open issues..."
issues_json=$(gh issue list --state open --limit 500 --json number,title)

# Group by title, sort each group by number ascending, keep index 0 as
# "original", emit the rest as (number, title, original_number) triples.
duplicates=$(echo "$issues_json" | jq -r '
  group_by(.title)
  | map(select(length > 1))
  | map(sort_by(.number))
  | map(. as $group | $group[1:][] | {number: .number, title: .title, original: $group[0].number})
  | .[]
  | [.number, .original, .title] | @tsv
')

if [[ -z "$duplicates" ]]; then
    echo "No duplicate-titled open issues found. Nothing to do."
    exit 0
fi

echo ""
echo "Found duplicates (dup_number, original_number, title):"
echo "$duplicates" | while IFS=$'\t' read -r num orig title; do
    echo "  #$num  -> duplicate of #$orig  ($title)"
done

echo ""
if $DRY_RUN; then
    echo "--dry-run: not closing anything. Re-run without --dry-run to apply."
    exit 0
fi

echo "$duplicates" | while IFS=$'\t' read -r num orig title; do
    echo "Closing #$num as duplicate of #$orig..."
    gh issue close "$num" --comment "duplicate of #$orig" \
        || echo "  (could not close #$num -- check manually)"
done

echo ""
echo "Done. Verify with: gh issue list --state all --search '$(echo "$duplicates" | head -1 | cut -f3)'"
