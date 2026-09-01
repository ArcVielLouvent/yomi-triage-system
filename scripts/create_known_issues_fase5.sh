#!/usr/bin/env bash
#
# create_known_issues_fase5.sh — GitHub issue housekeeping for Fase 5.
#
# Fase 5 covers: README split, and all FOUR pre-Fase-6 gate items --
# #12 (stamp.py coverage), #13 (checkpoint mismatch wording), #14
# (remediator.py critical-PID protection), #15 (remediator.py path
# containment), and #21 (router.py OS-level failure feedback) -- all
# FIXED. It also surfaced one new open finding, #24 (cleanup_corrupt_backups
# retain_last), while writing the coverage tests for #12.
#
# This script does two things:
#   1. Creates ONE new GitHub issue for #24.
#   2. Closes the five GitHub issues that correspond to known_issues.md
#      #12, #13, #14, #15, #21 (GitHub issue numbers are known_issues.md
#      number + 2, per the existing offset in this repo: #14, #15, #16,
#      #17, #23), each with a closing comment pointing at the fix.
#
# Run this ONCE, after create_known_issues_fase3.sh has already been run.
#
# Usage:
#   chmod +x create_known_issues_fase5.sh
#   ./create_known_issues_fase5.sh

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Creating any missing labels (safe to ignore 'already exists' errors)..."
gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "coverage-gap" --color "c5def5" --description "Untested code path" 2>/dev/null || true
gh label create "lapisan-0" --color "5319e7" --description "Foundation layer (stamp, os_bridge, yomi_data)" 2>/dev/null || true

echo ""
echo "Creating Fase 5 issue (#24 in known_issues.md)..."

gh issue create \
  --title "design: stamp.py cleanup_corrupt_backups retain_last counts files, not incidents" \
  --label "design-smell,coverage-gap,lapisan-0" \
  --body "Each call to _backup_corrupted_ledger writes two files (the .jsonl copy + a .metadata.json sidecar written right after it). cleanup_corrupt_backups lists every file starting with the backup prefix, sorts that FLAT list by mtime, and retains the first retain_last entries -- treating the .jsonl and its .metadata.json as two independent files rather than one paired incident. retain_last=1 therefore keeps the single most-recently-modified FILE (always the .metadata.json, written last), not the most recent full incident -- you can end up with a lone .metadata.json and no matching .jsonl beside it.

Not data loss of the live ledger itself (only affects retention of corruption-recovery backups), not attacker-exploitable, but the retention guarantee implied by the parameter name doesn't hold.

Captured as: tests/unit/test_stamp_coverage.py::test_cleanup_corrupt_backups_retain_last_counts_files_not_incidents

Status: OPEN. Found while writing coverage tests for known_issues.md #12 (this repo's stamp.py coverage gap). Fix would be to group files by shared incident prefix before sorting/retaining." \
  || echo "(issue may already exist, skipping)"

echo ""
echo "Closing issues fixed in Fase 5..."
echo "NOTE: adjust these numbers if your GitHub issue numbering differs from the +2 offset used below."

for gh_num_and_msg in \
  "14:Fixed in Fase 5 -- coverage raised from 54%% to 89%% via tests/unit/test_stamp_coverage.py (45 new tests). See docs/known_issues.md #12 for the full breakdown." \
  "15:Fixed in Fase 5 -- log message reworded to distinguish routine checkpoint catch-up from genuine tamper detection. See docs/known_issues.md #13." \
  "16:Fixed in Fase 5 -- _validate_payload now rejects any pid <= 100 before proceeding, mirroring harness.py's hardblock. Does not add harness.py's psutil-based NoSuchProcess fail-safe, since remediator.py must keep working for self-deleted (fileless) malware PIDs. See docs/known_issues.md #14." \
  "17:Fixed in Fase 5 -- critical-path check now uses real pathlib containment (resolved path in critical dir's parents) instead of exact string match, without repeating the mirage.py .startswith() bug (#16/#18). See docs/known_issues.md #15." \
  "23:Fixed in Fase 5 -- execute_autonomous_triage now has an explicit fallback branch that feeds [SYSTEM FEEDBACK] to the LLM for any OS-level failure status. See docs/known_issues.md #21."
do
  gh_num="${gh_num_and_msg%%:*}"
  msg="${gh_num_and_msg#*:}"
  gh issue close "$gh_num" --comment "$msg" 2>/dev/null \
    && echo "Closed #$gh_num" \
    || echo "Could not close #$gh_num (already closed, or number doesn't match -- check manually)."
done

echo ""
echo "Done. Verify with: gh issue list --state all --search 'stamp.py OR router.py OR checkpoint'"
