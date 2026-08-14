#!/usr/bin/env bash
#
# create_known_issues_batch2_3.sh — follow-up to create_known_issues.sh.
#
# The original script (scripts/create_known_issues.sh) was written before
# Fase 2's Batch 2 and Batch 3 work happened, so it only covers
# docs/known_issues.md findings #1-13 (Fase 0-1). This script covers the
# 7 findings added afterward (#14-20): 3 open design gaps from Batch 2
# (remediator.py, mirage.py) and 4 bugs found-and-fixed in Batch 3
# (library.py, sift_toolkit.py).
#
# Run this ONCE, after create_known_issues.sh has already been run.
# Running create_known_issues.sh again would duplicate its 13 issues --
# this script is deliberately separate so that doesn't happen.
#
# Usage:
#   chmod +x create_known_issues_batch2_3.sh
#   ./create_known_issues_batch2_3.sh

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Creating any missing labels (safe to ignore 'already exists' errors)..."
gh label create "bug:crash" --color "d73a4a" --description "Causes a crash or exception" 2>/dev/null || true
gh label create "bug:silent-failure" --color "e99695" --description "Fails silently / wrong behavior without error" 2>/dev/null || true
gh label create "bug:race-condition" --color "b60205" --description "Timing-dependent bug, intermittent by nature" 2>/dev/null || true
gh label create "docs" --color "0075ca" --description "Documentation inconsistency" 2>/dev/null || true
gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "coverage-gap" --color "c5def5" --description "Untested code path" 2>/dev/null || true
gh label create "lapisan-0" --color "5319e7" --description "Foundation layer (stamp, os_bridge, yomi_data)" 2>/dev/null || true
gh label create "lapisan-1" --color "1d76db" --description "Layer 1 modules (yomi_engine, yomi_mcp Batch 2/3)" 2>/dev/null || true

echo ""
echo "Creating Batch 2/3 issues..."

# --- Open issues (Batch 2 design gaps, not fixed) --------------------------

gh issue create \
  --title "design: remediator.py has no critical-PID protection (unlike harness.py)" \
  --label "design-smell,lapisan-1" \
  --body "_validate_payload has no equivalent of harness.py's PID<=100 hardblock. A payload targeting PID 1 (init) generates a rollback script successfully. The script isn't auto-executed, but nothing stops one from being generated.

Captured as a regression test: tests/unit/test_remediator.py::test_KNOWN_GAP_no_critical_pid_protection

Status: OPEN."

gh issue create \
  --title "design: remediator.py critical-system-path check is exact-match, not prefix" \
  --label "design-smell,lapisan-1" \
  --body "/bin/bash and /etc/passwd pass validation despite being core system files, because the check only compares against the bare directory strings (/bin, /etc) themselves, not paths within them. Practical impact is limited since the generated script's kill commands only ever reference pid, never file_path -- but the check's own comment claims broader protection than it actually provides.

Captured as: tests/unit/test_remediator.py::test_KNOWN_GAP_critical_path_check_is_exact_match_not_prefix

Status: OPEN."

gh issue create \
  --title "design: mirage.py teardown boundary check uses string startswith(), not path containment" \
  --label "design-smell,lapisan-1" \
  --body "teardown_hallucination's boundary check uses .startswith() on a plain string, vulnerable in principle to sibling-directory prefix matching (e.g. a folder named mirage_env_EVIL also 'starts with' mirage_env). NOT exploitable through the current public API (target_path is always built from an int-cast pid + a 2-value-constrained prefix), but flagged as a pattern to avoid if this code is ever refactored to accept more flexible input.

Captured as: tests/unit/test_mirage.py::test_teardown_boundary_check_documented_prefix_weakness

Status: OPEN (defense-in-depth hardening, not urgent)."

# --- Fixed issues (Batch 3 bugs, found AND fixed) --------------------------

ISSUE_URL=$(gh issue create \
  --title "bug: lzma.LZMAFile(fileobj=...) uses a non-existent keyword arg -- NVD CVE sync has never worked" \
  --label "bug:silent-failure,lapisan-1" \
  --body "Python's lzma.LZMAFile API names this parameter 'filename' (which also accepts file-like objects) -- 'fileobj' doesn't exist. Present in 2 call sites (_fetch_nvd_recent, seed_full_nvd_archive). This meant NVD CVE database sync has silently failed with TypeError, caught by a broad except-Exception, on every single invocation since project inception -- the core 'auto-updating threat intelligence' feature has never actually worked.

Fixed on foundation/layer1-modules: both occurrences now pass the BytesIO object positionally instead of via fileobj=.")
gh issue close --comment "Fixed on foundation/layer1-modules" "$ISSUE_URL"

ISSUE_URL=$(gh issue create \
  --title "bug: library.py analyze_artifact() checked substring containment backwards" \
  --label "bug:silent-failure,lapisan-1" \
  --body "The full (often long, decorated) artifact_name was checked as a substring INSIDE the short 'cve_id + description' text, which only succeeds when artifact_name IS almost exactly the bare CVE ID. Any realistic filename (e.g. 'suspicious_cve-2026-0006_dropper.exe') never matched.

Fixed on foundation/layer1-modules: redesigned with (a) a full CVE-ID pattern extracted from artifact_name gets a direct O(1) dict lookup as a fast/precise path, (b) context_hints keep the original correct direction, (c) extracted CVE ID checked for containment WITHIN artifact_name/hints as fallback.")
gh issue close --comment "Fixed on foundation/layer1-modules" "$ISSUE_URL"

ISSUE_URL=$(gh issue create \
  --title "bug: sift_toolkit.py _run_subprocess's 'timed out' error message was effectively dead code" \
  --label "bug:silent-failure,lapisan-1" \
  --body "Inferred timeout from process.returncode is None, but _stream_process_output already reaps the killed process via process.wait() before returning -- returncode is essentially never still None by the time the caller checks it. Callers got a generic 'tool returned -9' message instead of 'execution timed out after Xs'.

Fixed on foundation/layer1-modules: _stream_process_output now returns an explicit timed_out flag instead of inferring it from returncode.")
gh issue close --comment "Fixed on foundation/layer1-modules" "$ISSUE_URL"

ISSUE_URL=$(gh issue create \
  --title "bug: race condition in sift_toolkit.py _stream_process_output -- fast commands could lose output" \
  --label "bug:race-condition,lapisan-1" \
  --body "process.poll() is not None was checked FIRST every loop iteration, breaking immediately if the process had already exited -- for fast commands (e.g. echo), the child could finish before the loop ever attempted a single read, discarding output still sitting unread in the OS pipe buffer. Confirmed via 5x repeated local test runs: intermittent, different tests failed each run (classic race-condition signature).

Fixed on foundation/layer1-modules: the loop no longer uses poll() as an exit signal -- pipes are tracked in a set and only dropped on an actual EOF (empty read). Verified stable across 5 consecutive full-suite runs post-fix.")
gh issue close --comment "Fixed on foundation/layer1-modules" "$ISSUE_URL"

echo ""
echo "Done. Run 'gh issue list --state all' to review -- should now show 20 total."
