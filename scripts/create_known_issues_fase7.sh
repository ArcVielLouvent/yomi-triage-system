#!/usr/bin/env bash
#
# create_known_issues_fase7.sh — GitHub issue housekeeping for Fase 7
# Tahap 1 (cross-artifact correlation layer).
#
# Fase 7 Tahap 1 covers: registry hardening in hunter.py, the new
# correlator.py module (CrossArtifactCorrelator + CorrelatedCaseFile),
# and wiring it into guardian.py/sentinel.py/dossier.py. It surfaced one
# new finding, #33 (MitreMapper's signature set isn't validated against
# what correlator.py assumes exists) -- fixed for the two specific
# instances caught during development, but open as a broader design gap.
#
# Unlike earlier create_known_issues_fase*.sh scripts, this one does NOT
# attempt to close any existing GitHub issue by number. The "known_issues.md
# number + fixed offset = GitHub issue number" assumption those scripts
# relied on already broke down once (see the Fase 6 duplicate-issue
# cleanup -- scripts/close_duplicate_issues.sh) and shouldn't be
# re-introduced here for a brand-new finding that has no corresponding
# prior GitHub issue at all.
#
# Run this ONCE.
#
# Usage:
#   chmod +x create_known_issues_fase7.sh
#   ./create_known_issues_fase7.sh

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Creating any missing labels (safe to ignore 'already exists' errors)..."
gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "coverage-gap" --color "c5def5" --description "Untested code path" 2>/dev/null || true
gh label create "lapisan-2" --color "0e8a16" --description "Layer 2 modules (router, mcp_server, hunter, swarm, dossier, mind_reader, shadow_net, dashboard)" 2>/dev/null || true

echo ""
echo "Creating Fase 7 issue (#33 in known_issues.md)..."

gh issue create \
  --title "design: MitreMapper's signature set isn't validated against what correlator.py's corroboration checks assume exists" \
  --label "design-smell,coverage-gap,lapisan-2" \
  --body "While building correlator.py's cross-source corroboration logic (Fase 7), a _check_credential_access_corroboration function was written assuming a 'credential access' MITRE tactic existed in mitre_mapper.py's signature dictionary. It doesn't -- the module only has 5 fixed IoE signatures (PE_INJECT/T1055, YR_RANSOMWARE/T1486, PROC_BAD_DTB/T1014, PEB_MASQ/T1036.004, C2_BEACON/T1071), none with 'credential' in their tactical_desc. The function would have been silent dead code: its guard clause would always fire and its actual corroboration logic would never run. Nothing (no import error, no test failure, no lint warning) flags this kind of mistake -- it was only caught by manually re-reading mitre_mapper.py's signature table before committing.

A related, real (not hypothetical) bug caught the same way: the first draft of _check_c2_corroboration's network-finding match (a bare 'external|c2' substring) false-positived against swarm.py's own CLEAN finding wording ('...without obvious external C2 anomalies'), which would have marked an uncorroborated MitreMapper keyword hit as corroborated -- the exact failure mode the correlator exists to prevent.

Status: FIXED for both specific instances found (dead credential-access check replaced with a real T1055/Process-Injection check; C2 corroboration regex narrowed + regression-tested in tests/unit/test_correlator.py). OPEN as a broader design gap: nothing links the MITRE tactic IDs a correlation check assumes exist to the MITRE tactic IDs MitreMapper actually defines, at test-collection or CI time. A future correlator corroboration check for a tactic ID that doesn't exist in mitre_mapper.py's signature table would silently no-op again. A real fix would have MitreMapper expose its known tactic ID set (e.g. a KNOWN_MITRE_IDS frozenset) that correlator.py's own test suite asserts every corroboration check's referenced mitre_id against, turning this class of mistake into a test failure instead of a silent no-op.

See docs/known_issues.md #33." \
  || echo "(issue may already exist, skipping)"

echo ""
echo "Done. Verify with: gh issue list --search 'MitreMapper signature'"
