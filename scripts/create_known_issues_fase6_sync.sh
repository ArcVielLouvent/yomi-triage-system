#!/usr/bin/env bash
#
# create_known_issues_fase6_sync.sh — final GitHub issue reconciliation
# before Fase 6 Tahap 2 (Release). Run this ONCE, after
# create_known_issues_fase5.sh and create_known_issues_fase6.sh have
# already been run (safe to run even if you're not 100% sure -- every
# operation below is idempotent: closing an already-closed issue or
# creating a duplicate-titled issue just no-ops/warns, doesn't corrupt
# anything).
#
# This script exists because a full audit (cross-checking
# docs/known_issues.md against the actual GitHub issue list by TITLE,
# not by assumed number -- GitHub assigns issue numbers sequentially in
# real time, they do NOT match this repo's local known_issues.md
# numbering past #23) found two categories of drift:
#
#   1. GH#16 and GH#17 (remediator.py PID protection / path containment)
#      are still OPEN on GitHub even though both were fixed in Fase 5 --
#      an EARLIER version of create_known_issues_fase5.sh (before the
#      remediator fix was folded into that session) was run before the
#      closing commands for #16/#17 were added to the script.
#   2. Four Fase-6 findings (known_issues.md #27, #28, #29, #30) never
#      had a GitHub issue created for them at all.
#
# Usage:
#   chmod +x create_known_issues_fase6_sync.sh
#   ./create_known_issues_fase6_sync.sh

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "lapisan-0" --color "5319e7" --description "Foundation layer (stamp, os_bridge, yomi_data)" 2>/dev/null || true
gh label create "lapisan-1" --color "1d76db" --description "Layer 1 modules (yomi_engine, yomi_mcp Batch 2/3)" 2>/dev/null || true
gh label create "lapisan-2" --color "0e8a16" --description "Layer 2 modules (router, mcp_server, hunter, swarm, dossier, mind_reader, shadow_net, dashboard)" 2>/dev/null || true

echo ""
echo "=== Part 1: closing #16 and #17 (bookkeeping drift -- both actually fixed in Fase 5) ==="

gh issue close 16 --comment "Confirmed still fixed as of Fase 6 (this close was missed by an earlier run of create_known_issues_fase5.sh, before the remediator fix landed in that script). _validate_payload rejects pid<=100, mirroring harness.py's hardblock. See docs/known_issues.md #14." \
  2>/dev/null || echo "(could not close #16 -- check manually)"

gh issue close 17 --comment "Confirmed still fixed as of Fase 6 (this close was missed by an earlier run of create_known_issues_fase5.sh, before the remediator fix landed in that script). Critical-path check now uses real pathlib containment, not exact string match, without repeating the mirage.py .startswith() bug (#18). See docs/known_issues.md #15." \
  2>/dev/null || echo "(could not close #17 -- check manually)"

echo ""
echo "=== Part 2: creating the 4 missing issues (#27-#30 in known_issues.md, never tracked on GitHub) ==="

echo "Creating issue for known_issues.md #27 (OPEN)..."
gh issue create \
  --title "design: pip install . packages yomi_data/ like any other module -- evidence store location is implicit" \
  --label "design-smell,lapisan-0" \
  --body "pip install . packages yomi_data/ like any other Python module (it has an __init__.py, so setuptools includes it same as yomi_core/yomi_engine). A pip-installed daemon's evidence ledger, notary checkpoint, CVE store, and HMAC key end up inside venv/lib/python3.*/site-packages/yomi_data/, not anywhere an operator would intuitively look. Not broken functionality -- ImmutableStamp/OmniLibrary's __file__-relative path resolution finds it fine -- but for a DFIR tool, the evidence store's location needs to be predictable and documented.

Status: OPEN. Worked around for now by scripts/install_yomi_linux.sh printing the exact resolved path at the end of a successful run. A real fix would be a YOMI_DATA_DIR env var override respected by every module that currently does __file__-relative path resolution, defaulting to a standard Linux FHS location like /var/lib/yomi-triage for pip-installed daemons. Cross-cutting change, flagged for Fase 6 Tahap 2.

See docs/known_issues.md #27." \
  || echo "(issue may already exist, skipping)"

echo "Creating + closing issue for known_issues.md #28 (MITIGATED)..."
issue_url=$(gh issue create \
  --title "bug: dev/test audit_hmac.key silently copied into production pip install" \
  --label "design-smell,lapisan-0" \
  --body "Consequence of the yomi_data/ packaging behavior in #27 above: if a dev/test yomi_data/audit_hmac.key already exists in the checkout when pip install . runs, it gets copied into the 'production' install too -- meaning a non-production key could end up signing the real evidence ledger, undetected.

Status: MITIGATED, not fully fixed. scripts/install_yomi_linux.sh now detects a pre-existing yomi_data/audit_hmac.key before installing and requires explicit interactive confirmation ('Continue anyway and reuse this key? [y/N]') before proceeding, rather than silently continuing or silently deleting a key an operator might have a legitimate reason to keep. The root cause (setup.py packaging data files it shouldn't -- same as #27) is not addressed by this mitigation alone.

See docs/known_issues.md #28.")
issue_num=$(basename "$issue_url")
gh issue close "$issue_num" --comment "Mitigated in the same session that introduced scripts/install_yomi_linux.sh (Fase 6 Tahap 1) -- see docs/known_issues.md #28 for why this is a mitigation, not a full fix."

echo "Creating + closing issue for known_issues.md #29 (FIXED)..."
issue_url=$(gh issue create \
  --title "bug: sandbox.py bypassed module_registry when re-invoking MindReader/Mirage post-detonation" \
  --label "design-smell,lapisan-1" \
  --body "sandbox.py's _monitor_awakened_threat (its own post-detonation monitoring thread) called MindReaderDecompiler() and MirageProtocol() unconditionally, completely bypassing module_registry -- the same bug class as the Ghost Protocol / eBPF Sensor issue, but at a separate call site from GuardianOrchestrator's own dispatch (which did respect the registry). So disabling MIND_READER or MIRAGE via env var had no effect on this specific post-detonation re-analysis pass. Found while capturing real demo output for docs/demo_mode.md, not from code review.

Fixed same session: both calls now check module_registry.resolve_active_modules() first, matching every other dispatch site. New test: tests/unit/test_sandbox.py::test_monitor_awakened_threat_respects_disabled_mirage_and_mind_reader.

See docs/known_issues.md #29.")
issue_num=$(basename "$issue_url")
gh issue close "$issue_num" --comment "Fixed in the same session it was found (Fase 6 Tahap 1, documentation pass). See docs/known_issues.md #29."

echo "Creating issue for known_issues.md #30 (OPEN)..."
gh issue create \
  --title "design: asymmetric Mirage decoy lifecycle when SANDBOX is enabled (2x deployed, 1x torn down)" \
  --label "design-smell,lapisan-1" \
  --body "A single incident against one PID can end up with TWO independent Mirage decoys deployed for it when SANDBOX is enabled: one from GuardianOrchestrator.handle_post_containment (pre-detonation dispatch), one from sandbox.py's own _monitor_awakened_threat (post-detonation re-analysis, see the now-fixed #29). sandbox.py tears down its OWN decoy immediately after the observation window closes -- but guardian.py never calls teardown_hallucination() for the one it deployed, leaving it to periodic_maintenance()'s sweep_orphaned_hallucinations() sweep instead.

Not a security hole (the decoy is inert once the underlying process is gone) and not silent data loss, but the ledger will show two HALLUCINATION_DEPLOYED entries and only one HALLUCINATION_TEARDOWN for the same PID during a SANDBOX-enabled run -- worth knowing so it doesn't read as a ledger inconsistency. Documented in docs/demo_mode.md's walkthrough section.

Status: OPEN. A real fix would have GuardianOrchestrator track and tear down decoys it deployed itself, symmetric with sandbox.py's own handling.

See docs/known_issues.md #30." \
  || echo "(issue may already exist, skipping)"

echo ""
echo "Done. Verify with: gh issue list --state all --search 'yomi_data OR audit_hmac OR sandbox OR mirage decoy' "
echo "Expected end state: known_issues.md #1-26 all have a matching (open or closed) GitHub issue,"
echo "#27-30 now do too. known_issues.md's own FIXED/OPEN/MITIGATED status is the source of truth --"
echo "this script only brings GitHub's open/closed STATE in line with it, it doesn't change any code."
