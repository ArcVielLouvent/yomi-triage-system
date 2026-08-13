#!/usr/bin/env bash
#
# create_known_issues.sh — one-time migration of docs/known_issues.md
# findings into GitHub Issues, so they're visible/trackable in the Issues
# tab (open vs closed, labels, discussion threads) instead of only living
# in a markdown file.
#
# Requires: `gh` CLI, already authenticated (this is preconfigured in most
# Codespaces automatically -- run `gh auth status` first to confirm).
#
# Usage:
#   chmod +x create_known_issues.sh
#   ./create_known_issues.sh
#
# Safe to re-run: it will just create duplicate issues if run twice, so
# only run this once. (A "run once" guard isn't built in on purpose --
# keeping this simple; just don't run it twice.)

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Creating labels (safe to ignore 'already exists' errors)..."
gh label create "bug:crash" --color "d73a4a" --description "Causes a crash or exception" 2>/dev/null || true
gh label create "bug:silent-failure" --color "e99695" --description "Fails silently / wrong behavior without error" 2>/dev/null || true
gh label create "docs" --color "0075ca" --description "Documentation inconsistency" 2>/dev/null || true
gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "coverage-gap" --color "c5def5" --description "Untested code path" 2>/dev/null || true
gh label create "lapisan-0" --color "5319e7" --description "Foundation layer (stamp, os_bridge, yomi_data)" 2>/dev/null || true

echo ""
echo "Creating issues..."

# --- Fixed issues (created then immediately closed, so history is preserved) ---

ISSUE_URL=$(gh issue create \
  --title "docs: dataset_documentation.md tells judges to export GEMINI_API_KEY, router.py reads YOMI_GEMINI_API_KEY" \
  --label "docs" \
  --body "Following the doc literally means the LLM cascade silently never activates.

Fixed on \`develop\` (see commit 2119914)."
)
gh issue close --comment "Fixed in commit 2119914" "$ISSUE_URL"
ISSUE_URL=$(gh issue create \
  --title "docs: README references docs/system_topology.svg (lowercase), actual file is System_Topology.svg" \
  --label "docs" \
  --body "Broken image link on any case-sensitive filesystem (Linux, GitHub raw).

Fixed on \`develop\` (see commit 2119914)."
)
gh issue close --comment "Fixed in commit 2119914" "$ISSUE_URL"
ISSUE_URL=$(gh issue create \
  --title "chore: yomi_data/recovery/ (created at runtime by shadow_net.py) has no .gitkeep" \
  --label "docs" \
  --body "Inconsistent repo structure vs. the other 6 data subfolders on fresh clone.

Fixed on \`develop\` (see commit 2119914)."
)
gh issue close --comment "Fixed in commit 2119914" "$ISSUE_URL"
ISSUE_URL=$(gh issue create \
  --title "bug: cli.py --install flag crashes 100% of the time (UnboundLocalError)" \
  --label "bug:crash" \
  --body "Redundant local 'import sys' later in main() shadows the module-level import for the whole function scope, so 'sys.exit(0)' at line 491 raises UnboundLocalError before ever reaching the local import.

Fixed on foundation/stamp-datastore-osbridge (commit 7109a77)."
)
gh issue close --comment "Fixed in commit 7109a77" "$ISSUE_URL"
ISSUE_URL=$(gh issue create \
  --title "bug: _run_console_loop() calls undefined _get_latest_ledger_log()" \
  --label "bug:crash" \
  --body "NameError on first ledger-size change in console/headless fallback mode. _run_tui_loop() already used the correct helper (_get_new_ledger_logs); console mode was never brought in sync.

Fixed on foundation/stamp-datastore-osbridge (commit 7109a77)."
)
gh issue close --comment "Fixed in commit 7109a77" "$ISSUE_URL"
ISSUE_URL=$(gh issue create \
  --title "bug: query_cve() defined twice in library.py, active version uses shallow copy not deepcopy" \
  --label "bug:silent-failure" \
  --body "The second (silently active) definition used .copy() instead of deepcopy(), meaning callers could mutate nested fields of the in-memory CVE cache through the object they were handed.

Fixed on foundation/stamp-datastore-osbridge (commit 7109a77)." 

# --- Open issues (documented, not yet fixed) ---
)
gh issue close --comment "Fixed in commit 7109a77" "$ISSUE_URL"
gh issue create \
  --title "bug: weaver.py drops MITRE tactic findings from the human-readable dossier" \
  --label "bug:silent-failure" \
  --body "Confirmed empirically against a real report file: the ledger clearly logged MITRE_MAPPER 'MAPPED' events, but the generated dossier said 'No explicit MITRE heuristics detected.' Needs a fix in weaver.py's event-selection logic.

Status: OPEN. Scheduled for whichever phase touches yomi_engine/weaver.py + dossier.py."

gh issue create \
  --title "bug: write_year_store() silently drops entries missing a matching cve_id field" \
  --label "bug:silent-failure,lapisan-0" \
  --body "No shape validation at write time. An entry missing cve_id writes successfully with zero error, then vanishes (quarantined as corrupt) on next read/scan.

Regression-captured in tests/unit/test_yomi_data.py::test_write_year_store_silently_drops_entries_missing_cve_id, but the actual fix (validate on write) is not yet implemented.

Status: OPEN."

gh issue create \
  --title "design: ImmutableStamp singleton + hardcoded __file__-relative data_dir blocks multi-tenant use" \
  --label "design-smell,lapisan-0" \
  --body "stamp.py and yomi_data/__init__.py both hardcode their data directory relative to __file__, with ImmutableStamp additionally being a strict process-wide singleton. Makes concurrent-investigation use impossible within one process; required a __file__-monkeypatch fixture just to unit-test safely (see tests/unit/conftest.py).

Status: OPEN. Needs discussion -- this is a behavior change beyond 'add tests', affects every module built on top of it."

gh issue create \
  --title "design: mcp_server.py READ_VAULTS/WRITE_VAULTS hardcoded to a fixed path list" \
  --label "design-smell" \
  --body "Not derived from yomi_data's actual location. A deployment outside /tmp, /var/tmp, /mnt, /home, /workspace, /data, /media, /opt/yomi will have every MCP tool call VETOed as 'outside vault boundaries' even when legitimate.

Status: OPEN. Portability concern for enterprise deployment."

gh issue create \
  --title "architecture: sentinel.py's autonomous loop only wires 5 of 13 real modules" \
  --label "design-smell" \
  --body "mind_reader, shadow_net, remediator, dossier, mirage, sandbox, ghost, ebpf_sensor exist but were never called automatically from the main loop -- only reachable via each file's own __main__ block.

This is what yomi_core/module_registry.py (Fase 4-5, Guardian orchestrator) is being built to fix.

Status: OPEN. Tracked as the core architectural gap driving the Guardian orchestrator work."

gh issue create \
  --title "coverage: stamp.py is only 54% covered -- KMS/Vault/backup/checkpoint paths untested" \
  --label "coverage-gap,lapisan-0" \
  --body "Untested paths include: KMS/Vault/AWS-Secrets-Manager HMAC key retrieval, password-derived ephemeral key generation, corrupted-ledger backup + cleanup, SOC checkpoint anchoring/verification.

Status: OPEN. Top coverage priority for whichever phase next touches stamp.py."

gh issue create \
  --title "design: checkpoint 'mismatch detected' log message fires on every normal write, not just tampering" \
  --label "design-smell,lapisan-0" \
  --body "_create_or_verify_checkpoint() prints 'Checkpoint mismatch detected. Updating...' whenever last_hash differs from the stored checkpoint -- which is expected on every normal append, not a tamper signal. Risk: operators habituate to the message and ignore it, including on the rare occasion it IS real tampering.

Status: OPEN. Consider distinguishing 'routine update' from 'verification failure' in the log wording."

echo ""
echo "Done. Run 'gh issue list --state all' to review."
