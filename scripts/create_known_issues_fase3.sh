#!/usr/bin/env bash
#
# create_known_issues_fase3.sh — creates GitHub Issues for findings #21-22
# from Fase 3 (Lapisan 2: router.py, mcp_server.py, hunter.py, swarm.py,
# dossier.py, mind_reader.py, shadow_net.py, dashboard.py).
#
# Run once, after create_known_issues.sh and create_known_issues_batch2_3.sh
# have already been run.
#
# Usage:
#   chmod +x create_known_issues_fase3.sh
#   ./create_known_issues_fase3.sh

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Creating any missing labels (safe to ignore 'already exists' errors)..."
gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "lapisan-2" --color "0e8a16" --description "Layer 2 modules (router, mcp_server, hunter, swarm, dossier, mind_reader, shadow_net, dashboard)" 2>/dev/null || true
gh label create "dead-code" --color "cfd3d7" --description "Unreachable code, confirmed harmless, guarded by a regression test" 2>/dev/null || true

echo ""
echo "Creating Fase 3 issues..."

# --- Open (needs a product decision, not fixed) ----------------------------

gh issue create \
  --title "design: router.py ReAct loop gives no LLM feedback on OS-level execution failures" \
  --label "design-smell,lapisan-2" \
  --body "If an LLM-proposed freeze/thaw action passes veto (target PID isn't protected) but fails at the OS level (e.g. os_bridge returns GHOST_PROCESS for a PID that no longer exists, or a generic ERROR), _evaluate_intent's result doesn't match any of execute_autonomous_triage's explicit status checks (REJECTED, SELF_CORRECTION_REQUIRED, SUCCESS-and-not-vetoed, VETOED). The loop silently proceeds to the next iteration without appending any [SYSTEM FEEDBACK] to current_context -- unlike every other rejection path. The LLM has no signal that its action failed and may repeat an identical response, burning iterations until max_iterations triggers Shadow Net escalation with no useful diagnostic trail.

Captured as: tests/unit/test_router.py::test_triage_KNOWN_GAP_os_level_failure_gets_no_feedback_and_silently_retries

Status: OPEN. Needs a product decision: should this be its own handled branch (e.g. feed the OS-level failure reason back to the LLM, similar to VETOED), or is silent retry-then-escalate the intended fail-safe behavior?"

# --- Closed (confirmed, harmless, guarded by regression test) --------------

ISSUE_URL=$(gh issue create \
  --title "dead-code: harness.py's 'no OS routing defined' branch is unreachable" \
  --label "dead-code,lapisan-2" \
  --body "self.allowed_actions is exactly [\"freeze\", \"thaw\"]; _veto_check rejects any action outside that list before the dispatch logic runs, and the dispatch logic explicitly handles both remaining actions. No input can reach the trailing {\"status\": \"ERROR\", \"message\": \"Action valid but no OS routing defined...\"} branch.

Confirmed via regression test: tests/unit/test_harness.py::test_no_action_value_can_reach_the_trailing_no_routing_branch -- enumerates every entry in allowed_actions and confirms each is dispatched. If a future change adds a new allowed action without a matching dispatch branch, this test will fail loudly instead of the gap staying silent.

Not removed (harmless dead code), but fully investigated and guarded -- closing as resolved-by-test-coverage rather than leaving as an open TODO with no further action needed.")
gh issue close --comment "Confirmed harmless and guarded by regression test -- see tests/unit/test_harness.py" "$ISSUE_URL"

echo ""
echo "Done. Run 'gh issue list --state all' to review -- should now show 22 total."
