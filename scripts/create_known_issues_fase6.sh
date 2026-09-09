#!/usr/bin/env bash
#
# create_known_issues_fase6.sh — GitHub issue housekeeping for Fase 6,
# Tahap 1 (Guardian Orchestrator integration).
#
# Covers three known_issues.md entries:
#   #11 -- sentinel.py only wired 5/13 modules. FIXED by
#          yomi_core/guardian.py's GuardianOrchestrator.
#   #25 -- mirage.py's own YOMI_ENABLE_MIRAGE_MODE env var duplicates
#          module_registry's YOMI_MODULE_MIRAGE. WORKED AROUND (Guardian
#          calls with force_enable=True), not removed -- left OPEN as a
#          design note for a future cleanup pass.
#   #26 -- Ghost Protocol and the eBPF Sensor bypassed module_registry
#          entirely in cli.py (Ghost had its own ad-hoc env var; the
#          eBPF Sensor had NO gating at all). FIXED.
#
# This script:
#   1. Closes the GitHub issue for #11 (GH#13, per this repo's existing
#      known_issues# + 2 offset -- confirmed from the actual GitHub
#      issues list, not guessed).
#   2. Creates a new GitHub issue for #25, left OPEN.
#   3. Creates a new GitHub issue for #26, then immediately closes it
#      (found and fixed in the same session).
#
# Usage:
#   chmod +x create_known_issues_fase6.sh
#   ./create_known_issues_fase6.sh

set -euo pipefail

if ! command -v gh &>/dev/null; then
    echo "gh CLI not found. Install it or run this from GitHub Codespaces (usually preinstalled)."
    exit 1
fi

gh auth status || { echo "Run 'gh auth login' first."; exit 1; }

echo "Creating any missing labels (safe to ignore 'already exists' errors)..."
gh label create "design-smell" --color "fbca04" --description "Not a bug, but a design concern" 2>/dev/null || true
gh label create "lapisan-2" --color "0e8a16" --description "Orchestration layer (sentinel, guardian, router)" 2>/dev/null || true

echo ""
echo "Closing #11's GitHub issue (GH#13)..."
gh issue close 13 --comment "Fixed in Fase 6 Tahap 1 -- yomi_core/guardian.py's GuardianOrchestrator now wires all 13 modules (mind_reader, shadow_net, remediator, dossier, mirage, sandbox, ghost, ebpf_sensor) into sentinel.py's autonomous loop, gated entirely by module_registry. See docs/known_issues.md #11 and docs/phase_log/fase_6.md for the full dispatch design. 25 new tests in tests/unit/test_guardian.py (93% coverage), plus real end-to-end integration test assertions against a live subprocess PID." \
  2>/dev/null || echo "(could not close #13 -- already closed, or the number doesn't match; check manually)"

echo ""
echo "Creating Fase 6 issue for #25 (mirage.py dual env-var gating -- worked around)..."
gh issue create \
  --title "design: mirage.py's own env-var gate duplicates module_registry's YOMI_MODULE_MIRAGE" \
  --label "design-smell,lapisan-2" \
  --body "mirage.py's deploy_hallucination() checks its OWN internal env var (YOMI_ENABLE_MIRAGE_MODE) in addition to whatever module_registry's YOMI_MODULE_MIRAGE decided -- two separate toggles an operator could set inconsistently.

Status: WORKED AROUND, not removed. GuardianOrchestrator calls deploy_hallucination(..., force_enable=True), deliberately bypassing mirage.py's own env check -- the enable/disable decision is made once, at the registry level, before Guardian ever calls it. mirage.py's own env var is left in place for backward compatibility with direct/manual invocation. Genuinely removing the duplicate mechanism would be a larger, separate cleanup -- not done here since it risks breaking existing tests/unit/test_mirage.py assertions that specifically test that env var's behavior.

See docs/known_issues.md #25." \
  || echo "(issue may already exist, skipping)"

echo ""
echo "Creating + closing Fase 6 issue for #26 (Ghost Protocol / eBPF Sensor bypassed module_registry)..."
issue_url=$(gh issue create \
  --title "bug: Ghost Protocol and eBPF Sensor bypassed module_registry entirely in cli.py" \
  --label "design-smell,lapisan-2" \
  --body "Ghost Protocol was gated by its own ad-hoc YOMI_ENABLE_GHOST_PROTOCOL env var, never by module_registry's YOMI_MODULE_GHOST. Worse: the eBPF Sensor had NO gating at all -- cli.py unconditionally subprocess.Popen'd it on every --auto startup, completely ignoring EBPF_SENSOR's default_enabled=False in the registry.

Fixed same session: both now go through GuardianOrchestrator.bootstrap_startup_daemons(), which consults module_registry.resolve_active_modules() exclusively. BREAKING CHANGE: operators relying on YOMI_ENABLE_GHOST_PROTOCOL=true must switch to YOMI_MODULE_GHOST=true.

See docs/known_issues.md #26.")
issue_num=$(basename "$issue_url")
gh issue close "$issue_num" --comment "Fixed in the same commit that introduced yomi_core/guardian.py (Fase 6 Tahap 1). See docs/known_issues.md #26."

echo ""
echo "Done. Verify with: gh issue list --state all --search 'guardian OR module_registry OR ebpf OR ghost'"
