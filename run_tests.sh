#!/usr/bin/env bash
#
# run_tests.sh — one-command test runner for Codespaces / any dev machine.
#
# Usage:
#   ./run_tests.sh              # full suite: lint + unit + benchmarks + coverage
#   ./run_tests.sh lint         # lint only
#   ./run_tests.sh unit         # unit tests only
#   ./run_tests.sh bench        # benchmarks only
#   ./run_tests.sh integration  # integration/crucible tests only (once they exist)
#   ./run_tests.sh quick        # unit tests only, no coverage report (fastest loop)
#
# Exits non-zero on first failing stage, matching what branch-ci.yml /
# develop-ci.yml do in GitHub Actions -- so if this script is green, the
# CI job for this branch should be green too (mirrors CI locally, catches
# problems before you even push).

set -euo pipefail

# Always run from the repo root, regardless of where the script is invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

step() { echo -e "\n${BOLD}${YELLOW}==> $1${NC}"; }
ok()   { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }

MODE="${1:-all}"

# --------------------------------------------------------------------------
step "Checking dependencies"
# --------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    fail "python3 not found. Install Python 3.10+ first."
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  Python version: $PY_VERSION"

if ! python3 -c "import pytest" &>/dev/null; then
    echo "  pytest not found, installing dev requirements..."
    pip install -r requirements-dev.txt --quiet || pip install -r requirements-dev.txt --break-system-packages --quiet
fi
ok "Dependencies present"

# --------------------------------------------------------------------------
run_lint() {
    step "Lint (ruff — blocking ruleset only: real bug classes, not style)"
    if ruff check . ; then
        ok "Lint passed"
    else
        fail "Lint failed — fix the errors above before continuing (see docs/known_issues.md for the style backlog that's intentionally NOT blocking)"
    fi
}

run_unit() {
    step "Unit tests (tests/unit/)"
    if [ "$MODE" = "quick" ]; then
        pytest tests/unit/ -v || fail "Unit tests failed"
    else
        pytest tests/unit/ -v --cov=yomi_audit --cov=yomi_data --cov=yomi_mcp --cov=yomi_core --cov=yomi_engine --cov-report=term-missing || fail "Unit tests failed"
    fi
    ok "Unit tests passed"
}

run_integration() {
    step "Integration / crucible tests (tests/integration/)"
    if [ -z "$(find tests/integration -name 'test_*.py' 2>/dev/null)" ]; then
        echo "  (no integration tests yet — expected until Fase 4)"
        return 0
    fi
    pytest tests/integration/ -v || fail "Integration tests failed"
    ok "Integration tests passed"
}

run_bench() {
    step "Benchmarks (tests/benchmarks/)"
    if [ -z "$(find tests/benchmarks -name 'test_*.py' 2>/dev/null)" ]; then
        echo "  (no benchmarks yet)"
        return 0
    fi
    pytest tests/benchmarks/ -v -s || fail "Benchmarks failed"
    ok "Benchmarks passed"
}

# --------------------------------------------------------------------------
case "$MODE" in
    lint)        run_lint ;;
    unit)        run_lint; run_unit ;;
    quick)       run_unit ;;
    bench)       run_bench ;;
    integration) run_integration ;;
    all)
        run_lint
        run_unit
        run_integration
        run_bench
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: ./run_tests.sh [lint|unit|bench|integration|quick|all]"
        exit 1
        ;;
esac

echo -e "\n${GREEN}${BOLD}All requested checks passed.${NC}"
