#!/usr/bin/env python3
"""
Boots `yomi_core/cli.py --auto --headless` against a synthetic, non-destructive
scenario and asserts a clean startup + clean SIGTERM shutdown, proving the
wired pipeline actually runs end-to-end (not just that unit tests pass in
isolation).

STATUS: STUB. Intentionally exits 0 with a warning. Real implementation
depends on the Module Registry (feature/module-registry) and Guardian
orchestrator (feature/guardian-orchestrator) existing first, since a
meaningful smoke test needs a `ci-smoke` module profile that runs read-only
modules only, with Ghost Protocol / Mirage / Shadow Net force-disabled
regardless of local env, on a synthetic anomaly instead of a real one.
"""
import sys


def main() -> int:
    print(
        "[smoke_test_cli] STUB: Guardian/module_registry not implemented yet. "
        "This check currently does not fail the build. "
        "Real implementation: Fase 4-5 (Guardian orchestrator + Module Registry).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
