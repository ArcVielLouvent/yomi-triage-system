#!/usr/bin/env python3
"""
Compares a fresh telemetry benchmark run against a committed baseline and
fails CI if Time-to-Containment (or any tracked metric) regresses beyond an
allowed threshold.

STATUS: STUB. Intentionally exits 0 with a warning so `develop-ci` is
honest about the fact this gate does not enforce anything yet, rather than
silently pretending to. Real implementation is scheduled for Fase 4
(benchmark harness), once tests/benchmarks/ has real telemetry.py-driven
cases to compare against.
"""
import sys


def main() -> int:
    print(
        "[check_benchmark_regression] STUB: no baseline wired yet. "
        "This check currently does not fail the build. "
        "Real implementation: Fase 4 (Benchmarking harness).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
