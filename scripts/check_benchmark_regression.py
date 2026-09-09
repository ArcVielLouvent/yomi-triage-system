#!/usr/bin/env python3
"""
Compares fresh benchmark results against a committed baseline and fails
if any tracked metric regresses beyond an allowed threshold.

Design principle (see conversation with the user, who correctly pointed
out benchmark ABSOLUTE numbers are machine-dependent -- a laptop, a
Codespaces runner, and a CI runner will never produce the same raw
ops/sec, and that's expected, not a bug): this script does NOT compare
across machines. It compares a fresh run against a *baseline recorded on
that same machine* (or the same CI runner class, which is reasonably
consistent run-to-run on GitHub Actions). The baseline file itself is
regenerated locally per-environment via each benchmark's `__main__` block
(see tests/benchmarks/test_bench_stamp.py) -- CI's baseline is whatever
was last committed from a CI run, not from a contributor's laptop.

Usage:
    python3 scripts/check_benchmark_regression.py [--threshold 0.5]

Exit code 0: no regression (or no baseline yet to compare against --
first run on a new machine/runner is never a failure, it just seeds
data for next time to compare against).
Exit code 1: a tracked metric regressed beyond the threshold.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parent.parent / "tests" / "benchmarks"

TRACKED_BENCHMARKS = [
    {
        "name": "ImmutableStamp.record_action mean latency",
        "baseline_file": BENCHMARKS_DIR / "baseline_stamp_record_action.json",
        "metric_key": "mean_seconds",
        "direction": "lower_is_better",
    },
]


def _run_benchmark_fresh(baseline_file: Path) -> dict | None:
    """
    Re-runs the benchmark that produced this baseline file, fresh, right
    now, rather than trusting a possibly-stale value already on disk from
    a previous test run in this same CI job. Imports the benchmark
    module's own run_benchmark() function directly.
    """
    if baseline_file.name == "baseline_stamp_record_action.json":
        sys.path.insert(0, str(BENCHMARKS_DIR.parent.parent))
        from tests.benchmarks.test_bench_stamp import run_benchmark

        return run_benchmark(n_entries=200)
    return None


def check_regression(threshold: float) -> int:
    any_regression = False
    any_baseline_missing = False

    for bench in TRACKED_BENCHMARKS:
        name = bench["name"]
        baseline_file = bench["baseline_file"]
        metric_key = bench["metric_key"]
        direction = bench["direction"]

        if not baseline_file.exists():
            print(
                f"[check_benchmark_regression] No baseline yet for '{name}' "
                f"({baseline_file.name}) -- skipping, not a failure. "
                f"Run the benchmark's __main__ block on this machine/runner "
                f"once to seed one.",
                file=sys.stderr,
            )
            any_baseline_missing = True
            continue

        baseline = json.loads(baseline_file.read_text())
        baseline_value = baseline.get(metric_key)
        if baseline_value is None:
            print(
                f"[check_benchmark_regression] Baseline for '{name}' exists "
                f"but has no '{metric_key}' key -- skipping.",
                file=sys.stderr,
            )
            continue

        current = _run_benchmark_fresh(baseline_file)
        if current is None:
            print(
                f"[check_benchmark_regression] Don't know how to re-run "
                f"benchmark for '{name}' -- skipping.",
                file=sys.stderr,
            )
            continue
        current_value = current[metric_key]

        if direction == "lower_is_better":
            allowed_max = baseline_value * (1 + threshold)
            regressed = current_value > allowed_max
            pct_change = ((current_value - baseline_value) / baseline_value) * 100
        else:
            allowed_min = baseline_value * (1 - threshold)
            regressed = current_value < allowed_min
            pct_change = ((baseline_value - current_value) / baseline_value) * 100

        status = "REGRESSED" if regressed else "OK"
        print(
            f"[check_benchmark_regression] {name}: baseline={baseline_value:.6f} "
            f"current={current_value:.6f} change={pct_change:+.1f}% "
            f"(threshold={threshold*100:.0f}%) -> {status}"
        )

        if regressed:
            any_regression = True

    if any_regression:
        print(
            "[check_benchmark_regression] FAIL: one or more benchmarks "
            "regressed beyond the allowed threshold.",
            file=sys.stderr,
        )
        return 1

    if any_baseline_missing:
        print(
            "[check_benchmark_regression] PASS (with missing baselines -- "
            "not a failure, but consider seeding them).",
            file=sys.stderr,
        )
    else:
        print("[check_benchmark_regression] PASS: no regressions.", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Allowed fractional regression before failing (default 0.5 = 50%%). "
        "Deliberately generous: CI runners have noisy, shared CPU allocation, "
        "so a tight threshold would produce false-positive failures unrelated "
        "to real code regressions.",
    )
    args = parser.parse_args()
    return check_regression(args.threshold)


if __name__ == "__main__":
    sys.exit(main())
