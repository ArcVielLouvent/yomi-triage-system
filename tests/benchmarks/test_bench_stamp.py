"""
Fase 1 benchmark: ImmutableStamp.record_action() throughput.

Why this metric first: every other module in the system calls
record_action() on the hot path (containment, tool execution, LLM calls all
get sealed to the ledger). If this gets slow, everything built on top of it
inherits that latency -- including the README's claimed ~3-second
Time-to-Containment. This is the first number worth tracking over time.

This is intentionally simple (wall-clock timing, not statistical rigor via
pytest-benchmark yet) -- it establishes the pattern and a baseline file.
`scripts/check_benchmark_regression.py` (currently a stub, see Fase 4) will
eventually compare future runs against `baseline.json` here and fail CI on
regression beyond a threshold.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def run_benchmark(n_entries: int = 200) -> dict:
    # Isolated temp instance -- benchmarks must never touch the real ledger.
    import tempfile

    from yomi_audit import stamp as stamp_module

    with tempfile.TemporaryDirectory() as tmp:
        fake_module_dir = Path(tmp) / "fake_pkg" / "yomi_audit"
        fake_module_dir.mkdir(parents=True)
        stamp_module.__file__ = str(fake_module_dir / "stamp.py")
        stamp_module.ImmutableStamp._instance = None

        instance = stamp_module.ImmutableStamp()

        durations = []
        for i in range(n_entries):
            start = time.perf_counter()
            instance.record_action(
                agent_name="BENCHMARK",
                action_type="BENCH_WRITE",
                description=f"benchmark entry {i}",
            )
            durations.append(time.perf_counter() - start)

        stamp_module.ImmutableStamp._instance = None

    return {
        "operation": "ImmutableStamp.record_action",
        "n_entries": n_entries,
        "mean_seconds": statistics.mean(durations),
        "median_seconds": statistics.median(durations),
        "p95_seconds": sorted(durations)[int(0.95 * len(durations)) - 1],
        "max_seconds": max(durations),
        "ops_per_second": n_entries / sum(durations),
    }


def test_record_action_throughput_benchmark(tmp_path):
    """
    Not a pass/fail correctness test -- records current throughput so CI logs
    show it over time. Sanity floor only: fails if something is catastrophically
    slow (e.g. an accidental O(n^2) introduced upstream), not a strict SLA.
    """
    result = run_benchmark(n_entries=200)
    print(f"\n[BENCHMARK] {json.dumps(result, indent=2)}")

    baseline_path = Path(__file__).parent / "baseline_stamp_record_action.json"
    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text())
        print(f"[BENCHMARK] baseline mean: {baseline['mean_seconds']:.6f}s "
              f"vs current: {result['mean_seconds']:.6f}s")

    # Sanity floor: sealing one ledger entry should never take >250ms on
    # CI-class hardware. This catches gross regressions, not micro-drift.
    assert result["mean_seconds"] < 0.25, (
        f"record_action() averaged {result['mean_seconds']:.3f}s/call, "
        f"far above the 250ms sanity ceiling."
    )


if __name__ == "__main__":
    # Run standalone to (re)generate the committed baseline file:
    #   python3 tests/benchmarks/test_bench_stamp.py
    res = run_benchmark(n_entries=200)
    print(json.dumps(res, indent=2))
    out = Path(__file__).parent / "baseline_stamp_record_action.json"
    out.write_text(json.dumps(res, indent=2))
    print(f"Baseline written to {out}")
