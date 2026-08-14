"""
Unit tests for yomi_engine.telemetry.TelemetryEngine.

Reuses the isolated_stamp fixture pattern from conftest.py (TelemetryEngine
instantiates ImmutableStamp() internally, same singleton/hardcoded-path
situation as Fase 1 -- see docs/known_issues.md #9).
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def telemetry(isolated_stamp, monkeypatch):
    """
    TelemetryEngine backed by the same isolated ledger as isolated_stamp,
    since TelemetryEngine() would otherwise instantiate its own
    ImmutableStamp() call -- which, being a singleton, returns the SAME
    isolated_stamp instance the fixture already set up. Making the
    dependency explicit here rather than relying on singleton magic.
    """
    from yomi_engine import telemetry as telemetry_module

    engine = telemetry_module.TelemetryEngine()
    assert engine.audit is isolated_stamp  # sanity: confirms singleton reuse
    return engine


def test_start_then_stop_returns_report_with_expected_shape(telemetry):
    telemetry.start_timer("INC-001")
    time.sleep(0.01)
    report = telemetry.stop_timer("INC-001", "Cryogenic Freeze")

    assert report is not None
    assert report["incident_id"] == "INC-001"
    assert report["action"] == "Cryogenic Freeze"
    assert report["latency_seconds"] > 0
    assert report["human_speed_multiplier"].endswith("x")
    assert isinstance(report["beat_horizon3_ai"], bool)


def test_stop_timer_on_unknown_incident_returns_none(telemetry):
    assert telemetry.stop_timer("NEVER_STARTED", "some action") is None


def test_stop_timer_removes_incident_from_tracking(telemetry):
    telemetry.start_timer("INC-002")
    assert "INC-002" in telemetry.active_incidents
    telemetry.stop_timer("INC-002", "action")
    assert "INC-002" not in telemetry.active_incidents


def test_double_stop_second_call_returns_none(telemetry):
    telemetry.start_timer("INC-003")
    first = telemetry.stop_timer("INC-003", "action")
    second = telemetry.stop_timer("INC-003", "action")
    assert first is not None
    assert second is None


def test_report_is_sealed_to_ledger(telemetry, isolated_stamp):
    telemetry.start_timer("INC-004")
    telemetry.stop_timer("INC-004", "Sandbox Containment")

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 2  # genesis + this benchmark entry


def test_speed_multiplier_is_bounded_for_sub_millisecond_latency(telemetry):
    """
    Regression guard for the documented "astronomical multiplier" bug the
    module's own docstring says it prevents (human_soc_avg / near-zero
    latency could otherwise produce e.g. 120,000,000x). Confirms the
    max(latency, 0.001) floor actually caps it.
    """
    telemetry.start_timer("INC-FAST")
    # No sleep -- latency will be near-zero, sub-millisecond.
    report = telemetry.stop_timer("INC-FAST", "instant action")

    multiplier_str = report["human_speed_multiplier"].rstrip("x")
    multiplier = float(multiplier_str)
    # human_soc_avg (1200.0) / floor (0.001) = 1,200,000 is the mathematical
    # ceiling given the current floor value -- assert we never exceed it.
    assert multiplier <= 1_200_000.0


def test_beat_horizon3_ai_flag_reflects_60_second_threshold(telemetry, monkeypatch):
    # Directly exercise the boundary by manipulating perf_counter via the
    # active_incidents dict rather than actually sleeping 60+ seconds.
    telemetry.start_timer("INC-SLOW")
    with telemetry._dict_lock:
        telemetry.active_incidents["INC-SLOW"] = time.perf_counter() - 61.0
    report = telemetry.stop_timer("INC-SLOW", "slow action")
    assert report["beat_horizon3_ai"] is False
    assert report["latency_seconds"] >= 61.0


def test_max_tracked_incidents_evicts_oldest_on_overflow(telemetry):
    telemetry.MAX_TRACKED_INCIDENTS = 5  # shrink for a fast test
    for i in range(5):
        telemetry.start_timer(f"INC-{i}")
    assert len(telemetry.active_incidents) == 5

    telemetry.start_timer("INC-OVERFLOW")
    # Eviction pops up to 100 at a time, but with only 5 present, it clears
    # all 5 before inserting the new one -- so we expect exactly 1 left.
    assert len(telemetry.active_incidents) == 1
    assert "INC-OVERFLOW" in telemetry.active_incidents


def test_concurrent_start_stop_is_thread_safe(telemetry):
    """
    Fires 50 threads each starting+stopping their own incident concurrently.
    Not a proof of absence of races, but exercises the dual-lock path under
    real contention rather than only single-threaded calls.
    """
    errors = []

    def worker(i):
        try:
            incident_id = f"THREAD-{i}"
            telemetry.start_timer(incident_id)
            time.sleep(0.001)
            result = telemetry.stop_timer(incident_id, "concurrent action")
            if result is None:
                errors.append(f"{incident_id} got None result")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{i}: {exc!r}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert errors == []
    assert telemetry.active_incidents == {}
