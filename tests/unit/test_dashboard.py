"""
Unit tests for yomi_core.dashboard.YomiDashboard.

__init__ starts a daemon background thread (_background_metrics_worker,
polling every 1s) and constructs OmniLibrary() with no args (hardcoded
default data_dir, same isolation need as test_library.py) -- both handled
by the fixture. dashboard.stop() is called in teardown to avoid leaking a
live background thread into the rest of the test session.

_refresh_telemetry_metrics() also has its own hardcoded __file__-relative
path (yomi_data/telemetry_benchmarks.jsonl, relative to dashboard.py's own
__file__, independent of library.py's), isolated the same way.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def dashboard(isolated_stamp, tmp_path, monkeypatch):
    from yomi_core import dashboard as dashboard_module
    from yomi_engine import library as library_module

    fake_dashboard_dir = tmp_path / "fake_pkg" / "yomi_core"
    fake_library_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_dashboard_dir.mkdir(parents=True)
    fake_library_dir.mkdir(parents=True)
    monkeypatch.setattr(dashboard_module, "__file__", str(fake_dashboard_dir / "dashboard.py"))
    monkeypatch.setattr(library_module, "__file__", str(fake_library_dir / "library.py"))
    monkeypatch.setattr(library_module.OmniLibrary, "_has_network", lambda self: False)

    instance = dashboard_module.YomiDashboard()
    yield instance
    instance.stop()
    instance.library.shutdown()


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------

def test_background_worker_starts_and_stops_cleanly(dashboard):
    assert dashboard.worker_thread.is_alive()
    dashboard.stop()
    assert not dashboard.worker_thread.is_alive()
    assert dashboard.is_running is False


# --------------------------------------------------------------------------
# append_log: sanitization + classification
# --------------------------------------------------------------------------

def test_append_log_strips_ansi_escape_codes(dashboard):
    dashboard.append_log("\x1b[31mRED TEXT\x1b[0m normal text")
    logged = str(dashboard.action_log[-1])
    assert "\x1b[31m" not in logged
    assert "RED TEXT" in logged


def test_append_log_strips_control_chars_and_rtl_override(dashboard):
    dashboard.append_log("before\u202Eevil-reversed-text\x07after")
    logged = str(dashboard.action_log[-1])
    assert "\u202E" not in logged
    assert "\x07" not in logged


def test_append_log_marks_newlines_visibly(dashboard):
    dashboard.append_log("line one\nline two")
    logged = str(dashboard.action_log[-1])
    assert "[LF]" in logged
    assert "\n" not in logged.split("] ", 1)[-1].replace(" [LF] ", "")


def test_append_log_truncates_at_2000_chars(dashboard):
    dashboard.append_log("A" * 3000)
    logged = str(dashboard.action_log[-1])
    assert "[TRUNCATED BY YOMI VAULT SHIELD]" in logged
    assert len(logged) < 2200  # well under the untruncated 3000+ chars


def test_append_log_caps_history_at_100_entries(dashboard):
    for i in range(150):
        dashboard.append_log(f"entry {i}")
    assert len(dashboard.action_log) == 100
    assert "entry 149" in str(dashboard.action_log[-1])
    assert "entry 50" in str(dashboard.action_log[0])  # entries 0-49 evicted


@pytest.mark.parametrize(
    "text,expected_color_key",
    [
        ("CRITICAL failure detected", "blood_red"),
        ("SHADOW NET engaged", "cyber_purple"),
        ("WARNING: doubt threshold exceeded", "warning"),
        ("Operation SUCCESS", "green_matrix"),
        ("routine status update", "ghost_white"),
    ],
)
def test_append_log_color_classification(dashboard, text, expected_color_key):
    dashboard.append_log(text)
    logged_style = dashboard.action_log[-1].style
    assert dashboard.colors[expected_color_key] in str(logged_style)


def test_append_log_threat_keyword_takes_priority_over_others(dashboard):
    # Contains both a threat keyword (CRITICAL) and a success keyword
    # (SUCCESS) -- threat classification must win.
    dashboard.append_log("CRITICAL error during otherwise SUCCESS operation")
    logged_style = dashboard.action_log[-1].style
    assert dashboard.colors["blood_red"] in str(logged_style)


# --------------------------------------------------------------------------
# update_telemetry / update_state
# --------------------------------------------------------------------------

def test_update_telemetry_only_changes_provided_fields(dashboard):
    dashboard.update_telemetry(status="CONTAINMENT ACTIVE")
    assert dashboard.current_status == "CONTAINMENT ACTIVE"
    assert dashboard.active_pid == "SCANNING..."  # unchanged


def test_update_state_updates_telemetry_and_appends_log(dashboard):
    dashboard.update_state("CRITICAL", "1234", recent_log="Threat contained.")
    assert dashboard.current_status == "CRITICAL"
    assert dashboard.active_pid == "1234"
    assert "Threat contained" in str(dashboard.action_log[-1])


# --------------------------------------------------------------------------
# _refresh_telemetry_metrics
# --------------------------------------------------------------------------

def test_refresh_telemetry_missing_file_shows_tampered_state(dashboard):
    dashboard._refresh_telemetry_metrics()
    assert "TAMPERED" in dashboard.latest_ttc
    assert dashboard._last_tel_size == -1


def test_refresh_telemetry_parses_latest_valid_entry(dashboard, tmp_path, monkeypatch):
    import os

    tel_dir = Path(dashboard.__class__.__module__)  # placeholder, real path built below
    tel_path = os.path.abspath(
        os.path.join(os.path.dirname(sys.modules["yomi_core.dashboard"].__file__), "..", "yomi_data")
    )
    os.makedirs(tel_path, exist_ok=True)
    tel_file = os.path.join(tel_path, "telemetry_benchmarks.jsonl")

    with open(tel_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"latency_seconds": 2.5, "human_speed_multiplier": "120x", "beat_horizon3_ai": True}) + "\n")

    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "2.5s"
    assert "120x" in dashboard.speed_multiplier
    assert "True" in dashboard.speed_multiplier


def test_refresh_telemetry_skips_malformed_trailing_lines(dashboard):
    import os

    tel_path = os.path.abspath(
        os.path.join(os.path.dirname(sys.modules["yomi_core.dashboard"].__file__), "..", "yomi_data")
    )
    os.makedirs(tel_path, exist_ok=True)
    tel_file = os.path.join(tel_path, "telemetry_benchmarks.jsonl")

    with open(tel_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"latency_seconds": 1.0, "human_speed_multiplier": "10x", "beat_horizon3_ai": False}) + "\n")
        f.write("{not valid json\n")

    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "1.0s"  # fell back to the last VALID line


# --------------------------------------------------------------------------
# _refresh_library_metrics / _refresh_system_metrics
# --------------------------------------------------------------------------

def test_refresh_library_metrics_success(dashboard):
    dashboard._refresh_library_metrics()
    assert dashboard.library_status in ("ONLINE", "AIR-GAPPED")


def test_refresh_library_metrics_exception_sets_error_status(dashboard, monkeypatch):
    def raise_error():
        raise RuntimeError("simulated metadata failure")

    monkeypatch.setattr(dashboard.library, "get_metadata", raise_error)
    dashboard._refresh_library_metrics()
    assert dashboard.library_status == "ERROR"


def test_refresh_system_metrics_populates_real_values(dashboard):
    dashboard._refresh_system_metrics()
    assert dashboard.memory_status in ("NORMAL", "WARNING", "CRITICAL")
    assert dashboard.yomi_ram_mb > 0  # this test process genuinely uses some RAM
    assert dashboard.cpu_usage.endswith("%")


# --------------------------------------------------------------------------
# Layout rendering: smoke tests (must not crash, correct Rich types)
# --------------------------------------------------------------------------

def test_render_layout_does_not_crash(dashboard):
    from rich.layout import Layout

    layout = dashboard.render_layout()
    assert isinstance(layout, Layout)


def test_make_telemetry_panel_reflects_critical_status_color(dashboard):
    from rich.panel import Panel

    dashboard.update_telemetry(status="SYSTEM OVERLOAD - CRITICAL")
    panel = dashboard.make_telemetry_panel()
    assert isinstance(panel, Panel)
