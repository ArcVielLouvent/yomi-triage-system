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

def test_refresh_telemetry_missing_file_on_fresh_install_is_not_an_alarm(dashboard):
    """
    TelemetryEngine records benchmarks in the audit ledger and never creates
    telemetry_benchmarks.jsonl, so on a normal install that file simply does
    not exist. The dashboard used to treat that as tampering and showed a red
    "[TAMPERED] FILE MISSING / AUDIT LOG COMPROMISED" permanently.
    """
    dashboard._refresh_telemetry_metrics()
    assert "TAMPERED" not in dashboard.latest_ttc
    assert dashboard.latest_ttc == "AWAITING INCIDENT"
    assert dashboard.speed_multiplier == "N/A"
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
        f.write(json.dumps({"latency_seconds": 2.5, "human_speed_multiplier": "120x", "sub_60s_containment": True}) + "\n")

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
        f.write(json.dumps({"latency_seconds": 1.0, "human_speed_multiplier": "10x", "sub_60s_containment": False}) + "\n")
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


# --------------------------------------------------------------------------
# Telemetry sources: ledger (real data source) and the tamper signal
# --------------------------------------------------------------------------

def _data_root(dashboard):
    import os

    root = os.path.abspath(
        os.path.join(os.path.dirname(sys.modules["yomi_core.dashboard"].__file__), "..", "yomi_data")
    )
    os.makedirs(root, exist_ok=True)
    return root


def _ledger_line(action, metadata=None, agent="TELEMETRY"):
    return json.dumps({"agent": agent, "action_type": action, "description": "x", "metadata": metadata or {}})


def test_telemetry_file_that_existed_and_vanished_is_flagged_as_tampering(dashboard):
    import os

    tel_file = os.path.join(_data_root(dashboard), "telemetry_benchmarks.jsonl")
    with open(tel_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"latency_seconds": 1.5, "human_speed_multiplier": "5x", "sub_60s_containment": True}) + "\n")
    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "1.5s"

    os.remove(tel_file)
    dashboard._refresh_telemetry_metrics()
    assert "TAMPERED" in dashboard.latest_ttc
    assert dashboard.speed_multiplier == "TELEMETRY FILE REMOVED"


def test_latency_is_read_from_the_ledger_benchmark_entry(dashboard):
    import os

    ledger = os.path.join(_data_root(dashboard), "yomi_chain_of_custody.jsonl")
    with open(ledger, "w", encoding="utf-8") as f:
        f.write(_ledger_line("BENCHMARK_RECORDED", {
            "latency_seconds": 2.9871, "human_speed_multiplier": "401.7x", "sub_60s_containment": True,
        }) + "\n")
        f.write(_ledger_line("DEPLOYED", agent="SWARM") + "\n")
        f.write("{not valid json\n")

    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "2.9871s"
    assert "401.7x" in dashboard.speed_multiplier
    assert "TAMPERED" not in dashboard.latest_ttc


def test_newest_ledger_benchmark_wins(dashboard):
    import os

    ledger = os.path.join(_data_root(dashboard), "yomi_chain_of_custody.jsonl")
    with open(ledger, "w", encoding="utf-8") as f:
        for latency in (9.0, 1.25):
            f.write(_ledger_line("BENCHMARK_RECORDED", {
                "latency_seconds": latency, "human_speed_multiplier": "1x", "sub_60s_containment": True,
            }) + "\n")
    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "1.25s"


def test_ledger_without_benchmark_leaves_awaiting_state(dashboard):
    import os

    ledger = os.path.join(_data_root(dashboard), "yomi_chain_of_custody.jsonl")
    with open(ledger, "w", encoding="utf-8") as f:
        f.write(_ledger_line("GENESIS", agent="YOMI_AUDIT") + "\n")
    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "AWAITING INCIDENT"


def test_telemetry_location_honors_yomi_data_dir(dashboard, tmp_path, monkeypatch):
    ledger_dir = tmp_path / "var_lib_yomi"
    ledger_dir.mkdir()
    (ledger_dir / "yomi_chain_of_custody.jsonl").write_text(
        _ledger_line("BENCHMARK_RECORDED", {
            "latency_seconds": 0.5, "human_speed_multiplier": "2400x", "sub_60s_containment": True,
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("YOMI_DATA_DIR", str(ledger_dir))
    dashboard._refresh_telemetry_metrics()
    assert dashboard.latest_ttc == "0.5s"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("401.7x (Sub-60s: True)", "401.7x · sub-60s"),
        ("12.0x (Sub-60s: False)", "12.0x · over 60s"),
        ("N/A", "N/A"),
        ("AUDIT LOG COMPROMISED", "AUDIT LOG COMPROMISED"),
    ],
)
def test_speed_summary_is_short_enough_to_display(dashboard, raw, expected):
    dashboard.speed_multiplier = raw
    assert dashboard._speed_summary() == expected


# --------------------------------------------------------------------------
# Event helpers
# --------------------------------------------------------------------------

def test_extract_pid():
    from yomi_core.dashboard import extract_pid

    assert extract_pid("Executed SIGSTOP on PID 4242.") == "4242"
    assert extract_pid("pid=77 gone") == "77"
    assert extract_pid("nothing to see") is None
    assert extract_pid(None) is None
    assert extract_pid("") is None


@pytest.mark.parametrize(
    "agent, action, shown",
    [
        ("SWARM", "DEPLOYED", False),        # per-cycle noise
        ("SHADOW_NET", "DEPLOYED", True),    # a real deployment must be visible
        ("SENTINEL", "UI_START", False),
        ("TELEMETRY", "BENCHMARK_RECORDED", False),
        ("MITRE_MAPPER", "MAPPED", False),
        ("SENTINEL", "AUTONOMOUS_CONTAINMENT", True),
        ("DOSSIER", "REPORT_SIGNED", True),
        ("ANYTHING", "NEVER_SEEN_BEFORE", True),
    ],
)
def test_should_display_event(agent, action, shown):
    from yomi_core.dashboard import should_display_event

    assert should_display_event(agent, action) is shown


@pytest.mark.parametrize(
    "agent, action, description, expected",
    [
        ("SENTINEL", "AUTONOMOUS_CONTAINMENT", "froze it", "CRITICAL"),
        ("X", "CONTAINMENT_FAILED", "", "CRITICAL"),
        ("X", "NOTE", "A critical finding", "CRITICAL"),
        ("SHADOW_NET", "DEPLOYED", "hook deployed", "DECEPTION"),
        ("MIRAGE", "HALLUCINATION_DEPLOYED", "decoy", "DECEPTION"),
        ("X", "NOTE", "MIRAGE decoy placed", "DECEPTION"),
        ("X", "DOUBT_RAISED", "", "WARNING"),
        ("DOSSIER", "REPORT_SIGNED", "signed", "SAFE"),
    ],
)
def test_classify_event(agent, action, description, expected):
    from yomi_core.dashboard import classify_event

    assert classify_event(action, description, agent) == expected


# --------------------------------------------------------------------------
# update_state: PID handling and status hold
# --------------------------------------------------------------------------

def test_update_state_without_pid_keeps_current_target(dashboard):
    dashboard.update_state("SAFE", "1234", recent_log="first")
    dashboard.update_state("SAFE", None, recent_log="no pid in this one")
    assert dashboard.active_pid == "1234"


def test_update_state_picks_up_pid_named_in_the_event(dashboard):
    dashboard.update_state("CRITICAL", None, recent_log="[X] froze PID 4242")
    assert dashboard.active_pid == "4242"


def test_update_state_legacy_auto_placeholder_is_not_shown_as_the_pid(dashboard):
    dashboard.update_state("SAFE", "AUTO", recent_log="routine")
    assert dashboard.active_pid != "AUTO"


def test_critical_status_is_held_against_a_routine_event_that_follows(dashboard):
    from datetime import datetime, timedelta

    t0 = datetime(2026, 1, 1, 12, 0, 0)
    dashboard.update_state("CRITICAL", None, "[A] threat", when=t0)
    dashboard.update_state("SAFE", None, "[B] report signed", when=t0 + timedelta(seconds=5))
    assert dashboard.current_status == "CRITICAL"


def test_held_status_is_released_after_the_hold_window(dashboard):
    from datetime import datetime, timedelta

    t0 = datetime(2026, 1, 1, 12, 0, 0)
    dashboard.update_state("CRITICAL", None, "[A] threat", when=t0)
    dashboard.update_state(
        "SAFE", None, "[B] calm again",
        when=t0 + timedelta(seconds=dashboard.STATUS_HOLD_SECONDS + 1),
    )
    assert dashboard.current_status == "SAFE"


def test_equal_or_higher_severity_replaces_the_status_immediately(dashboard):
    from datetime import datetime, timedelta

    t0 = datetime(2026, 1, 1, 12, 0, 0)
    dashboard.update_state("WARNING", None, "[A] doubt", when=t0)
    dashboard.update_state("CRITICAL", None, "[B] threat", when=t0 + timedelta(seconds=1))
    assert dashboard.current_status == "CRITICAL"


def test_old_critical_does_not_pin_status_when_history_is_replayed(dashboard):
    """Backfill replays old events with their own timestamps: a critical event
    from hours ago must not outrank what happened since."""
    from datetime import datetime, timedelta

    t0 = datetime(2026, 1, 1, 8, 0, 0)
    dashboard.update_state("CRITICAL", None, "[A] old threat", when=t0)
    dashboard.update_state("SAFE", None, "[B] quiet since", when=t0 + timedelta(hours=2))
    assert dashboard.current_status == "SAFE"


def test_log_line_keeps_its_own_severity_while_the_headline_status_is_held(dashboard):
    from datetime import datetime, timedelta

    t0 = datetime(2026, 1, 1, 12, 0, 0)
    dashboard.update_state("CRITICAL", None, "[A] threat", when=t0)
    dashboard.update_state("SAFE", None, "[B] report signed", when=t0 + timedelta(seconds=3))
    dashboard.update_state("DECEPTION", None, "[C] decoy placed", when=t0 + timedelta(seconds=6))

    assert dashboard.current_status == "CRITICAL"  # headline is held ...
    levels = [r["level"] for r in dashboard._log_records]
    assert levels == ["CRIT", "INFO", "DECP"]  # ... but each line shows its own level


# --------------------------------------------------------------------------
# Log records
# --------------------------------------------------------------------------

def test_log_record_splits_leading_tag_from_body(dashboard):
    dashboard.append_log("[REPORT_SIGNED] Generated dossier")
    record = dashboard._log_records[-1]
    assert record["tag"] == "REPORT_SIGNED"
    assert record["body"] == "Generated dossier"


def test_log_record_without_tag_keeps_whole_text_as_body(dashboard):
    dashboard.append_log("plain message")
    record = dashboard._log_records[-1]
    assert record["tag"] == ""
    assert record["body"] == "plain message"


def test_log_uses_event_time_not_current_time(dashboard):
    from datetime import datetime

    dashboard.append_log("[X] from the past", when=datetime(2020, 5, 17, 3, 4, 5))
    assert dashboard._log_records[-1]["time"] == "03:04:05"
    assert "[03:04:05]" in str(dashboard.action_log[-1])


@pytest.mark.parametrize(
    "status, key, level",
    [
        ("CRITICAL", "blood_red", "CRIT"),
        ("DECEPTION", "cyber_purple", "DECP"),
        ("WARNING", "warning", "WARN"),
    ],
)
def test_status_hint_colours_a_line_that_matched_no_keyword(dashboard, status, key, level):
    dashboard.append_log("a neutral sentence", status=status)
    assert dashboard.colors[key] in str(dashboard.action_log[-1].style)
    assert dashboard._log_records[-1]["level"] == level


def test_keyword_still_wins_over_status_hint(dashboard):
    dashboard.append_log("Operation SUCCESS", status="CRITICAL")
    assert dashboard._log_records[-1]["level"] == "OK"


def test_log_records_and_action_log_stay_in_step_at_the_cap(dashboard):
    for i in range(130):
        dashboard.append_log(f"entry {i}")
    assert len(dashboard._log_records) == len(dashboard.action_log) == 100


# --------------------------------------------------------------------------
# Rendering at real terminal sizes
# --------------------------------------------------------------------------

def _render(dashboard, width, height, color=False):
    import io
    from rich.console import Console

    console = Console(
        width=width,
        height=height,
        file=io.StringIO(),
        force_terminal=color,
        color_system="truecolor" if color else None,
        record=True,
    )
    dashboard.console = console
    console.print(dashboard.render_layout())
    return console.export_text()


@pytest.mark.parametrize("size", [(40, 10), (80, 24), (100, 30), (120, 46), (200, 60)])
def test_render_does_not_crash_at_any_terminal_size_with_colour(dashboard, size):
    dashboard.update_state("CRITICAL", None, "[X] froze PID 1")
    text = _render(dashboard, *size, color=True)
    assert "YOMI TRIAGE SYSTEM" in text or size[0] < 60


def test_render_fits_inside_the_terminal(dashboard):
    for i in range(30):
        dashboard.append_log(f"[E{i}] " + "long words " * 20)
    for width, height in [(80, 24), (100, 30), (120, 46)]:
        lines = _render(dashboard, width, height).splitlines()
        assert len(lines) <= height
        assert all(len(line) <= width for line in lines)


def test_80x24_uses_compact_summary_instead_of_the_tall_telemetry_panel(dashboard):
    text = _render(dashboard, 80, 24)
    assert "SENSORS" not in text and "INTELLIGENCE" not in text
    assert "CPU" in text and "CVE" in text


def test_wide_terminal_shows_grouped_telemetry(dashboard):
    text = _render(dashboard, 100, 30)
    for heading in ("INCIDENT", "SENSORS", "HOST", "INTELLIGENCE"):
        assert heading in text


def test_labels_do_not_wrap_in_the_telemetry_panel(dashboard):
    text = _render(dashboard, 100, 30)
    for label in ("Epistemic doubt", "Latency", "Yomi RAM", "CVE records"):
        assert label in text


def test_large_logo_only_on_tall_terminals(dashboard):
    assert "KUROTECH   ████" not in _render(dashboard, 120, 30)
    tall = _render(dashboard, 120, 46)
    assert "████   KUROTECH   ████" in tall
    assert "YOMI TRIAGE SYSTEM" in tall  # the title row must not be cropped away


def test_empty_stream_shows_a_friendly_message(dashboard):
    assert "No incidents recorded yet" in _render(dashboard, 100, 30)


def test_newest_event_is_never_cropped_off_the_bottom(dashboard):
    for i in range(60):
        dashboard.append_log(f"[EVENT_{i}] " + "wrapped description " * 8)
    for width, height in [(80, 24), (90, 20), (120, 36)]:
        text = _render(dashboard, width, height)
        assert "EVENT_59" in text, (width, height)


def test_header_shows_current_status_and_footer_shows_exit_hint(dashboard):
    dashboard.update_telemetry(status="CRITICAL")
    text = _render(dashboard, 100, 30)
    assert "CRITICAL" in text
    assert "Ctrl+C" in text
    assert "no events yet" in text


def test_footer_shows_time_of_last_event(dashboard):
    from datetime import datetime

    dashboard.append_log("[X] something", when=datetime(2026, 1, 1, 9, 8, 7))
    assert "last event 09:08:07" in _render(dashboard, 100, 30)


def test_telemetry_panel_flags_only_real_tampering_in_red(dashboard):
    dashboard.latest_ttc = "[TAMPERED] FILE MISSING"
    text = _render(dashboard, 100, 30, color=True)
    assert "TAMPERED" in text
    dashboard.latest_ttc = "AWAITING INCIDENT"
    assert "TAMPERED" not in _render(dashboard, 100, 30)


# --------------------------------------------------------------------------
# Lazy library start (air-gapped hosts)
# --------------------------------------------------------------------------

def test_lazy_library_builds_off_thread_and_is_shut_down_on_stop(isolated_stamp, tmp_path, monkeypatch):
    import threading

    from yomi_core import dashboard as dashboard_module

    fake_dir = tmp_path / "fake_pkg" / "yomi_core"
    fake_dir.mkdir(parents=True)
    monkeypatch.setattr(dashboard_module, "__file__", str(fake_dir / "dashboard.py"))

    built = threading.Event()
    release = threading.Event()
    shut_down = []

    class FakeLibrary:
        def __init__(self):
            release.wait(timeout=5)  # simulate a slow network probe
            built.set()

        def get_metadata(self):
            return {"count": 1234, "online": False, "last_updated": "x", "source": "LOCAL"}

        def shutdown(self):
            shut_down.append(True)

    monkeypatch.setattr(dashboard_module, "OmniLibrary", FakeLibrary)

    instance = dashboard_module.YomiDashboard(lazy_library=True)  # must not block on the slow probe
    try:
        assert instance.library is None
        assert instance.library_status == "STARTING"
        assert "STARTING" in _render(instance, 100, 30)

        release.set()
        assert built.wait(timeout=5)
        deadline = time.time() + 5
        while instance.library_status == "STARTING" and time.time() < deadline:
            time.sleep(0.05)
        assert instance.library_status == "AIR-GAPPED"
        assert instance.cve_count == 1234
    finally:
        instance.stop()
    assert shut_down == [True]


def test_stop_without_a_library_is_safe(isolated_stamp, tmp_path, monkeypatch):
    from yomi_core import dashboard as dashboard_module

    fake_dir = tmp_path / "fake_pkg" / "yomi_core"
    fake_dir.mkdir(parents=True)
    monkeypatch.setattr(dashboard_module, "__file__", str(fake_dir / "dashboard.py"))

    class BlockingLibrary:
        def __init__(self):
            time.sleep(10)

    monkeypatch.setattr(dashboard_module, "OmniLibrary", BlockingLibrary)
    instance = dashboard_module.YomiDashboard(lazy_library=True)
    instance.stop()  # must return promptly even though the library never finished
    assert instance.library is None


def test_telemetry_keeps_refreshing_while_the_library_is_still_starting(isolated_stamp, tmp_path, monkeypatch):
    """A slow library start (network probe) must not stall the metrics worker."""
    import os
    import threading

    from yomi_core import dashboard as dashboard_module

    fake_dir = tmp_path / "fake_pkg" / "yomi_core"
    fake_dir.mkdir(parents=True)
    monkeypatch.setattr(dashboard_module, "__file__", str(fake_dir / "dashboard.py"))
    data_root = tmp_path / "fake_pkg" / "yomi_data"
    data_root.mkdir(exist_ok=True)
    (data_root / "yomi_chain_of_custody.jsonl").write_text(
        _ledger_line("BENCHMARK_RECORDED", {
            "latency_seconds": 1.0, "human_speed_multiplier": "9x", "sub_60s_containment": True,
        }) + "\n",
        encoding="utf-8",
    )

    release = threading.Event()

    class BlockedLibrary:
        def __init__(self):
            release.wait(timeout=10)

        def shutdown(self):
            pass

    monkeypatch.setattr(dashboard_module, "OmniLibrary", BlockedLibrary)
    instance = dashboard_module.YomiDashboard(lazy_library=True)
    try:
        deadline = time.time() + 5
        while instance.latest_ttc == "AWAITING INCIDENT" and time.time() < deadline:
            time.sleep(0.05)
        assert instance.latest_ttc == "1.0s"
        assert instance.library is None  # still blocked: proves they are independent
    finally:
        release.set()
        instance.stop()
