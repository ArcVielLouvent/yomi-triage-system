"""
Tests for the TUI plumbing in yomi_core/cli.py.

Importing yomi_core.cli installs SIGINT/SIGTERM handlers; they are restored
right after the import so Ctrl+C keeps working for the rest of the pytest run.

The loop itself is exercised with a recording stand-in for rich's Live and for
YomiDashboard, driven by a small temporary ledger -- the real rendering has its
own tests in test_dashboard.py.
"""
from __future__ import annotations

import json
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_saved_handlers = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
from yomi_core import cli  # noqa: E402

signal.signal(signal.SIGINT, _saved_handlers[0])
signal.signal(signal.SIGTERM, _saved_handlers[1])


def _entry(index: int, agent: str = "SENTINEL", action: str = "NOTE", description: str = "d") -> dict:
    return {
        "hash": f"hash-{index:04d}",
        "agent": agent,
        "action_type": action,
        "description": description,
        "timestamp_utc": datetime(2026, 1, 1, 12, 0, index % 60, tzinfo=timezone.utc).isoformat(),
    }


def _write_ledger(path: Path, entries: list[dict]) -> None:
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    path.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli, "validate_data_store", lambda: {"ledger_file": str(path)})
    return path


# --------------------------------------------------------------------------
# _get_new_ledger_logs
# --------------------------------------------------------------------------

def test_first_call_returns_only_the_latest_entry_by_default(ledger):
    _write_ledger(ledger, [_entry(i) for i in range(5)])
    result = cli._get_new_ledger_logs("")
    assert [e["hash"] for e in result] == ["hash-0004"]


def test_backfill_returns_recent_history_in_order(ledger):
    _write_ledger(ledger, [_entry(i) for i in range(10)])
    result = cli._get_new_ledger_logs("", backfill=4)
    assert [e["hash"] for e in result] == ["hash-0006", "hash-0007", "hash-0008", "hash-0009"]


def test_backfill_larger_than_ledger_returns_everything(ledger):
    _write_ledger(ledger, [_entry(i) for i in range(3)])
    assert len(cli._get_new_ledger_logs("", backfill=60)) == 3


def test_known_hash_returns_only_newer_entries(ledger):
    _write_ledger(ledger, [_entry(i) for i in range(6)])
    result = cli._get_new_ledger_logs("hash-0002", backfill=60)
    assert [e["hash"] for e in result] == ["hash-0003", "hash-0004", "hash-0005"]


def test_unknown_hash_falls_back_to_backfill(ledger):
    _write_ledger(ledger, [_entry(i) for i in range(6)])
    result = cli._get_new_ledger_logs("not-in-ledger", backfill=2)
    assert [e["hash"] for e in result] == ["hash-0004", "hash-0005"]


def test_empty_ledger_returns_nothing(ledger):
    assert cli._get_new_ledger_logs("") == []
    assert cli._get_new_ledger_logs("", backfill=5) == []


@pytest.mark.parametrize("bad", [0, -3])
def test_nonpositive_backfill_is_treated_as_one(ledger, bad):
    _write_ledger(ledger, [_entry(i) for i in range(4)])
    assert len(cli._get_new_ledger_logs("", backfill=bad)) == 1


# --------------------------------------------------------------------------
# _quiet_stdio / _ledger_event_time
# --------------------------------------------------------------------------

def test_quiet_stdio_swallows_prints_and_restores_streams(capsys):
    before = (sys.stdout, sys.stderr)
    with cli._quiet_stdio():
        print("engine chatter that must not reach the screen")
        print("stderr chatter", file=sys.stderr)
    assert (sys.stdout, sys.stderr) == before
    captured = capsys.readouterr()
    assert "engine chatter" not in captured.out
    assert "stderr chatter" not in captured.err


def test_quiet_stdio_restores_streams_even_when_the_body_raises():
    before = (sys.stdout, sys.stderr)
    with pytest.raises(RuntimeError):
        with cli._quiet_stdio():
            raise RuntimeError("boom")
    assert (sys.stdout, sys.stderr) == before


def test_ledger_event_time_parses_utc_stamp_to_local_time():
    result = cli._ledger_event_time({"timestamp_utc": "2026-01-01T12:00:05+00:00"})
    assert isinstance(result, datetime)
    assert result.tzinfo is not None
    assert result.astimezone(timezone.utc).strftime("%H:%M:%S") == "12:00:05"


@pytest.mark.parametrize("entry", [{}, {"timestamp_utc": None}, {"timestamp_utc": "not a date"}])
def test_ledger_event_time_returns_none_for_unusable_stamps(entry):
    assert cli._ledger_event_time(entry) is None


# --------------------------------------------------------------------------
# _run_tui_loop
# --------------------------------------------------------------------------

class _FakeLive:
    """Records how Live is configured and behaves as a plain context manager."""

    instances: list = []

    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs
        _FakeLive.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDashboard:
    instances: list = []

    def __init__(self, lazy_library: bool = False):
        self.lazy_library = lazy_library
        self.updates: list = []
        self.stopped = False
        self.stdout_during_run = None
        _FakeDashboard.instances.append(self)

    console = object()

    def render_layout(self):
        return "layout"

    def update_state(self, status, pid, recent_log, when=None):
        self.updates.append({"status": status, "pid": pid, "log": recent_log, "when": when})
        self.stdout_during_run = sys.stdout
        if len(self.updates) >= self.expected:
            cli._global_shutdown_event.set()

    def stop(self):
        self.stopped = True


@pytest.fixture
def tui_env(ledger, monkeypatch):
    import yomi_core.dashboard as dashboard_module

    _FakeLive.instances = []
    _FakeDashboard.instances = []
    monkeypatch.setattr(cli, "Live", _FakeLive)
    monkeypatch.setattr(dashboard_module, "YomiDashboard", _FakeDashboard)
    cli._global_shutdown_event.clear()
    yield ledger
    cli._global_shutdown_event.clear()


def _run(expected_updates: int):
    _FakeDashboard.expected = expected_updates
    # If the loop never reaches the expected number of updates, don't hang.
    import threading

    watchdog = threading.Timer(10, cli._global_shutdown_event.set)
    watchdog.start()
    try:
        cli._run_tui_loop(MagicMock(), str(cli.validate_data_store()["ledger_file"]))
    finally:
        watchdog.cancel()
    return _FakeDashboard.instances[0]


def test_tui_loop_configures_live_for_smooth_redraws(tui_env):
    _write_ledger(tui_env, [_entry(1, action="REPORT_SIGNED")])
    tui = _run(1)
    live = _FakeLive.instances[0]
    # get_renderable makes Live rebuild the layout on every refresh, so
    # metrics keep moving between ledger events.
    assert live.kwargs["get_renderable"] == tui.render_layout
    assert live.kwargs["screen"] is True
    assert live.kwargs["refresh_per_second"] == 4
    # Stray prints from engine threads must not be injected into the screen.
    assert live.kwargs["redirect_stdout"] is False
    assert live.kwargs["redirect_stderr"] is False


def test_tui_loop_builds_the_dashboard_with_a_lazy_library(tui_env):
    _write_ledger(tui_env, [_entry(1, action="REPORT_SIGNED")])
    assert _run(1).lazy_library is True


def test_tui_loop_replays_recent_history_with_original_timestamps(tui_env):
    _write_ledger(tui_env, [_entry(i, action="REPORT_SIGNED", description=f"event {i}") for i in range(1, 8)])
    tui = _run(7)
    assert [u["log"] for u in tui.updates] == [f"[REPORT_SIGNED] event {i}" for i in range(1, 8)]
    assert all(isinstance(u["when"], datetime) for u in tui.updates)
    assert tui.updates[0]["when"] < tui.updates[-1]["when"]


def test_tui_loop_hides_noise_but_keeps_real_deployments(tui_env):
    _write_ledger(tui_env, [
        _entry(1, agent="SWARM", action="DEPLOYED", description="sweep"),
        _entry(2, agent="SHADOW_NET", action="DEPLOYED", description="hook on PID 9"),
        _entry(3, agent="TELEMETRY", action="BENCHMARK_RECORDED", description="bench"),
        _entry(4, agent="DOSSIER", action="REPORT_SIGNED", description="signed"),
    ])
    tui = _run(2)
    assert [u["log"] for u in tui.updates] == [
        "[DEPLOYED] hook on PID 9",
        "[REPORT_SIGNED] signed",
    ]


def test_tui_loop_classifies_events_and_leaves_pid_to_the_dashboard(tui_env):
    _write_ledger(tui_env, [
        _entry(1, agent="SENTINEL", action="AUTONOMOUS_CONTAINMENT", description="froze PID 4242"),
        _entry(2, agent="SHADOW_NET", action="DEPLOYED", description="hook"),
        _entry(3, agent="DOSSIER", action="REPORT_SIGNED", description="signed"),
    ])
    tui = _run(3)
    assert [u["status"] for u in tui.updates] == ["CRITICAL", "DECEPTION", "SAFE"]
    # pid None: the dashboard extracts it from the event text itself.
    assert all(u["pid"] is None for u in tui.updates)


def test_tui_loop_silences_stdout_while_running_and_restores_it(tui_env):
    _write_ledger(tui_env, [_entry(1, action="REPORT_SIGNED")])
    before = sys.stdout
    tui = _run(1)
    assert tui.stdout_during_run is not before
    assert sys.stdout is before


def test_tui_loop_stops_the_dashboard_on_exit(tui_env):
    _write_ledger(tui_env, [_entry(1, action="REPORT_SIGNED")])
    assert _run(1).stopped is True


def test_tui_loop_keeps_going_when_the_ledger_read_fails(tui_env, monkeypatch):
    _write_ledger(tui_env, [_entry(1, action="REPORT_SIGNED")])
    calls = {"n": 0}
    real = cli._get_new_ledger_logs

    def flaky(last_hash, backfill=1):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("transient")
        return real(last_hash, backfill=backfill)

    monkeypatch.setattr(cli, "_get_new_ledger_logs", flaky)
    # The first read fails; the failed pass must not stop the UI, and the
    # entry is delivered once a later pass succeeds. Force a size change so a
    # second pass happens.
    import threading

    def bump():
        with open(tui_env, "a", encoding="utf-8") as f:
            f.write(json.dumps(_entry(2, action="REPORT_SIGNED", description="later")) + "\n")

    threading.Timer(0.8, bump).start()
    tui = _run(1)
    assert tui.updates, "UI should recover after a transient ledger error"
