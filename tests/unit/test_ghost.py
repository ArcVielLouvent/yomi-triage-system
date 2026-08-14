"""
Unit tests for yomi_core.ghost.GhostProtocol.

Two real hazards had to be designed around here, not just mocked away:

1. arm_watchdog() installs REAL signal handlers (SIGTERM, SIGHUP) on the
   calling process. Left unguarded, a test that calls this would hijack
   the actual pytest process's signal handling for the rest of the test
   run (or worse, for whatever process runs this suite in CI). Every test
   that touches arm_watchdog() saves the original handler first and
   restores it in a finally block.

2. setproctitle is a real dependency (see requirements.txt) but isn't
   necessarily installed in every environment this test suite runs in.
   Rather than let behavior silently depend on whether it happens to be
   installed locally, both the "installed" and "not installed" code paths
   are forced deterministically via sys.modules manipulation, so the test
   result doesn't depend on the environment's coincidental package list.
"""
from __future__ import annotations

import signal
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def ghost(isolated_stamp):
    from yomi_core.ghost import GhostProtocol

    return GhostProtocol()


@pytest.fixture
def restore_signal_handlers():
    """
    Snapshots SIGTERM/SIGHUP handlers before a test and restores them
    after, regardless of pass/fail -- so arm_watchdog() tests never leak a
    live handler into the rest of the test session.
    """
    original_term = signal.getsignal(signal.SIGTERM)
    original_hup = signal.getsignal(signal.SIGHUP)
    yield
    signal.signal(signal.SIGTERM, original_term)
    signal.signal(signal.SIGHUP, original_hup)


# --------------------------------------------------------------------------
# engage_camouflage
# --------------------------------------------------------------------------

def test_camouflage_with_setproctitle_available(ghost, monkeypatch):
    fake_setproctitle_module = MagicMock()
    monkeypatch.setitem(sys.modules, "setproctitle", fake_setproctitle_module)
    monkeypatch.setattr(ghost, "_deep_linux_camouflage", lambda name: None)  # isolate this path

    ghost.engage_camouflage()

    fake_setproctitle_module.setproctitle.assert_called_once()
    assert ghost.is_camouflaged is True


def test_camouflage_without_setproctitle_falls_back_gracefully(ghost, monkeypatch):
    # Force ImportError regardless of whether it's actually installed here.
    monkeypatch.setitem(sys.modules, "setproctitle", None)
    monkeypatch.setattr(ghost, "_deep_linux_camouflage", lambda name: None)  # isolate

    ghost.engage_camouflage()  # must not raise

    # is_camouflaged stays False from surface-level camouflage specifically
    # (deep camouflage is mocked out above), proving the ImportError path
    # doesn't crash the whole method.


def test_camouflage_uses_windows_fake_name_on_windows(ghost, monkeypatch):
    monkeypatch.setattr(ghost, "os_type", "Windows")
    fake_setproctitle_module = MagicMock()
    monkeypatch.setitem(sys.modules, "setproctitle", fake_setproctitle_module)

    ghost.engage_camouflage()

    fake_setproctitle_module.setproctitle.assert_called_once_with("svchost.exe")


def test_camouflage_uses_linux_fake_name_and_calls_deep_camouflage(ghost, monkeypatch):
    monkeypatch.setattr(ghost, "os_type", "Linux")
    fake_setproctitle_module = MagicMock()
    monkeypatch.setitem(sys.modules, "setproctitle", fake_setproctitle_module)
    deep_calls = []
    monkeypatch.setattr(ghost, "_deep_linux_camouflage", lambda name: deep_calls.append(name))

    ghost.engage_camouflage()

    fake_setproctitle_module.setproctitle.assert_called_once_with("[kworker/u4:2]")
    assert deep_calls == ["[kworker/u4:2]"]


def test_camouflage_seals_action_to_ledger(ghost, isolated_stamp, monkeypatch):
    monkeypatch.setitem(sys.modules, "setproctitle", None)
    monkeypatch.setattr(ghost, "_deep_linux_camouflage", lambda name: None)

    ghost.engage_camouflage()

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 2  # genesis + CAMOUFLAGE_ENGAGED


def test_deep_linux_camouflage_handles_ctypes_failure_gracefully(ghost, monkeypatch, capsys):
    def raise_error(name):
        raise OSError("simulated libc load failure")

    monkeypatch.setattr("ctypes.CDLL", raise_error)
    ghost._deep_linux_camouflage("[kworker/u4:2]")  # must not raise
    captured = capsys.readouterr()
    assert "PRCTL masking failed" in captured.out


@pytest.mark.skipif(sys.platform != "linux", reason="prctl/libc is Linux-specific")
def test_deep_linux_camouflage_real_prctl_changes_proc_comm(ghost):
    """
    One real (non-mocked) test of the actual prctl(PR_SET_NAME) call,
    verified by reading /proc/self/comm -- then restored to the original
    name so this doesn't leak into the rest of the test session's process
    listing.
    """
    original_name = Path("/proc/self/comm").read_text().strip()
    try:
        ghost._deep_linux_camouflage("test-ghost-name")
        new_name = Path("/proc/self/comm").read_text().strip()
        assert new_name == "test-ghost-nam"[:15] or new_name.startswith("test-ghost")
        assert ghost.is_camouflaged is True
    finally:
        ghost._deep_linux_camouflage(original_name)


# --------------------------------------------------------------------------
# arm_watchdog / _tamper_handler
# --------------------------------------------------------------------------

def test_arm_watchdog_on_windows_does_not_install_signal_handlers(ghost, monkeypatch, restore_signal_handlers):
    monkeypatch.setattr(ghost, "os_type", "Windows")
    before = signal.getsignal(signal.SIGTERM)
    ghost.arm_watchdog()
    after = signal.getsignal(signal.SIGTERM)
    assert before == after  # unchanged -- Windows path returns early


@pytest.mark.skipif(sys.platform == "win32", reason="signal.SIGHUP doesn't exist on Windows")
def test_arm_watchdog_on_linux_installs_tamper_handler(ghost, monkeypatch, restore_signal_handlers):
    monkeypatch.setattr(ghost, "os_type", "Linux")
    ghost.arm_watchdog()
    assert signal.getsignal(signal.SIGTERM) == ghost._tamper_handler
    assert signal.getsignal(signal.SIGHUP) == ghost._tamper_handler


def test_tamper_handler_seals_alert_to_ledger_before_exiting(ghost, isolated_stamp):
    with pytest.raises(SystemExit) as exc_info:
        ghost._tamper_handler(signal.SIGTERM, None)
    assert exc_info.value.code == 0

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "TAMPER_ATTEMPT_DETECTED"
    assert lines[-1]["metadata"]["signal"] == signal.SIGTERM


def test_tamper_handler_records_correct_signal_name_for_sighup(ghost, isolated_stamp):
    with pytest.raises(SystemExit):
        ghost._tamper_handler(signal.SIGHUP, None)

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert "SIGHUP" in lines[-1]["description"]
