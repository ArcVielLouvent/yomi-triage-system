"""
Unit tests for yomi_engine.ebpf_sensor.eBPFSentinel.

Real eBPF/bcc requires a Linux kernel + root + the `bcc` package, none of
which are assumed present in CI. Two testing strategies used here:

1. arm_sensor()'s ImportError fallback path is tested for REAL -- `bcc`
   genuinely isn't installed in this environment, so this naturally
   exercises the real fallback rather than needing to mock an ImportError.

2. monitor_pid()'s threat-detection logic (the actual security-relevant
   business logic: which file accesses/exec'd binaries count as a threat,
   false-positive filtering, containment on detection) lives inside a
   closure (`print_event`) that's normally only invoked by bcc's real perf
   buffer polling. It's captured here by mocking self.bpf_instance and
   intercepting the callback passed to `open_perf_buffer()`, then invoking
   that captured callback directly with a fake event object -- this
   exercises the real detection logic without needing a real kernel.
"""
from __future__ import annotations

import signal
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def sensor(isolated_stamp, monkeypatch):
    from yomi_engine import ebpf_sensor as ebpf_module

    monkeypatch.setattr("shutil.which", lambda name: None)
    ebpf_module.eBPFSentinel._instance = None
    instance = ebpf_module.eBPFSentinel()
    yield instance
    ebpf_module.eBPFSentinel._instance = None


class FakeEvent:
    """Stands in for the ctypes struct bcc would normally hand to print_event."""

    def __init__(self, pid: int, event_type: int, filename: str):
        self.pid = pid
        self.event_type = event_type
        self.filename = filename.encode("utf-8")


# --------------------------------------------------------------------------
# Singleton contract
# --------------------------------------------------------------------------

def test_singleton_returns_same_instance(sensor):
    from yomi_engine.ebpf_sensor import eBPFSentinel

    assert eBPFSentinel() is sensor


# --------------------------------------------------------------------------
# arm_sensor
# --------------------------------------------------------------------------

def test_arm_sensor_rejects_unsupported_os(sensor, monkeypatch):
    monkeypatch.setattr(sensor.os_bridge, "environment", "WINDOWS")
    assert sensor.arm_sensor() is False
    assert sensor.is_armed is False


def test_arm_sensor_fails_gracefully_when_bcc_not_installed(sensor, monkeypatch):
    # bcc genuinely isn't installed in this test environment -- this
    # exercises the real ImportError fallback, not a simulated one.
    monkeypatch.setattr(sensor.os_bridge, "environment", "LINUX")
    result = sensor.arm_sensor()
    assert result is False
    assert sensor.is_armed is False


def test_arm_sensor_short_circuits_when_already_armed(sensor, monkeypatch):
    sensor.is_armed = True
    sensor.bpf_instance = MagicMock()  # pretend a real BPF instance exists

    # If this actually attempted to re-arm, it would hit the bcc import
    # and fail differently -- returning True immediately proves the
    # short-circuit fired instead.
    assert sensor.arm_sensor() is True


# --------------------------------------------------------------------------
# monitor_pid: guard clause
# --------------------------------------------------------------------------

def test_monitor_pid_without_arming_returns_false(sensor):
    assert sensor.is_armed is False
    assert sensor.monitor_pid(1234, duration_sec=1) is False


# --------------------------------------------------------------------------
# monitor_pid: threat-detection logic (via captured print_event callback)
# --------------------------------------------------------------------------

@pytest.fixture
def armed_sensor_with_captured_callback(sensor, monkeypatch):
    """
    Arms the sensor with a fully mocked bpf_instance, runs monitor_pid for
    a near-zero duration (so the real polling loop exits almost
    immediately), and returns the captured print_event callback so tests
    can invoke it directly with fake events.
    """
    sensor.is_armed = True
    fake_bpf = MagicMock()

    class _FakeTrackedPidsTable:
        """Real bcc tables accept ctypes keys (which aren't hashable in
        plain Python) via a custom C-level __setitem__/__delitem__ -- a
        plain dict can't stand in for that. This no-op table is enough
        since these tests don't care about tracked_pids' actual content."""

        def __setitem__(self, key, value):
            pass

        def __delitem__(self, key):
            pass

    fake_bpf.get_table.return_value = _FakeTrackedPidsTable()

    captured = {}

    def fake_open_perf_buffer(callback):
        captured["callback"] = callback

    fake_events_table = MagicMock()
    fake_events_table.open_perf_buffer = fake_open_perf_buffer
    fake_events_table.event = lambda data: data  # pass fake event straight through

    fake_bpf.__getitem__ = lambda self, key: fake_events_table
    fake_bpf.perf_buffer_poll = MagicMock()
    sensor.bpf_instance = fake_bpf

    sensor.monitor_pid(999999, duration_sec=0)  # captures callback, loop exits immediately
    return captured["callback"]


def test_shadow_file_access_triggers_alert_and_containment(
    armed_sensor_with_captured_callback, isolated_stamp, monkeypatch
):
    killed = {}
    monkeypatch.setattr("os.kill", lambda pid, sig: killed.update(pid=pid, sig=sig))

    event = FakeEvent(pid=5000, event_type=1, filename="/etc/shadow")
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)

    assert killed == {"pid": 5000, "sig": signal.SIGSTOP}

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    action_types = [l["action_type"] for l in lines]
    assert "AUTONOMOUS_CONTAINMENT" in action_types
    assert "THREAT_DETECTED_OPENAT" in action_types


def test_benign_file_access_does_not_trigger_alert(
    armed_sensor_with_captured_callback, isolated_stamp
):
    event = FakeEvent(pid=5001, event_type=1, filename="/home/user/document.txt")
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 1  # genesis only, no alert


def test_critical_shell_execve_triggers_alert(
    armed_sensor_with_captured_callback, isolated_stamp
):
    event = FakeEvent(pid=5002, event_type=2, filename="/bin/bash")
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "THREAT_DETECTED_EXECVE"


def test_benign_execve_does_not_trigger_alert(
    armed_sensor_with_captured_callback, isolated_stamp
):
    event = FakeEvent(pid=5003, event_type=2, filename="/usr/bin/python3")
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 1  # genesis only


def test_yomis_own_process_cmdline_is_excluded_from_detection(
    armed_sensor_with_captured_callback, isolated_stamp, monkeypatch
):
    # Simulates Yomi's own volatility subprocess touching /etc/shadow-like
    # paths during legitimate forensic analysis -- must not self-alert.
    real_open = open  # captured BEFORE patching, to avoid self-referential recursion

    def fake_open(path, *a, **k):
        if "cmdline" in str(path):
            import io
            return io.StringIO("volatility --profile")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)

    event = FakeEvent(pid=5004, event_type=1, filename="/etc/shadow")
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 1  # genesis only -- self-excluded


def test_hackathon_sample_data_paths_are_excluded(
    armed_sensor_with_captured_callback, isolated_stamp
):
    event = FakeEvent(
        pid=5005, event_type=1, filename="/data/sans_hackathon/shadow_sample"
    )
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 1  # genesis only


def test_sigstop_failure_is_caught_but_threat_still_logged(
    armed_sensor_with_captured_callback, isolated_stamp, monkeypatch
):
    def raise_error(pid, sig):
        raise PermissionError("simulated: cannot signal this PID")

    monkeypatch.setattr("os.kill", raise_error)

    event = FakeEvent(pid=5006, event_type=1, filename="/root/.ssh/authorized_keys")
    armed_sensor_with_captured_callback(cpu=0, data=event, size=0)  # must not raise

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    action_types = [l["action_type"] for l in lines]
    assert "AUTONOMOUS_CONTAINMENT" not in action_types  # SIGSTOP failed
    assert "THREAT_DETECTED_OPENAT" in action_types  # but still logged
