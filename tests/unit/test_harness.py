"""
Unit tests for yomi_mcp.harness.YomiHarness.

This is the architectural (not prompt-based) guardrail -- the actual
location of the "PID 1 is hardblocked in Python, not just asked nicely via
prompt" claim made throughout the project's documentation. Tested heavily
because everything upstream (Router's LLM cascade) is explicitly untrusted
input by design; this is the last line of defense.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import psutil
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def harness(isolated_stamp, monkeypatch):
    from yomi_mcp.harness import YomiHarness

    monkeypatch.setattr("shutil.which", lambda name: None)  # no real tools needed
    return YomiHarness()


# --------------------------------------------------------------------------
# _veto_check: schema validation
# --------------------------------------------------------------------------

def test_non_string_action_is_vetoed(harness):
    result = harness._veto_check({"action": 12345, "target_pid": 999999})
    assert result["is_vetoed"] is True
    assert "must be a valid string" in result["reason"]


def test_disallowed_action_is_vetoed(harness):
    result = harness._veto_check({"action": "delete_everything", "target_pid": 999999})
    assert result["is_vetoed"] is True
    assert "denied" in result["reason"]


def test_missing_target_pid_is_vetoed(harness):
    result = harness._veto_check({"action": "freeze"})
    assert result["is_vetoed"] is True
    assert "requires a 'target_pid'" in result["reason"]


def test_non_integer_target_pid_is_vetoed(harness):
    result = harness._veto_check({"action": "freeze", "target_pid": "not_a_number"})
    assert result["is_vetoed"] is True
    assert "strict integer" in result["reason"]


def test_action_matching_is_case_insensitive_and_trimmed(harness, monkeypatch):
    monkeypatch.setattr(harness, "_is_critical_system_pid", lambda pid: False)
    result = harness._veto_check({"action": "  FREEZE  ", "target_pid": 999999})
    assert result["is_vetoed"] is False


# --------------------------------------------------------------------------
# _is_critical_system_pid: the actual architectural guardrail
# --------------------------------------------------------------------------

def test_pids_100_and_below_are_always_protected(harness):
    for pid in [0, 1, 50, 100]:
        assert harness._is_critical_system_pid(pid) is True


def test_pid_101_is_not_automatically_protected(harness, monkeypatch):
    fake_proc = MagicMock()
    fake_proc.exe.return_value = "/home/user/my_malware"
    monkeypatch.setattr("psutil.Process", lambda pid: fake_proc)
    assert harness._is_critical_system_pid(101) is False


def test_kernel_thread_with_no_exe_path_is_protected(harness, monkeypatch):
    fake_proc = MagicMock()
    fake_proc.exe.return_value = ""  # kernel threads have no on-disk binary
    monkeypatch.setattr("psutil.Process", lambda pid: fake_proc)
    assert harness._is_critical_system_pid(999) is True


def test_critical_binary_in_safe_dir_is_protected(harness, monkeypatch):
    fake_proc = MagicMock()
    fake_proc.exe.return_value = "/usr/sbin/sshd"
    monkeypatch.setattr("psutil.Process", lambda pid: fake_proc)
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    assert harness._is_critical_system_pid(999) is True


def test_process_named_like_critical_binary_but_outside_safe_dir_is_NOT_protected(harness, monkeypatch):
    # A malware sample named "sshd" sitting in /tmp should NOT get the
    # free pass real /usr/sbin/sshd gets -- name alone is not enough.
    fake_proc = MagicMock()
    fake_proc.exe.return_value = "/tmp/evil/sshd"
    monkeypatch.setattr("psutil.Process", lambda pid: fake_proc)
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    assert harness._is_critical_system_pid(999) is False


def test_deleted_binary_suffix_is_stripped_before_path_check(harness, monkeypatch):
    fake_proc = MagicMock()
    fake_proc.exe.return_value = "/usr/bin/docker (deleted)"
    monkeypatch.setattr("psutil.Process", lambda pid: fake_proc)
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    assert harness._is_critical_system_pid(999) is True


def test_symlink_masquerade_is_defeated_by_realpath_resolution(harness, monkeypatch):
    # Malware placed a symlink at /usr/bin/sshd pointing to its own payload
    # in /tmp -- proc.exe() reports the symlink path, but realpath()
    # resolves to the true (untrusted) location.
    fake_proc = MagicMock()
    fake_proc.exe.return_value = "/usr/bin/sshd"
    monkeypatch.setattr("psutil.Process", lambda pid: fake_proc)
    monkeypatch.setattr("os.path.realpath", lambda p: "/tmp/evil/real_payload")
    assert harness._is_critical_system_pid(999) is False


def test_access_denied_fails_safe_to_protected(harness, monkeypatch):
    def raise_access_denied(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr("psutil.Process", raise_access_denied)
    assert harness._is_critical_system_pid(999) is True


def test_no_such_process_fails_safe_to_protected(harness, monkeypatch):
    # Documented current behavior: a PID that no longer exists is treated
    # as "protected" (vetoed) rather than allowed through to os_bridge's
    # own GHOST_PROCESS handling. Conservative, but means a legitimate
    # freeze attempt on an already-exited process gets a veto reason
    # message ("classified as a protected critical OS process") that's
    # misleading about WHY it was blocked.
    def raise_no_such_process(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr("psutil.Process", raise_no_such_process)
    assert harness._is_critical_system_pid(999) is True


# --------------------------------------------------------------------------
# process_intent: end-to-end schema validation + routing
# --------------------------------------------------------------------------

def test_invalid_json_is_rejected_not_crashed(harness):
    result = harness.process_intent("this is not json at all {{{")
    assert result["status"] == "ERROR"
    assert "not a valid JSON intent" in result["message"]


def test_json_array_instead_of_object_is_rejected(harness):
    result = harness.process_intent('["freeze", 1234]')
    assert result["status"] == "ERROR"


def test_vetoed_intent_is_sealed_to_ledger(harness, isolated_stamp):
    harness.process_intent(json.dumps({"action": "freeze", "target_pid": 1}))
    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 2  # genesis + VETO_ENGAGED

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "VETO_ENGAGED"


def test_authorized_freeze_routes_to_os_bridge(harness, monkeypatch):
    fake_bridge = MagicMock()
    fake_bridge.cryogenic_freeze.return_value = {"status": "SUCCESS", "action": "FROZEN"}
    harness.os_bridge = fake_bridge
    monkeypatch.setattr(harness, "_is_critical_system_pid", lambda pid: False)

    result = harness.process_intent(json.dumps({"action": "freeze", "target_pid": 5555}))
    fake_bridge.cryogenic_freeze.assert_called_once_with(5555)
    assert result["status"] == "SUCCESS"


def test_authorized_thaw_routes_to_os_bridge(harness, monkeypatch):
    fake_bridge = MagicMock()
    fake_bridge.thaw_process.return_value = {"status": "SUCCESS", "action": "THAWED"}
    harness.os_bridge = fake_bridge
    monkeypatch.setattr(harness, "_is_critical_system_pid", lambda pid: False)

    result = harness.process_intent(json.dumps({"action": "thaw", "target_pid": 5555}))
    fake_bridge.thaw_process.assert_called_once_with(5555)
    assert result["status"] == "SUCCESS"


# --------------------------------------------------------------------------
# One real end-to-end test: no mocks on the OS layer, actual subprocess.
# --------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="real SIGSTOP/SIGCONT is Linux-specific")
def test_real_end_to_end_freeze_via_harness(harness):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.2)
        result = harness.process_intent(
            json.dumps({"action": "freeze", "target_pid": proc.pid})
        )
        assert result["status"] == "SUCCESS"

        for _ in range(20):
            with open(f"/proc/{proc.pid}/status") as f:
                status = f.read()
            if "State:\tT" in status:
                break
            time.sleep(0.05)
        else:
            pytest.fail("Process was never actually frozen end-to-end through harness.")
    finally:
        proc.kill()
        proc.wait(timeout=5)
