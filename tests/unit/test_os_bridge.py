"""
Unit tests for yomi_mcp.os_bridge.OSBridge.

Two kinds of coverage here:
1. Tool-detection logic (mocked at the shutil.which boundary -- no real
   SIFT binaries required to run this suite in CI).
2. Real process freeze/thaw behavior (spawns actual short-lived child
   processes and sends real SIGSTOP/SIGCONT -- this is OS-level behavior
   that a mock cannot honestly verify, so we test it for real on Linux).
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from yomi_mcp.os_bridge import OSBridge

LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux", reason="SIGSTOP/SIGCONT behavior is Linux-specific"
)


@pytest.fixture
def bridge_no_tools(monkeypatch):
    """OSBridge with every external tool reporting as unavailable."""
    monkeypatch.setattr("shutil.which", lambda name: None)
    return OSBridge()


@pytest.fixture
def bridge_full_sift(monkeypatch):
    """OSBridge with volatility + fls resolvable, simulating a real SIFT box."""

    def fake_which(name):
        return {"vol.py": "/usr/local/bin/vol.py", "fls": "/usr/bin/fls"}.get(name)

    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    return OSBridge()


def test_no_tools_means_minimal_environment(bridge_no_tools):
    assert bridge_no_tools.can_execute_forensics() is False
    assert bridge_no_tools.is_reduced_mode() is True
    assert bridge_no_tools.is_sift is False


def test_full_sift_toolchain_detected(bridge_full_sift):
    assert bridge_full_sift.is_tool_available("volatility") is True
    assert bridge_full_sift.is_tool_available("fls") is True
    assert bridge_full_sift.can_execute_forensics() is True
    assert bridge_full_sift.environment == "SIFT_LINUX"
    assert bridge_full_sift.is_reduced_mode() is False


def test_untrusted_binary_path_is_rejected_on_linux(monkeypatch):
    if platform.system() != "Linux":
        pytest.skip("trusted-path check only runs on Linux")
    # Simulate a "volatility" binary sitting somewhere untrusted, e.g. /tmp
    # (classic PATH-hijack location) -- OSBridge must refuse it.
    monkeypatch.setattr("shutil.which", lambda name: "/tmp/evil/vol.py" if name == "vol.py" else None)
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    bridge = OSBridge()
    assert bridge.is_tool_available("volatility") is False


def test_get_tool_path_unknown_tool_returns_empty(bridge_no_tools):
    assert bridge_no_tools.get_tool_path("nonexistent_tool") == ""


# --------------------------------------------------------------------------
# Real process freeze/thaw (Linux SIGSTOP/SIGCONT) -- not mocked.
# --------------------------------------------------------------------------

@LINUX_ONLY
def test_cryogenic_freeze_and_thaw_real_process(bridge_no_tools):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.2)  # let it actually start

        result = bridge_no_tools.cryogenic_freeze(proc.pid)
        assert result["status"] == "SUCCESS"
        assert result["action"] == "FROZEN"

        # A stopped process's status in /proc should become 'T' (stopped).
        # Kernel scheduling can take a beat to reflect the state change
        # under a signal, so poll briefly instead of reading once.
        for _ in range(20):
            with open(f"/proc/{proc.pid}/status") as f:
                status = f.read()
            if "State:\tT" in status or "State:  T" in status:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"Process never reached STOPPED state. Last status:\n{status}")

        result = bridge_no_tools.thaw_process(proc.pid)
        assert result["status"] == "SUCCESS"
        assert result["action"] == "THAWED"
    finally:
        proc.kill()
        proc.wait(timeout=5)


@LINUX_ONLY
def test_cryogenic_freeze_refuses_critical_low_pids(bridge_no_tools):
    result = bridge_no_tools.cryogenic_freeze(1)  # init/systemd
    assert result["status"] == "ERROR"
    assert "Blocked" in result["reason"]


@LINUX_ONLY
def test_cryogenic_freeze_refuses_illegal_pid(bridge_no_tools):
    result = bridge_no_tools.cryogenic_freeze(-5)
    assert result["status"] == "ERROR"
    assert "illegal PID" in result["reason"]


@LINUX_ONLY
def test_cryogenic_freeze_refuses_self(bridge_no_tools):
    result = bridge_no_tools.cryogenic_freeze(os.getpid())
    assert result["status"] == "ERROR"
    assert "current or parent process" in result["reason"]


@LINUX_ONLY
def test_freeze_dead_pid_reports_ghost_process(bridge_no_tools):
    # Spawn, let it exit immediately, then try to freeze the now-dead PID.
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    dead_pid = proc.pid
    proc.wait(timeout=5)
    result = bridge_no_tools.cryogenic_freeze(dead_pid)
    assert result["status"] == "GHOST_PROCESS"
