"""
Unit tests for yomi_engine.shadow_net.ShadowNetProtocol.

__init__ hardcodes recovery_dir relative to __file__ (isolated the usual
way) and imports/constructs the eBPFSentinel singleton -- reset before and
after each test, matching test_ebpf_sensor.py's pattern. Since this
sandbox runs as root, the constructor's real root-check branch actually
attempts eBPFSentinel.arm_sensor() for real (which itself fails
gracefully since bcc isn't installed -- already covered by
test_ebpf_sensor.py). After construction, self.ebpf is replaced with a
MagicMock for tests focused on ShadowNetProtocol's own orchestration
logic, isolating it from eBPF's real behavior.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def shadow_net(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import ebpf_sensor as ebpf_module
    from yomi_engine import shadow_net as shadow_net_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(shadow_net_module, "__file__", str(fake_module_dir / "shadow_net.py"))
    monkeypatch.setattr("shutil.which", lambda name: None)

    ebpf_module.eBPFSentinel._instance = None
    instance = shadow_net_module.ShadowNetProtocol()
    instance.ebpf = MagicMock()  # isolate from real eBPF for orchestration tests
    yield instance
    ebpf_module.eBPFSentinel._instance = None


def test_init_creates_recovery_dir_isolated(shadow_net, tmp_path):
    expected = tmp_path / "fake_pkg" / "yomi_data" / "recovery"
    assert shadow_net.recovery_dir == str(expected)
    assert expected.is_dir()


def test_init_recovery_dir_has_0700_permissions(shadow_net):
    """
    Regression test for a real, reproducible bug: os.umask(0o077) alone
    was insufficient on a filesystem with default POSIX ACLs (confirmed
    on a GitHub Codespaces devcontainer -- deterministically produced
    mode 0o756, WORLD-WRITABLE, not a random/racy value). Per POSIX, a
    directory with a default ACL causes new children to inherit
    permissions from that ACL, bypassing umask calculation entirely.
    __init__ now calls os.chmod(recovery_dir, 0o700) explicitly after
    creation, which guarantees the permission regardless of umask/ACL
    interactions on any filesystem. Asserting the exact mode is
    appropriate again now that it's explicitly enforced rather than
    umask-dependent.
    """
    mode = stat.S_IMODE(os.stat(shadow_net.recovery_dir).st_mode)
    assert mode == 0o700


# --------------------------------------------------------------------------
# _get_process_start_time / _resolve_binary_path (real /proc, using self)
# --------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="/proc is Linux-specific")
def test_get_process_start_time_real_self_pid(shadow_net):
    result = shadow_net._get_process_start_time(os.getpid())
    assert result.isdigit()


def test_get_process_start_time_dead_pid_returns_empty(shadow_net):
    assert shadow_net._get_process_start_time(999999999) == ""


@pytest.mark.skipif(sys.platform != "linux", reason="/proc is Linux-specific")
def test_resolve_binary_path_real_self_process(shadow_net):
    path, is_fileless, raw_path, start_time = shadow_net._resolve_binary_path(os.getpid())
    # sys.executable may be a symlink (e.g. "/usr/bin/python3") while
    # /proc/self/exe resolves to the concrete binary (e.g.
    # "/usr/bin/python3.12") -- both correctly identify this interpreter,
    # so just confirm the resolved path is a real, executable file rather
    # than doing an exact string/basename comparison.
    assert os.path.isfile(path)
    assert os.access(path, os.X_OK)
    assert "python3" in os.path.basename(path)
    assert is_fileless is False
    assert start_time != ""


def test_resolve_binary_path_dead_pid_returns_empty_tuple(shadow_net):
    path, is_fileless, raw_path, start_time = shadow_net._resolve_binary_path(999999999)
    assert path == ""


# --------------------------------------------------------------------------
# deploy_micro_hook
# --------------------------------------------------------------------------

def test_deploy_invalid_pid_aborted_and_logged(shadow_net, isolated_stamp):
    result = shadow_net.deploy_micro_hook(-5, "test reason")
    assert result["status"] == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ABORTED"


def test_deploy_no_ebpf_instance_returns_error(shadow_net):
    shadow_net.ebpf = None
    result = shadow_net.deploy_micro_hook(999999, "reason")
    assert result["status"] == "ERROR"
    assert "not initialized" in result["message"]


def test_deploy_already_active_pid_returns_active_status(shadow_net):
    shadow_net.active_hooks[12345] = "some_thread_placeholder"
    result = shadow_net.deploy_micro_hook(12345, "reason")
    assert result["status"] == "ACTIVE"


def test_deploy_unresolvable_binary_errors_and_cleans_up_hook_entry(shadow_net, monkeypatch):
    monkeypatch.setattr(shadow_net, "_resolve_binary_path", lambda pid: ("", False, "", ""))
    result = shadow_net.deploy_micro_hook(999999, "reason")
    assert result["status"] == "ERROR"
    assert 999999 not in shadow_net.active_hooks  # cleaned up, not left dangling


def test_deploy_success_spawns_thread_and_logs(shadow_net, isolated_stamp, monkeypatch):
    monkeypatch.setattr(
        shadow_net, "_resolve_binary_path", lambda pid: ("/bin/fake", False, "/bin/fake", "12345")
    )
    monkeypatch.setattr(shadow_net, "_monitor_syscalls_safe", lambda *a: None)  # no-op the thread body

    result = shadow_net.deploy_micro_hook(999999, "test reason")
    assert result["status"] == "DEPLOYED"
    result["thread"].join(timeout=2)

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "DEPLOYED" for l in lines)


# --------------------------------------------------------------------------
# _monitor_syscalls_safe: exception isolation + hook cleanup
# --------------------------------------------------------------------------

def test_monitor_safe_catches_exception_and_cleans_up(shadow_net, isolated_stamp, monkeypatch):
    def raise_error(*a, **k):
        raise RuntimeError("simulated monitor crash")

    monkeypatch.setattr(shadow_net, "_monitor_syscalls_logic", raise_error)
    shadow_net.active_hooks[999999] = "placeholder"

    shadow_net._monitor_syscalls_safe(999999, "/bin/x", "/bin/x", False, "1")  # must not raise
    assert 999999 not in shadow_net.active_hooks

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "MONITOR_ERROR"


# --------------------------------------------------------------------------
# _monitor_syscalls_logic
# --------------------------------------------------------------------------

def test_monitor_logic_no_threat_detected_takes_no_action(shadow_net, isolated_stamp):
    shadow_net.ebpf.monitor_pid.return_value = False
    shadow_net._monitor_syscalls_logic(999999, "/bin/x", "/bin/x", False, "100")

    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 1  # genesis only, no escalation


def test_monitor_logic_freeze_failure_stops_early(shadow_net, monkeypatch):
    shadow_net.ebpf.monitor_pid.return_value = True
    monkeypatch.setattr(shadow_net.os_bridge, "cryogenic_freeze", lambda pid: {"status": "ERROR"})
    kill_chain_calls = []
    monkeypatch.setattr(shadow_net, "_execute_kill_chain", lambda *a: kill_chain_calls.append(a))

    shadow_net._monitor_syscalls_logic(999999, "/bin/x", "/bin/x", False, "100")
    assert kill_chain_calls == []  # never reached kill chain


def test_monitor_logic_pid_recycling_detected_thaws_via_os_bridge(shadow_net, isolated_stamp, monkeypatch):
    shadow_net.ebpf.monitor_pid.return_value = True
    monkeypatch.setattr(shadow_net.os_bridge, "cryogenic_freeze", lambda pid: {"status": "SUCCESS"})
    monkeypatch.setattr(shadow_net.os_bridge, "thaw_process", lambda pid: {"status": "SUCCESS"})
    # Start time mismatch -> recycled PID
    monkeypatch.setattr(shadow_net, "_resolve_binary_path", lambda pid: ("/bin/x", False, "/bin/x", "DIFFERENT_START_TIME"))

    shadow_net._monitor_syscalls_logic(999999, "/bin/x", "/bin/x", False, "ORIGINAL_START_TIME")

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "FALSE_POSITIVE_AVOIDED" for l in lines)


def test_monitor_logic_pid_recycling_thaw_fallback_to_raw_sigcont(shadow_net, monkeypatch):
    shadow_net.ebpf.monitor_pid.return_value = True
    monkeypatch.setattr(shadow_net.os_bridge, "cryogenic_freeze", lambda pid: {"status": "SUCCESS"})
    monkeypatch.setattr(shadow_net.os_bridge, "thaw_process", lambda pid: {"status": "ERROR"})
    monkeypatch.setattr(shadow_net, "_resolve_binary_path", lambda pid: ("/bin/x", False, "/bin/x", "DIFFERENT"))

    killed = {}
    monkeypatch.setattr("os.kill", lambda pid, sig: killed.update(pid=pid, sig=sig))

    shadow_net._monitor_syscalls_logic(999999, "/bin/x", "/bin/x", False, "ORIGINAL")
    assert killed == {"pid": 999999, "sig": signal.SIGCONT}


def test_monitor_logic_confirmed_threat_not_recycled_triggers_kill_chain(shadow_net, monkeypatch):
    shadow_net.ebpf.monitor_pid.return_value = True
    monkeypatch.setattr(shadow_net.os_bridge, "cryogenic_freeze", lambda pid: {"status": "SUCCESS"})
    monkeypatch.setattr(shadow_net, "_resolve_binary_path", lambda pid: ("/bin/x", False, "/bin/x", "SAME_TIME"))

    kill_chain_calls = []
    monkeypatch.setattr(shadow_net, "_execute_kill_chain", lambda pid, path, fileless: kill_chain_calls.append((pid, path, fileless)))

    shadow_net._monitor_syscalls_logic(999999, "/bin/x", "/bin/x", False, "SAME_TIME")
    assert kill_chain_calls == [(999999, "/bin/x", False)]


# --------------------------------------------------------------------------
# _execute_kill_chain
# --------------------------------------------------------------------------

def test_kill_chain_seals_threat_neutralized(shadow_net, isolated_stamp, tmp_path, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")

    fake_reverser = MagicMock()
    fake_reverser.generate_rollback_script.return_value = {"status": "SUCCESS", "script_path": "/fake/script.sh"}
    monkeypatch.setattr("yomi_engine.remediator.ReverserEngine", lambda: fake_reverser)

    fake_sandbox = MagicMock()
    fake_sandbox.execute_resurrection.return_value = {"status": "SUCCESS"}
    monkeypatch.setattr("yomi_engine.sandbox.SandboxEnvironment", lambda: fake_sandbox)

    shadow_net._execute_kill_chain(999999, str(binary), is_fileless=False)

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "THREAT_NEUTRALIZED" for l in lines)
    fake_reverser.generate_rollback_script.assert_called_once()
    fake_sandbox.execute_resurrection.assert_called_once_with(999999, str(binary))


def test_kill_chain_missing_binary_triggers_quarantine_escalation(shadow_net, isolated_stamp, monkeypatch):
    monkeypatch.setattr("yomi_engine.remediator.ReverserEngine", lambda: MagicMock())

    # binary_path doesn't exist and is_fileless=False and PID doesn't
    # exist either -- RAM recovery via /proc/{pid}/exe will fail, leaving
    # recovery_source as None -> quarantine escalation path.
    shadow_net._execute_kill_chain(999999999, "/nonexistent/malware.bin", is_fileless=False)

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "QUARANTINE_ESCALATION" for l in lines)


@pytest.mark.skipif(sys.platform != "linux", reason="/proc/[pid]/exe RAM recovery is Linux-specific")
def test_kill_chain_fileless_recovers_real_elf_from_proc_exe(shadow_net, isolated_stamp, monkeypatch):
    """
    Real (non-mocked) ELF recovery test: spawns an actual subprocess and
    has _execute_kill_chain recover ITS /proc/[pid]/exe into the recovery
    vault, confirming the real file-copy path (not just that the branch
    was taken).
    """
    monkeypatch.setattr("yomi_engine.remediator.ReverserEngine", lambda: MagicMock(
        generate_rollback_script=lambda payload: {"status": "SUCCESS", "script_path": "/fake"}
    ))
    fake_sandbox = MagicMock()
    fake_sandbox.execute_resurrection.return_value = {"status": "SUCCESS"}
    monkeypatch.setattr("yomi_engine.sandbox.SandboxEnvironment", lambda: fake_sandbox)

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.2)
        shadow_net._execute_kill_chain(proc.pid, "/memfd:fake", is_fileless=True)

        fake_sandbox.execute_resurrection.assert_called_once()
        call_args = fake_sandbox.execute_resurrection.call_args[0]
        recovered_path = call_args[1]
        assert os.path.exists(recovered_path)
        assert os.path.getsize(recovered_path) > 0

        import stat as stat_module
        mode = stat_module.S_IMODE(os.stat(recovered_path).st_mode)
        assert mode == 0o700
    finally:
        proc.kill()
        proc.wait(timeout=5)
