"""
Unit tests for yomi_engine.sandbox.SandboxEnvironment.

Testing strategy tiers:
1. _validate_binary_path, _secure_containment: pure logic + real file I/O,
   no namespace/root risk -- tested for real.
2. _create_container_overlay: genuinely works in this sandbox (confirmed
   via a direct `mount -t overlay` probe before writing these tests -- this
   container has CAP_SYS_ADMIN) -- tested for REAL, with careful
   umount+rmtree cleanup in a finally block so a failing test never leaves
   a mounted overlay behind.
3. _launch_in_minicontainer: the actual `unshare -n -m -p -f --mount-proc
   chroot ...` launch is NOT executed for real here -- full namespace +
   chroot + process execution is too environment-dependent and risky to
   run unattended in a test suite (could hang, behave inconsistently
   between this sandbox and other CI runners). The root-privilege and
   OS-type guards ARE tested for real (deterministic, no side effects);
   the actual launch command construction is verified via a mocked
   subprocess.Popen instead of actually running it.
4. _monitor_awakened_threat: mirage/mind_reader imports and the actual
   process are all mocked, to verify the orchestration SEQUENCE (deploy
   decoy -> wait/timeout -> teardown decoy -> lock down evidence copy ->
   profile -> cleanup -> ledger) without needing a real sandboxed process.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def sandbox(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import sandbox as sandbox_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(sandbox_module, "__file__", str(fake_module_dir / "sandbox.py"))
    monkeypatch.setattr("shutil.which", lambda name: None)

    return sandbox_module.SandboxEnvironment()


def test_init_creates_isolated_chamber_dir(sandbox, tmp_path):
    expected = tmp_path / "fake_pkg" / "yomi_data" / "lazarus_chamber"
    assert sandbox.chamber_dir == str(expected)
    assert os.path.isdir(sandbox.chamber_dir)


# --------------------------------------------------------------------------
# _validate_binary_path
# --------------------------------------------------------------------------

def test_relative_binary_path_rejected(sandbox):
    valid, error = sandbox._validate_binary_path("relative/malware.bin")
    assert valid is False
    assert "absolute" in error.lower()


def test_nonexistent_binary_path_rejected(sandbox):
    valid, error = sandbox._validate_binary_path("/tmp/nonexistent_malware_xyz.bin")
    assert valid is False
    assert "does not exist" in error.lower()


def test_directory_as_binary_path_rejected(sandbox, tmp_path):
    valid, error = sandbox._validate_binary_path(str(tmp_path))
    assert valid is False
    assert "not a regular file" in error.lower()


def test_valid_binary_path_passes(sandbox, tmp_path):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"fake ELF content")
    valid, error = sandbox._validate_binary_path(str(binary))
    assert valid is True


# --------------------------------------------------------------------------
# _secure_containment: real file copy + permission lockdown
# --------------------------------------------------------------------------

def test_secure_containment_creates_readonly_pristine_copy(sandbox, tmp_path):
    original = tmp_path / "malware.bin"
    original.write_bytes(b"malicious payload bytes")

    result_path = sandbox._secure_containment(str(original), threat_pid=1234)
    assert result_path != "ERROR"
    assert os.path.exists(result_path)
    assert Path(result_path).read_bytes() == b"malicious payload bytes"

    mode = stat.S_IMODE(os.stat(result_path).st_mode)
    assert mode == 0o400


def test_secure_containment_invalid_binary_returns_error_and_logs(sandbox, isolated_stamp):
    result = sandbox._secure_containment("/nonexistent/malware.bin", threat_pid=5678)
    assert result == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "CONTAINMENT_ERROR"


def test_secure_containment_filename_includes_pid_and_is_unique(sandbox, tmp_path):
    original = tmp_path / "sample.bin"
    original.write_bytes(b"x")

    result_1 = sandbox._secure_containment(str(original), threat_pid=9999)
    time.sleep(1.1)  # ensure the timestamp component differs
    result_2 = sandbox._secure_containment(str(original), threat_pid=9999)

    assert "9999" in result_1
    assert result_1 != result_2  # different timestamps -> different filenames


# --------------------------------------------------------------------------
# _create_container_overlay: REAL overlay mount (this sandbox has
# CAP_SYS_ADMIN -- confirmed by direct probe before writing this test)
# --------------------------------------------------------------------------

@pytest.mark.skipif(os.geteuid() != 0, reason="overlay mount requires root/CAP_SYS_ADMIN")
def test_create_container_overlay_real_mount_succeeds(sandbox, tmp_path):
    binary = tmp_path / "sample_target.bin"
    binary.write_bytes(b"#!/bin/sh\necho hello\n")

    result = sandbox._create_container_overlay(str(binary))
    try:
        assert result["status"] == "SUCCESS"
        assert os.path.ismount(result["mount_dir"])

        # The binary must have been copied into the overlay's upperdir,
        # executable, and visible from the mounted root.
        binary_in_overlay = os.path.join(
            result["mount_dir"], "opt", "yomi_sandbox", "sample_target.bin"
        )
        assert os.path.exists(binary_in_overlay)
        mode = stat.S_IMODE(os.stat(binary_in_overlay).st_mode)
        assert mode & stat.S_IXUSR  # executable bit set
    finally:
        sandbox._cleanup_container(result)
        assert not os.path.ismount(result.get("mount_dir", "/nonexistent"))


def test_create_container_overlay_mount_failure_is_handled_gracefully(sandbox, tmp_path, monkeypatch):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"x")

    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=32, cmd=args[0], stderr="mount: simulated failure"
        )

    monkeypatch.setattr("subprocess.run", fake_run)
    result = sandbox._create_container_overlay(str(binary))
    assert result["status"] == "ERROR"
    assert "simulated failure" in result["reason"]


# --------------------------------------------------------------------------
# _launch_in_minicontainer: guards tested for real, launch command verified
# via mock (never actually executed)
# --------------------------------------------------------------------------

def test_launch_rejects_non_linux_host(sandbox, monkeypatch):
    monkeypatch.setattr(sandbox.os_bridge, "os_type", "Windows")
    result = sandbox._launch_in_minicontainer({"mount_dir": "/fake", "binary_relpath": "/x"})
    assert result["status"] == "ERROR"
    assert "Linux hosts" in result["reason"]


def test_launch_rejects_non_root(sandbox, monkeypatch):
    monkeypatch.setattr(sandbox.os_bridge, "os_type", "Linux")
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # simulate non-root
    result = sandbox._launch_in_minicontainer({"mount_dir": "/fake", "binary_relpath": "/x"})
    assert result["status"] == "ERROR"
    assert "Root privileges" in result["reason"]


def test_launch_command_excludes_dash_r_to_prevent_uid_escape(sandbox, monkeypatch):
    """
    Confirms the documented safety claim in the module docstring: "-r"
    (which would map the container's root to a pseudo-root, a known
    namespace-escape vector) must NOT appear in the unshare command.
    """
    monkeypatch.setattr(sandbox.os_bridge, "os_type", "Linux")
    monkeypatch.setattr("os.geteuid", lambda: 0)

    captured_cmd = {}

    def fake_popen(command, **kwargs):
        captured_cmd["cmd"] = command
        fake_proc = MagicMock()
        fake_proc.pid = 99999
        return fake_proc

    monkeypatch.setattr("subprocess.Popen", fake_popen)

    sandbox._launch_in_minicontainer({"mount_dir": "/fake/mount", "binary_relpath": "/payload"})

    cmd = captured_cmd["cmd"]
    assert "-r" not in cmd
    assert cmd[0] == "unshare"
    assert "chroot" in cmd
    assert "/fake/mount" in cmd
    assert "/payload" in cmd


def test_launch_popen_failure_is_caught_not_crashed(sandbox, monkeypatch):
    monkeypatch.setattr(sandbox.os_bridge, "os_type", "Linux")
    monkeypatch.setattr("os.geteuid", lambda: 0)

    def raise_error(*a, **k):
        raise OSError("simulated: unshare binary not found")

    monkeypatch.setattr("subprocess.Popen", raise_error)
    result = sandbox._launch_in_minicontainer({"mount_dir": "/fake", "binary_relpath": "/x"})
    assert result["status"] == "ERROR"


# --------------------------------------------------------------------------
# _cleanup_container / _cleanup_container_forceful
# --------------------------------------------------------------------------

def test_cleanup_removes_all_container_directories(sandbox, tmp_path):
    upper = tmp_path / "upper"
    work = tmp_path / "work"
    mount = tmp_path / "mount"
    for d in (upper, work, mount):
        d.mkdir()

    sandbox._cleanup_container(
        {"upper_dir": str(upper), "work_dir": str(work), "mount_dir": str(mount)}
    )
    assert not upper.exists()
    assert not work.exists()
    assert not mount.exists()


def test_cleanup_survives_umount_failure(sandbox, tmp_path, monkeypatch):
    def raise_error(*a, **k):
        raise subprocess.CalledProcessError(returncode=1, cmd="umount")

    monkeypatch.setattr("subprocess.run", raise_error)
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()

    sandbox._cleanup_container({"mount_dir": str(mount_dir)})  # must not raise
    assert not mount_dir.exists()  # rmtree still happens despite umount failure


def test_cleanup_handles_missing_keys_gracefully(sandbox):
    sandbox._cleanup_container({})  # must not raise (no keys at all)


# --------------------------------------------------------------------------
# execute_resurrection: early-exit validation path (real), full
# orchestration wiring (mocked internals)
# --------------------------------------------------------------------------

def test_execute_resurrection_invalid_binary_short_circuits(sandbox, isolated_stamp):
    result = sandbox.execute_resurrection(1234, "/nonexistent/malware.bin")
    assert result["status"] == "ERROR"
    # Never got past containment -- no RESURRECTION_ACTIVE entry.
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    action_types = [l["action_type"] for l in lines]
    assert "RESURRECTION_ACTIVE" not in action_types


def test_execute_resurrection_overlay_failure_short_circuits(sandbox, tmp_path, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")

    monkeypatch.setattr(
        sandbox, "_create_container_overlay",
        lambda source_path: {"status": "ERROR", "reason": "simulated overlay failure"},
    )
    result = sandbox.execute_resurrection(1234, str(binary))
    assert result["status"] == "ERROR"
    assert "overlay failure" in result["message"]


def test_execute_resurrection_launch_failure_cleans_up_overlay(sandbox, tmp_path, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")

    fake_container_info = {"mount_dir": "/fake/mount", "upper_dir": "/fake/upper", "work_dir": "/fake/work"}
    monkeypatch.setattr(
        sandbox, "_create_container_overlay", lambda source_path: {**fake_container_info, "status": "SUCCESS"}
    )
    monkeypatch.setattr(
        sandbox, "_launch_in_minicontainer",
        lambda container_info: {"status": "ERROR", "reason": "simulated launch failure"},
    )
    cleanup_calls = []
    monkeypatch.setattr(sandbox, "_cleanup_container", lambda info: cleanup_calls.append(info))

    result = sandbox.execute_resurrection(1234, str(binary))
    assert result["status"] == "ERROR"
    assert len(cleanup_calls) == 1  # overlay was cleaned up after launch failed


def test_execute_resurrection_success_spawns_monitoring_thread(sandbox, tmp_path, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")

    monkeypatch.setattr(
        sandbox, "_create_container_overlay",
        lambda source_path: {"status": "SUCCESS", "mount_dir": "/fake/mount"},
    )
    fake_process = MagicMock()
    monkeypatch.setattr(
        sandbox, "_launch_in_minicontainer",
        lambda container_info: {"status": "SUCCESS", "pid": 55555, "process": fake_process},
    )
    # Prevent the real monitoring thread from actually running (it imports
    # mirage/mind_reader and would try real interrogation) -- replace the
    # thread target with a no-op just for this wiring test.
    monkeypatch.setattr(sandbox, "_monitor_awakened_threat", lambda *a, **k: None)

    result = sandbox.execute_resurrection(1234, str(binary))
    assert result["status"] == "SUCCESS"
    assert result["sandbox_pid"] == 55555
    assert 55555 in sandbox.active_sandboxes
    result["thread"].join(timeout=2)  # let the no-op thread finish


# --------------------------------------------------------------------------
# _monitor_awakened_threat: full orchestration sequence, heavily mocked
# --------------------------------------------------------------------------

def test_monitor_awakened_threat_full_sequence(sandbox, tmp_path, monkeypatch, isolated_stamp):
    # MIRAGE requires SANDBOX and is disabled by default -- explicitly
    # enable it for this test since it asserts mirage IS called.
    monkeypatch.setenv("YOMI_MODULE_SANDBOX", "true")
    monkeypatch.setenv("YOMI_MODULE_MIRAGE", "true")
    contained_path = tmp_path / "contained.bin"
    contained_path.write_bytes(b"x")
    contained_path.chmod(0o400)

    fake_mirage = MagicMock()
    fake_mind_reader_instance = MagicMock()
    monkeypatch.setattr(
        "yomi_engine.mirage.MirageProtocol", lambda: fake_mirage
    )
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler", lambda: fake_mind_reader_instance
    )

    fake_process = MagicMock()
    fake_process.communicate.return_value = (b"", b"")

    cleanup_calls = []
    monkeypatch.setattr(sandbox, "_cleanup_container_forceful", lambda info: cleanup_calls.append(info))

    sandbox._monitor_awakened_threat(
        original_pid=1234,
        sandbox_pid=55555,
        contained_path=str(contained_path),
        container_info={"mount_dir": "/fake"},
        process=fake_process,
    )

    fake_mirage.deploy_hallucination.assert_called_once()
    fake_mirage.teardown_hallucination.assert_called_once()
    fake_mind_reader_instance.decompile_and_profile.assert_called_once_with(
        str(contained_path), 1234
    )
    assert len(cleanup_calls) == 1

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "CONTAINER_DESTROYED"

    # Evidence copy locked to 0o500 (execute+read, no write) after analysis.
    mode = stat.S_IMODE(os.stat(contained_path).st_mode)
    assert mode == 0o500


def test_monitor_awakened_threat_kills_process_on_timeout(sandbox, tmp_path, monkeypatch, isolated_stamp):
    monkeypatch.setenv("YOMI_MODULE_SANDBOX", "true")
    monkeypatch.setenv("YOMI_MODULE_MIRAGE", "true")
    contained_path = tmp_path / "contained.bin"
    contained_path.write_bytes(b"x")

    monkeypatch.setattr("yomi_engine.mirage.MirageProtocol", lambda: MagicMock())
    monkeypatch.setattr("yomi_engine.mind_reader.MindReaderDecompiler", lambda: MagicMock())
    monkeypatch.setattr(sandbox, "_cleanup_container_forceful", lambda info: None)

    fake_process = MagicMock()
    fake_process.pid = 55555
    fake_process.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd="chroot", timeout=15),
        (b"", b""),  # second call after kill, to drain pipes
    ]
    killed = {}
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr(
        "os.killpg", lambda pgid, sig: killed.update(pgid=pgid, sig=sig)
    )

    sandbox._monitor_awakened_threat(
        original_pid=1234,
        sandbox_pid=55555,
        contained_path=str(contained_path),
        container_info={"mount_dir": "/fake"},
        process=fake_process,
    )

    assert killed["pgid"] == 55555
    assert fake_process.communicate.call_count == 2


def test_monitor_awakened_threat_respects_disabled_mirage_and_mind_reader(
    sandbox, tmp_path, monkeypatch, isolated_stamp
):
    """
    [FIXED] known_issues.md #29: this method used to call MirageProtocol()
    and MindReaderDecompiler() unconditionally, bypassing module_registry
    entirely. With SANDBOX enabled but MIRAGE and MIND_READER left at
    their real defaults (MIRAGE off, MIND_READER on... explicitly turned
    off here to prove the gate works both ways), neither should be
    touched when disabled.
    """
    monkeypatch.setenv("YOMI_MODULE_SANDBOX", "true")
    monkeypatch.delenv("YOMI_MODULE_MIRAGE", raising=False)  # stays default OFF
    monkeypatch.setenv("YOMI_MODULE_MIND_READER", "false")

    contained_path = tmp_path / "contained.bin"
    contained_path.write_bytes(b"x")

    mirage_cls = MagicMock()
    mind_reader_cls = MagicMock()
    monkeypatch.setattr("yomi_engine.mirage.MirageProtocol", mirage_cls)
    monkeypatch.setattr("yomi_engine.mind_reader.MindReaderDecompiler", mind_reader_cls)
    monkeypatch.setattr(sandbox, "_cleanup_container_forceful", lambda info: None)

    fake_process = MagicMock()
    fake_process.communicate.return_value = (b"", b"")

    sandbox._monitor_awakened_threat(
        original_pid=1234,
        sandbox_pid=55555,
        contained_path=str(contained_path),
        container_info={"mount_dir": "/fake"},
        process=fake_process,
    )

    mirage_cls.assert_not_called()
    mind_reader_cls.assert_not_called()

    # Cleanup and the final ledger entry must still happen regardless.
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "CONTAINER_DESTROYED"
