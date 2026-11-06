"""
Unit tests for yomi_engine.mirage.MirageProtocol.

teardown_hallucination's "Absolute Security Boundary Check" used to be a
plain-string ``.startswith(self.mirage_dir)``, which treats a sibling such as
"/mirage_env_EVIL" as inside "/mirage_env" (known issue #16). Not exploitable
through the public API (target_path is built from an int-cast pid and a fixed
prefix), but fixed anyway as defense in depth: the check is now
``MirageProtocol._is_inside_mirage_dir()`` -- real path containment on
resolved paths -- and the tests below cover the sibling-prefix, "..", root
and escaping-symlink cases.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def mirage(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import mirage as mirage_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(mirage_module, "__file__", str(fake_module_dir / "mirage.py"))
    monkeypatch.delenv("YOMI_ENABLE_MIRAGE_MODE", raising=False)

    return mirage_module.MirageProtocol()


def test_init_creates_mirage_dir_in_isolated_location(mirage, tmp_path):
    assert mirage.mirage_dir == str(
        tmp_path / "fake_pkg" / "yomi_data" / "lazarus_chamber" / "mirage_env"
    )
    assert os.path.isdir(mirage.mirage_dir)


# --------------------------------------------------------------------------
# deploy_hallucination: env-var gate (Module Registry pattern)
# --------------------------------------------------------------------------

def test_deploy_skipped_by_default_without_force_enable(mirage):
    result = mirage.deploy_hallucination(1234)
    assert result["status"] == "SKIPPED"
    assert "YOMI_ENABLE_MIRAGE_MODE" in result["reason"]


def test_deploy_proceeds_with_force_enable_true(mirage):
    result = mirage.deploy_hallucination(1234, force_enable=True)
    assert result["status"] == "SUCCESS"


def test_deploy_proceeds_when_env_var_set(mirage, monkeypatch):
    monkeypatch.setenv("YOMI_ENABLE_MIRAGE_MODE", "true")
    result = mirage.deploy_hallucination(1234)
    assert result["status"] == "SUCCESS"


def test_invalid_pid_is_rejected_and_logged(mirage, isolated_stamp):
    import json

    result = mirage.deploy_hallucination("not_a_pid", force_enable=True)
    assert result["status"] == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ABORTED"


def test_zero_or_negative_pid_is_rejected(mirage):
    for bad_pid in [0, -1, -999]:
        result = mirage.deploy_hallucination(bad_pid, force_enable=True)
        assert result["status"] == "ERROR"


# --------------------------------------------------------------------------
# _generate_linux_mirage / _generate_windows_mirage: content + permissions
# --------------------------------------------------------------------------

def test_linux_mirage_creates_decoy_shadow_and_ssh_key_with_0600(mirage):
    result = mirage.deploy_hallucination(5000, "LINUX", force_enable=True)
    assert result["status"] == "SUCCESS"

    shadow_path = Path(result["mirage_path"]) / "etc" / "shadow"
    key_path = Path(result["mirage_path"]) / "root" / ".ssh" / "id_rsa"
    assert shadow_path.exists()
    assert key_path.exists()
    assert "DECOY.HASH.DO.NOT.USE.YOMI" in shadow_path.read_text()

    if sys.platform != "win32":
        import stat as stat_module
        assert stat_module.S_IMODE(shadow_path.stat().st_mode) == 0o600
        assert stat_module.S_IMODE(key_path.stat().st_mode) == 0o600


def test_windows_mirage_creates_decoy_sam_and_document(mirage):
    result = mirage.deploy_hallucination(5000, "WINDOWS", force_enable=True)
    assert result["status"] == "SUCCESS"

    sam_path = Path(result["mirage_path"]) / "Windows" / "System32" / "config" / "SAM"
    doc_path = (
        Path(result["mirage_path"])
        / "Users" / "Administrator" / "Documents" / "Q3_Financials_2026.docx"
    )
    assert sam_path.exists()
    assert doc_path.exists()
    assert "DECOY" in sam_path.read_text()


def test_deploy_seals_success_to_ledger(mirage, isolated_stamp):
    mirage.deploy_hallucination(5000, force_enable=True)
    summary = isolated_stamp.get_ledger_summary()
    assert summary["entry_count"] == 2  # genesis + HALLUCINATION_DEPLOYED


# --------------------------------------------------------------------------
# teardown_hallucination
# --------------------------------------------------------------------------

def test_teardown_removes_existing_decoy_and_returns_true(mirage):
    mirage.deploy_hallucination(6000, "LINUX", force_enable=True)
    mirage_path = os.path.join(mirage.mirage_dir, "linux_target_6000")
    assert os.path.isdir(mirage_path)

    result = mirage.teardown_hallucination(6000, "LINUX")
    assert result is True
    assert not os.path.exists(mirage_path)


def test_teardown_of_nonexistent_target_returns_false_not_crash(mirage):
    result = mirage.teardown_hallucination(999999, "LINUX")
    assert result is False


def test_teardown_seals_to_ledger_on_success(mirage, isolated_stamp):
    mirage.deploy_hallucination(6001, "LINUX", force_enable=True)
    mirage.teardown_hallucination(6001, "LINUX")

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "HALLUCINATION_TEARDOWN"


def test_boundary_check_rejects_string_prefix_sibling(mirage):
    """
    Known issue #16 (FIXED): the teardown boundary check used string
    .startswith(), so a sibling such as ``<mirage_dir>_EVIL_SIBLING`` counted
    as "inside" ``<mirage_dir>``. It now uses real path containment.
    """
    sibling_dir = mirage.mirage_dir + "_EVIL_SIBLING"
    os.makedirs(sibling_dir, exist_ok=True)
    try:
        # The raw string-prefix relationship that made the old check wrong:
        assert os.path.abspath(sibling_dir).startswith(mirage.mirage_dir)
        # ...but it is no longer treated as inside the mirage directory.
        assert not mirage._is_inside_mirage_dir(sibling_dir)
        assert not mirage._is_inside_mirage_dir(
            os.path.join(sibling_dir, "linux_target_1")
        )
    finally:
        os.rmdir(sibling_dir)


def test_boundary_check_accepts_real_children_only(mirage):
    child = os.path.join(mirage.mirage_dir, "linux_target_42")
    assert mirage._is_inside_mirage_dir(child)
    assert mirage._is_inside_mirage_dir(os.path.join(child, "etc", "shadow"))
    # The decoy root itself and its parent are never valid teardown targets.
    assert not mirage._is_inside_mirage_dir(mirage.mirage_dir)
    assert not mirage._is_inside_mirage_dir(os.path.dirname(mirage.mirage_dir))
    # ".." traversal that resolves back out is rejected.
    assert not mirage._is_inside_mirage_dir(
        os.path.join(mirage.mirage_dir, "linux_target_42", "..", "..", "x")
    )


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privileges on Windows")
def test_teardown_refuses_symlink_that_escapes_mirage_dir(mirage, tmp_path):
    outside = tmp_path / "outside_secret"
    outside.mkdir()
    (outside / "keep.txt").write_text("must survive")
    link = os.path.join(mirage.mirage_dir, "linux_target_777")
    os.symlink(outside, link)

    assert mirage.teardown_hallucination(777, "LINUX") is False
    assert (outside / "keep.txt").read_text() == "must survive"


# --------------------------------------------------------------------------
# sweep_orphaned_hallucinations
# --------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="/proc-based liveness check is Linux-specific")
def test_sweep_removes_decoy_for_dead_pid(mirage):
    dead_pid = 999999  # astronomically unlikely to be a real running PID
    decoy_path = os.path.join(mirage.mirage_dir, f"linux_target_{dead_pid}")
    os.makedirs(decoy_path)

    mirage.sweep_orphaned_hallucinations()
    assert not os.path.exists(decoy_path)


@pytest.mark.skipif(sys.platform != "linux", reason="/proc-based liveness check is Linux-specific")
def test_sweep_keeps_decoy_for_alive_pid(mirage):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.1)
        decoy_path = os.path.join(mirage.mirage_dir, f"linux_target_{proc.pid}")
        os.makedirs(decoy_path)

        mirage.sweep_orphaned_hallucinations()
        assert os.path.exists(decoy_path)
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_sweep_ignores_malformed_folder_names(mirage):
    # Wrong part count and non-digit suffix -- must not crash, must not
    # be touched (not our decoy format, don't blindly delete it).
    weird_dir_1 = os.path.join(mirage.mirage_dir, "not_our_format")
    weird_dir_2 = os.path.join(mirage.mirage_dir, "linux_target_notanumber")
    os.makedirs(weird_dir_1)
    os.makedirs(weird_dir_2)

    mirage.sweep_orphaned_hallucinations()  # must not raise

    assert os.path.exists(weird_dir_1)
    assert os.path.exists(weird_dir_2)


def test_sweep_error_is_caught_and_logged_not_crashed(mirage, isolated_stamp, monkeypatch):
    import json

    def raise_error(path):
        raise OSError("simulated listdir failure")

    monkeypatch.setattr("os.listdir", raise_error)
    mirage.sweep_orphaned_hallucinations()  # must not raise

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "SWEEP_ERROR"
