"""
Unit tests for yomi_engine.mirage.MirageProtocol.

Notes a theoretical (not currently exploitable through the public API)
path-containment weakness: teardown_hallucination's "Absolute Security
Boundary Check" uses `.startswith(self.mirage_dir)` on a plain string,
which is vulnerable to sibling-directory prefix matching (e.g.
"/mirage_env_EVIL" also starts with "/mirage_env"). Not exploitable here
specifically because target_path is always built via os.path.join with an
int-cast pid and a 2-value-constrained prefix -- but documented as a
pattern worth avoiding if this code is ever reused/refactored.
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


def test_teardown_boundary_check_documented_prefix_weakness(mirage, monkeypatch):
    """
    Documents (does not exploit) the theoretical weakness in the boundary
    check: it uses string .startswith() rather than proper path
    containment (e.g. os.path.commonpath or checking for a path separator
    after the prefix). Not reachable via the public API today since
    target_path is always built from an int-cast pid and a 2-value prefix
    -- but this test exists so the weakness is visible if the method is
    ever refactored to accept more flexible input.
    """
    sibling_dir = mirage.mirage_dir + "_EVIL_SIBLING"
    os.makedirs(sibling_dir, exist_ok=True)
    try:
        # Confirms the raw string-prefix relationship exists (the actual
        # vulnerability precondition), even though teardown_hallucination's
        # own path construction prevents reaching it via the public API.
        assert os.path.abspath(sibling_dir).startswith(mirage.mirage_dir)
    finally:
        os.rmdir(sibling_dir)


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
