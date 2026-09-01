"""
Unit tests for yomi_engine.remediator.ReverserEngine.

Two real validation gaps found while writing these tests (documented as
regression tests, not silently worked around -- see docs/known_issues.md):

1. Unlike harness.py's _is_critical_system_pid (PID <= 100 hardblocked),
   remediator.py's _validate_payload has NO PID protection whatsoever. A
   rollback script targeting PID 1 (init) generates successfully.

2. The "critical system path" check does an EXACT match against a fixed
   set ({"/", "/bin", "/sbin", "/usr", "/etc"}), not a prefix check. A
   file_path of "/bin/bash" or "/etc/passwd" passes validation, because
   neither equals "/bin" or "/etc" exactly. (Practical impact is limited:
   the generated script's kill commands only ever reference `pid`, never
   `file_path` -- file_path only ends up in the comment header and
   metadata -- but the validation's actual behavior doesn't match what its
   own comment claims ("Never execute kill commands targeting core OS
   paths" implies broader protection than an exact-match check provides).
"""
from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def reverser(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import remediator as remediator_module

    monkeypatch.setattr("shutil.which", lambda name: None)  # no real gpg
    engine = remediator_module.ReverserEngine.__new__(remediator_module.ReverserEngine)
    engine.audit = isolated_stamp
    engine.remediation_dir = tmp_path / "remediation"
    engine.remediation_dir.mkdir(parents=True, exist_ok=True)
    engine.gpg_binary = None
    return engine


# --------------------------------------------------------------------------
# _validate_payload
# --------------------------------------------------------------------------

def test_non_dict_payload_rejected(reverser):
    valid, reason = reverser._validate_payload("not a dict")
    assert valid is False


def test_missing_pid_rejected(reverser):
    valid, reason = reverser._validate_payload({"file_path": "/tmp/x"})
    assert valid is False
    assert "pid" in reason.lower()


def test_negative_or_zero_pid_rejected(reverser):
    for bad_pid in [0, -1, -99999]:
        valid, reason = reverser._validate_payload({"pid": bad_pid, "file_path": "/tmp/x"})
        assert valid is False


def test_relative_file_path_rejected(reverser):
    valid, reason = reverser._validate_payload({"pid": 5000, "file_path": "relative/path"})
    assert valid is False
    assert "absolute" in reason.lower()


def test_exact_critical_root_path_rejected(reverser, monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    valid, reason = reverser._validate_payload({"pid": 5000, "file_path": "/etc"})
    assert valid is False
    assert "critical system path" in reason.lower()


def test_valid_payload_passes(reverser, monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    valid, reason = reverser._validate_payload({"pid": 5000, "file_path": "/tmp/malware.bin"})
    assert valid is True


# --- Fixed gaps (regression tests for the FIXED behavior) -----------------

def test_low_numbered_pid_is_now_protected(reverser, monkeypatch):
    """
    FIXED (known_issues.md #14): mirrors harness.py's PID<=100 hardblock.
    A payload targeting PID 1 (init) must now be rejected before it ever
    reaches script generation.
    """
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    valid, reason = reverser._validate_payload({"pid": 1, "file_path": "/tmp/x"})
    assert valid is False
    assert "protected" in reason.lower() or "100" in reason


def test_pid_exactly_100_is_still_protected(reverser, monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    valid, _ = reverser._validate_payload({"pid": 100, "file_path": "/tmp/x"})
    assert valid is False


def test_pid_101_is_not_blocked_by_the_low_pid_rule(reverser, monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    valid, _ = reverser._validate_payload({"pid": 101, "file_path": "/tmp/x"})
    assert valid is True


def test_critical_path_containment_now_blocks_files_inside_protected_dirs(reverser, monkeypatch):
    """
    FIXED (known_issues.md #15): the check now uses real path containment
    (pathlib parent comparison), not an exact match against the bare
    directory string. "/bin/bash" and "/etc/passwd" -- files INSIDE the
    blocked directories -- must now be rejected too.
    """
    monkeypatch.setattr("os.path.realpath", lambda p: p)

    valid, reason = reverser._validate_payload({"pid": 5000, "file_path": "/bin/bash"})
    assert valid is False
    assert "critical system path" in reason.lower()

    valid2, reason2 = reverser._validate_payload({"pid": 5000, "file_path": "/etc/passwd"})
    assert valid2 is False
    assert "critical system path" in reason2.lower()

    valid3, _ = reverser._validate_payload({"pid": 5000, "file_path": "/usr/local/bin/tool"})
    assert valid3 is False


def test_critical_path_containment_does_not_repeat_mirage_startswith_bug(reverser, monkeypatch):
    """
    The fix for #15 must use real path containment, not string
    .startswith() -- the same class of bug already flagged for
    mirage.py's boundary check (known_issues.md #16/#18).
    "/etcetera/file" and "/binfoo" share a string PREFIX with "/etc" and
    "/bin" but are NOT inside those directories, and must still pass.
    """
    monkeypatch.setattr("os.path.realpath", lambda p: p)

    valid, _ = reverser._validate_payload({"pid": 5000, "file_path": "/etcetera/file"})
    assert valid is True

    valid2, _ = reverser._validate_payload({"pid": 5000, "file_path": "/binfoo/malware"})
    assert valid2 is True


def test_root_path_is_still_exact_match_only_not_containment(reverser, monkeypatch):
    """
    "/" is deliberately kept as an EXACT match, not path containment --
    every absolute path is technically "under" "/", so treating "/" as a
    containment boundary would reject every single payload. Only a
    payload whose resolved path IS "/" itself gets blocked.
    """
    monkeypatch.setattr("os.path.realpath", lambda p: p)

    valid, reason = reverser._validate_payload({"pid": 5000, "file_path": "/"})
    assert valid is False
    assert "critical system path" in reason.lower()

    # A normal, unrelated absolute path must NOT be blocked just because
    # it's technically "under root".
    valid2, _ = reverser._validate_payload({"pid": 5000, "file_path": "/tmp/malware.bin"})
    assert valid2 is True


# --------------------------------------------------------------------------
# _generate_script: content correctness + injection safety
# --------------------------------------------------------------------------

def test_generated_script_has_correct_permissions(reverser):
    script_path, _ = reverser._generate_script(1234, "/tmp/malware.bin", "trojan")
    mode = stat.S_IMODE(script_path.stat().st_mode)
    assert mode == 0o750


def test_generated_script_follows_stop_dump_kill_order(reverser):
    script_path, _ = reverser._generate_script(1234, "/tmp/malware.bin", "trojan")
    content = script_path.read_text()
    stop_idx = content.index("kill -STOP")
    dump_idx = content.index("gcore")
    kill_idx = content.index("kill -9")
    assert stop_idx < dump_idx < kill_idx


def test_generated_script_targets_correct_pid(reverser):
    script_path, _ = reverser._generate_script(9999, "/tmp/x", "trojan")
    content = script_path.read_text()
    assert "kill -STOP 9999" in content
    assert "kill -9 9999" in content


def test_threat_type_newlines_are_stripped_preventing_comment_injection(reverser):
    # Newlines are replaced with spaces (not deleted), so the malicious
    # text can still appear -- what matters for injection safety is that
    # it stays WITHIN the single "# Threat Type:" comment line and never
    # becomes its own standalone (potentially executable) line.
    malicious_threat_type = "trojan\n# INJECTED\nrm -rf / --no-preserve-root"
    script_path, _ = reverser._generate_script(1234, "/tmp/x", malicious_threat_type)
    content = script_path.read_text()

    threat_line = next(l for l in content.splitlines() if l.startswith("# Threat Type:"))
    assert "rm -rf /" in threat_line  # stayed on the same comment line...
    # ...and does NOT appear as its own separate, potentially-executable line:
    assert "rm -rf / --no-preserve-root" not in [
        line.strip() for line in content.splitlines()
    ]


def test_script_uses_set_euo_pipefail_for_safety(reverser):
    script_path, _ = reverser._generate_script(1234, "/tmp/x", "trojan")
    content = script_path.read_text()
    assert "set -euo pipefail" in content


# --------------------------------------------------------------------------
# _sign_script: gpg -> HMAC -> plain SHA256 fallback chain
# --------------------------------------------------------------------------

def test_signing_falls_back_to_hmac_when_no_gpg(reverser, isolated_stamp):
    reverser.gpg_binary = None
    script_path, _ = reverser._generate_script(1234, "/tmp/x", "trojan")
    sig_path = reverser._sign_script(script_path)

    assert sig_path.exists()
    payload = json.loads(sig_path.read_text())
    if isolated_stamp.hmac_key:
        assert payload["signature_type"] == "HMAC-SHA256"
    else:
        assert payload["signature_type"] == "SHA256"


def test_signature_file_has_restrictive_permissions(reverser):
    reverser.gpg_binary = None
    script_path, _ = reverser._generate_script(1234, "/tmp/x", "trojan")
    sig_path = reverser._sign_script(script_path)
    mode = stat.S_IMODE(sig_path.stat().st_mode)
    assert mode == 0o640


def test_signing_uses_gpg_when_available(reverser, monkeypatch):
    reverser.gpg_binary = "/usr/bin/gpg"
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("subprocess.run", fake_run)

    script_path, _ = reverser._generate_script(1234, "/tmp/x", "trojan")
    sig_path = reverser._sign_script(script_path)

    fake_run.assert_called_once()
    assert sig_path.name == script_path.name + ".sig"


def test_signing_falls_back_when_gpg_times_out(reverser, monkeypatch):
    import subprocess as subprocess_module

    reverser.gpg_binary = "/usr/bin/gpg"

    def raise_timeout(*args, **kwargs):
        raise subprocess_module.TimeoutExpired(cmd="gpg", timeout=10)

    monkeypatch.setattr("subprocess.run", raise_timeout)
    script_path, _ = reverser._generate_script(1234, "/tmp/x", "trojan")
    sig_path = reverser._sign_script(script_path)  # must not raise

    payload = json.loads(sig_path.read_text())
    assert payload["signature_type"] in ("HMAC-SHA256", "SHA256")


# --------------------------------------------------------------------------
# generate_rollback_script: full orchestration
# --------------------------------------------------------------------------

def test_invalid_payload_is_aborted_and_logged(reverser, isolated_stamp):
    result = reverser.generate_rollback_script({"pid": -1})
    assert result["status"] == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ABORTED"


def test_valid_payload_generates_and_logs_success(reverser, isolated_stamp, monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    result = reverser.generate_rollback_script(
        {"pid": 5000, "file_path": "/tmp/malware.bin", "threat_type": "ransomware"}
    )
    assert result["status"] == "SUCCESS"
    assert Path(result["script_path"]).exists()
    assert Path(result["signature_path"]).exists()

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "PLAYBOOK_GENERATED"


# --------------------------------------------------------------------------
# __init__: exercised separately, since the `reverser` fixture above
# deliberately bypasses it (via __new__) for path-isolation safety. This
# test isolates __init__ itself the same way Fase 1 isolated stamp.py's
# __init__ -- by monkeypatching __file__ so the hardcoded
# ../yomi_data/remediation path resolves inside a temp dir, never the real
# repository.
# --------------------------------------------------------------------------

def test_init_creates_remediation_dir_and_logs_initialization(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import remediator as remediator_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(remediator_module, "__file__", str(fake_module_dir / "remediator.py"))
    monkeypatch.setattr("shutil.which", lambda name: None)

    engine = remediator_module.ReverserEngine()

    expected_dir = tmp_path / "fake_pkg" / "yomi_data" / "remediation"
    assert engine.remediation_dir == expected_dir
    assert expected_dir.exists()

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "INITIALIZATION"
