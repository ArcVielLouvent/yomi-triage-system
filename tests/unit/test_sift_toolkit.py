"""
Unit tests for yomi_mcp.sift_toolkit.SiftArsenal.

Strategy: SiftArsenal wraps ~18 different forensic tools (Volatility,
Radare2, Plaso, TSK, tshark, bulk_extractor, YARA, ssdeep, reglookup,
scalpel), but every single one funnels through the same small set of
chokepoints: _validate_target_path, _validate_tool, _run_subprocess,
_run_pipe. Testing those chokepoints thoroughly with REAL subprocesses
(echo/false/sleep/nonexistent binaries -- not mocked, since this module's
entire job is safe subprocess handling) covers the shared risk surface.
On top of that, a representative sample of wrapper methods is tested for
their tool-specific logic (injection barriers, binary-mode preservation,
flag ordering) rather than exhaustively re-testing all 18 wrappers, since
they're structurally identical past the chokepoint.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def arsenal(monkeypatch):
    from yomi_mcp.sift_toolkit import SiftArsenal

    monkeypatch.setattr("shutil.which", lambda name: None)
    return SiftArsenal()


def _make_fake_tool_script(tmp_path, name, script_body):
    """
    Creates a real, executable shell script standing in for a forensic
    binary, so wrapper tests exercise a REAL subprocess end-to-end rather
    than mocking subprocess.Popen (which would only prove the mock was
    called correctly, not that the real chokepoint handles a real process).
    """
    script_path = tmp_path / name
    # NOTE: uses bash specifically, not /bin/sh -- on Debian/Ubuntu-based
    # systems /bin/sh is typically dash, whose printf builtin does NOT
    # support \xHH hex escapes (confirmed by testing directly: dash prints
    # the literal text "\x00" instead of the byte 0x00). bash's printf
    # builtin does support it correctly, which the binary-integrity test
    # below depends on.
    script_path.write_text(f"#!/bin/bash\n{script_body}\n")
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
    return str(script_path)


# --------------------------------------------------------------------------
# _validate_target_path
# --------------------------------------------------------------------------

def test_relative_path_rejected(arsenal):
    valid, error = arsenal._validate_target_path("relative/path.bin")
    assert valid is False
    assert "absolute" in error.lower()


def test_nonexistent_path_rejected(arsenal):
    valid, error = arsenal._validate_target_path("/tmp/does_not_exist_at_all_12345.bin")
    assert valid is False
    assert "does not exist" in error.lower()


def test_directory_rejected_when_block_device_not_allowed(arsenal, tmp_path):
    valid, error = arsenal._validate_target_path(str(tmp_path))
    assert valid is False
    assert "not a regular file" in error.lower()


def test_directory_allowed_when_block_device_flag_set(arsenal, tmp_path):
    # Memory dumps / disk images are sometimes block devices, not regular
    # files -- allow_block_device relaxes the is_file() check.
    valid, error = arsenal._validate_target_path(str(tmp_path), allow_block_device=True)
    assert valid is True


def test_non_string_path_rejected(arsenal):
    valid, error = arsenal._validate_target_path(12345)
    assert valid is False


def test_valid_file_passes(arsenal, tmp_path):
    real_file = tmp_path / "evidence.bin"
    real_file.write_bytes(b"fake evidence content")
    valid, error = arsenal._validate_target_path(str(real_file))
    assert valid is True


# --------------------------------------------------------------------------
# _validate_tool
# --------------------------------------------------------------------------

def test_unavailable_tool_rejected_with_helpful_message(arsenal):
    enabled, msg = arsenal._validate_tool("volatility")
    assert enabled is False
    assert "unavailable" in msg.lower()
    assert "PATH" in msg


def test_available_tool_returns_its_path(arsenal, monkeypatch):
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: "/usr/bin/fake_tool")
    enabled, path = arsenal._validate_tool("volatility")
    assert enabled is True
    assert path == "/usr/bin/fake_tool"


# --------------------------------------------------------------------------
# _run_subprocess: the core chokepoint, tested with REAL processes
# --------------------------------------------------------------------------

def test_run_subprocess_success_captures_stdout(arsenal):
    result = arsenal._run_subprocess(["echo", "hello from forensic tool"], "echo_test")
    assert result["status"] == "SUCCESS"
    assert "hello from forensic tool" in result["output"]


def test_run_subprocess_nonzero_exit_reports_error(arsenal):
    result = arsenal._run_subprocess(["false"], "false_test")
    assert result["status"] == "ERROR"


def test_run_subprocess_nonexistent_binary_reports_error_not_crash(arsenal):
    result = arsenal._run_subprocess(["/nonexistent/binary/at/all"], "missing_test")
    assert result["status"] == "ERROR"
    assert "not found" in result["error"].lower()


def test_run_subprocess_timeout_kills_and_reports(arsenal):
    result = arsenal._run_subprocess(["sleep", "10"], "sleep_test", timeout=1)
    assert result["status"] == "ERROR"
    assert "timed out" in result["error"].lower()
    assert "returned -9" not in result["error"]


def test_run_subprocess_captures_stderr_on_failure(arsenal):
    result = arsenal._run_subprocess(
        ["sh", "-c", "echo 'error details' >&2; exit 1"], "stderr_test"
    )
    assert result["status"] == "ERROR"
    assert "error details" in result["error"]


def test_run_subprocess_truncates_huge_output_at_100000_chars(arsenal, tmp_path):
    script = _make_fake_tool_script(
        tmp_path, "big_output.sh", "yes X | head -c 200000"
    )
    result = arsenal._run_subprocess([script], "big_output_test", timeout=15)
    assert result["status"] == "SUCCESS"
    assert len(result["output"]) <= 100000


# --------------------------------------------------------------------------
# _run_pipe: real two-process pipeline
# --------------------------------------------------------------------------

def test_run_pipe_success(arsenal):
    result = arsenal._run_pipe(
        ["echo", "needle in a haystack"], ["grep", "needle"], "pipe_test"
    )
    assert result["status"] == "SUCCESS"
    assert "needle" in result["output"]


def test_run_pipe_right_side_failure_reported(arsenal):
    result = arsenal._run_pipe(["echo", "no match here"], ["grep", "nonexistent"], "pipe_test")
    assert result["status"] == "ERROR"


def test_run_pipe_timeout_reports_clear_message(arsenal):
    result = arsenal._run_pipe(["yes"], ["sleep", "10"], "pipe_timeout_test", timeout=1)
    assert result["status"] == "ERROR"
    assert "timed out" in result["error"].lower()


# --------------------------------------------------------------------------
# Representative high-level wrapper tests
# --------------------------------------------------------------------------

def test_volatility_pslist_missing_file_short_circuits_before_tool_check(arsenal):
    result = arsenal.run_volatility_pslist("/nonexistent/dump.raw")
    assert result["status"] == "ERROR"
    assert "does not exist" in result["error"].lower()


def test_volatility_pslist_tool_unavailable(arsenal, tmp_path):
    dump_file = tmp_path / "dump.raw"
    dump_file.write_bytes(b"fake memory dump")
    result = arsenal.run_volatility_pslist(str(dump_file))
    assert result["status"] == "ERROR"
    assert "unavailable" in result["error"].lower()


def test_volatility_pslist_full_success_with_fake_binary(arsenal, tmp_path, monkeypatch):
    fake_vol = _make_fake_tool_script(
        tmp_path, "fake_vol.sh", 'echo "PID   PPID  ImageFileName"\necho "4    0     System"'
    )
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: fake_vol)
    dump_file = tmp_path / "dump.raw"
    dump_file.write_bytes(b"fake memory dump")

    result = arsenal.run_volatility_pslist(str(dump_file))
    assert result["status"] == "SUCCESS"
    assert "ImageFileName" in result["output"]


def test_volatility_yarascan_missing_rules_file_rejected(arsenal, tmp_path, monkeypatch):
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: "/fake/vol")
    dump_file = tmp_path / "dump.raw"
    dump_file.write_bytes(b"x")
    result = arsenal.run_volatility_yarascan(str(dump_file), "/nonexistent/rules.yar")
    assert result["status"] == "ERROR"
    assert "YARA file not found" in result["error"]


def test_volatility_yarascan_injects_double_dash_barrier_before_rules_path(arsenal, tmp_path, monkeypatch):
    """
    Confirms the documented "Global Flag Evasion Immunity" claim: a "--"
    literal is injected before the YARA rules path so a maliciously-named
    rules file (e.g. one starting with "-") can't be interpreted as a
    volatility CLI flag.
    """
    captured_cmd = {}

    def fake_run_subprocess(command_list, tool_name, timeout=60):
        captured_cmd["cmd"] = command_list
        return {"status": "SUCCESS", "tool": tool_name, "output": ""}

    monkeypatch.setattr(arsenal, "_run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: "/fake/vol")

    dump_file = tmp_path / "dump.raw"
    dump_file.write_bytes(b"x")
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text("rule test {}")

    arsenal.run_volatility_yarascan(str(dump_file), str(rules_file))

    cmd = captured_cmd["cmd"]
    dash_dash_index = cmd.index("--")
    assert cmd[dash_dash_index + 1] == str(rules_file)


def test_tsk_icat_preserves_binary_content_exactly(arsenal, tmp_path, monkeypatch):
    """
    Confirms the documented "Binary Integrity" claim: output is written in
    "wb" mode, so binary content (including bytes that would corrupt a
    text-mode write, e.g. embedded null bytes / non-UTF8 sequences) is
    preserved exactly.
    """
    binary_payload = bytes([0x00, 0xFF, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    printf_escapes = "".join(f"\\x{b:02x}" for b in binary_payload)
    fake_icat = _make_fake_tool_script(
        tmp_path, "fake_icat.sh", f'printf "{printf_escapes}"'
    )
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: fake_icat)

    image_file = tmp_path / "image.dd"
    image_file.write_bytes(b"fake disk image")
    output_file = tmp_path / "extracted" / "recovered_file.bin"

    result = arsenal.run_tsk_icat(str(image_file), "12345", output_path=str(output_file))
    assert result["status"] == "SUCCESS"
    assert output_file.read_bytes() == binary_payload


def test_scalpel_inserts_config_flag_correctly_when_provided(arsenal, tmp_path, monkeypatch):
    captured_cmd = {}

    def fake_run_subprocess(command_list, tool_name, timeout=60):
        captured_cmd["cmd"] = command_list
        return {"status": "SUCCESS", "tool": tool_name, "output": ""}

    monkeypatch.setattr(arsenal, "_run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: "/fake/scalpel")

    image_file = tmp_path / "image.dd"
    image_file.write_bytes(b"x")
    config_file = tmp_path / "scalpel.conf"
    config_file.write_text("# config")

    arsenal.run_scalpel(str(image_file), config_path=str(config_file))

    cmd = captured_cmd["cmd"]
    assert cmd[0] == "/fake/scalpel"
    assert "-c" in cmd
    assert cmd[cmd.index("-c") + 1] == str(config_file)
    assert "-o" in cmd


def test_scalpel_generates_default_output_dir_when_not_provided(arsenal, tmp_path, monkeypatch):
    captured_cmd = {}

    def fake_run_subprocess(command_list, tool_name, timeout=60):
        captured_cmd["cmd"] = command_list
        return {"status": "SUCCESS", "tool": tool_name, "output": ""}

    monkeypatch.setattr(arsenal, "_run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(arsenal.os_bridge, "get_tool_path", lambda name: "/fake/scalpel")

    image_file = tmp_path / "image.dd"
    image_file.write_bytes(b"x")
    arsenal.run_scalpel(str(image_file))

    cmd = captured_cmd["cmd"]
    output_dir = cmd[cmd.index("-o") + 1]
    assert tempfile.gettempdir() in output_dir
    assert "scalpel_" in output_dir
