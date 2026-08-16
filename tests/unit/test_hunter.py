"""
Unit tests for yomi_engine.hunter.OmniVectorHunter.

_resolve_forensic_source() defaults to "/" (the real filesystem root) on
POSIX when YOMI_FORENSIC_PATH isn't set -- tests that don't care about the
specific path always set the env var to an isolated tmp_path so nothing
here ever implicitly points at the real system root.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def hunter(isolated_stamp, monkeypatch):
    from yomi_engine.hunter import OmniVectorHunter

    monkeypatch.setattr("shutil.which", lambda name: None)
    return OmniVectorHunter()


# --------------------------------------------------------------------------
# _resolve_forensic_source
# --------------------------------------------------------------------------

def test_resolve_uses_env_var_when_set_and_exists(hunter, tmp_path, monkeypatch):
    monkeypatch.setenv("YOMI_FORENSIC_PATH", str(tmp_path))
    assert hunter._resolve_forensic_source() == str(tmp_path)


def test_resolve_ignores_env_var_pointing_to_nonexistent_path(hunter, monkeypatch):
    monkeypatch.setenv("YOMI_FORENSIC_PATH", "/nonexistent/path/xyz123")
    result = hunter._resolve_forensic_source()
    assert result != "/nonexistent/path/xyz123"


@pytest.mark.skipif(sys.platform == "win32", reason="posix-specific fallback")
def test_resolve_falls_back_to_root_on_posix_without_env_var(hunter, monkeypatch):
    monkeypatch.delenv("YOMI_FORENSIC_PATH", raising=False)
    assert hunter._resolve_forensic_source() == "/"


# --------------------------------------------------------------------------
# _parse_plaso_output
# --------------------------------------------------------------------------

def test_parse_plaso_empty_output_returns_message(hunter):
    assert "empty or unavailable" in hunter._parse_plaso_output("", 1234)


def test_parse_plaso_word_boundary_prevents_partial_pid_match(hunter):
    # PID 234 must NOT match inside "812345" -- word-boundary regex is the
    # documented safeguard against this exact false-positive.
    output = "2026-01-01T10:00:00 process 812345 spawned suspicious child"
    result = hunter._parse_plaso_output(output, 234)
    assert "No temporal artifacts" in result


def test_parse_plaso_exact_pid_match_is_found(hunter):
    output = "2026-01-01T10:00:00 process 1234 spawned bash shell"
    result = hunter._parse_plaso_output(output, 1234)
    assert "1234" in result
    assert "Shell execution" in result


def test_parse_plaso_malicious_keyword_matches_regardless_of_pid(hunter):
    output = "2026-01-01T10:00:00 MALICIOUS payload detected, unrelated pid 9999"
    result = hunter._parse_plaso_output(output, 1234)  # different PID entirely
    assert "1234" in result  # still reported under this hunt


def test_parse_plaso_categorizes_credential_access_events(hunter):
    output = "2026-01-01T10:00:00 pid 1234 executed mimikatz lsass dump"
    result = hunter._parse_plaso_output(output, 1234)
    assert "Credential access" in result


def test_parse_plaso_categorizes_persistence_events(hunter):
    output = "2026-01-01T10:00:00 pid 1234 created runkey for service start"
    result = hunter._parse_plaso_output(output, 1234)
    assert "Persistence mechanism" in result


def test_parse_plaso_missing_timestamp_falls_back_to_unknown(hunter):
    output = "no timestamp here but pid 1234 is present bash"
    result = hunter._parse_plaso_output(output, 1234)
    assert "UNKNOWN_TIME" in result


def test_parse_plaso_events_sorted_chronologically(hunter):
    output = (
        "2026-06-01T10:00:00 pid 1234 bash\n"
        "2026-01-01T10:00:00 pid 1234 mimikatz\n"
        "2026-03-01T10:00:00 pid 1234 runkey service start\n"
    )
    result = hunter._parse_plaso_output(output, 1234)
    # The summary header itself mentions window_start/window_end (jan/jun)
    # BEFORE the actual per-event bullet list -- so ordering must be
    # checked only within the "Key correlations:" bullet section, not
    # naively across the whole string (the header would otherwise confuse
    # a plain substring-index comparison).
    bullet_section = result.split("Key correlations:")[1]
    jan_pos = bullet_section.index("2026-01-01")
    mar_pos = bullet_section.index("2026-03-01")
    jun_pos = bullet_section.index("2026-06-01")
    assert jan_pos < mar_pos < jun_pos


def test_parse_plaso_summary_caps_at_5_events(hunter):
    lines = [f"2026-01-01T10:00:0{i} pid 1234 bash execution\n" for i in range(9)]
    output = "".join(lines)
    result = hunter._parse_plaso_output(output, 1234)
    assert result.count("Shell execution") == 5


def test_parse_plaso_truncates_preserved_line_at_500_chars(hunter):
    output = f"2026-01-01T10:00:00 pid 1234 bash {'A' * 1000}"
    result = hunter._parse_plaso_output(output, 1234)
    # Each summary line embeds up to 500 chars of the original -- overall
    # result shouldn't contain the full 1000-char run of "A"s.
    assert "A" * 1000 not in result


# --------------------------------------------------------------------------
# _parse_tsk_output
# --------------------------------------------------------------------------

def test_parse_tsk_empty_output_returns_message(hunter):
    assert "empty or unavailable" in hunter._parse_tsk_output("")


def test_parse_tsk_finds_deleted_mimikatz(hunter):
    output = "* (deleted) C:/temp/mimikatz.exe"
    result = hunter._parse_tsk_output(output)
    assert "Suspicious filesystem artifacts" in result


def test_parse_tsk_no_match_returns_clean_message(hunter):
    output = "regular_document.docx  normal_file.txt"
    result = hunter._parse_tsk_output(output)
    assert "No deleted or hidden droppers" in result


def test_parse_tsk_deduplicates_and_caps_at_5(hunter):
    output = "\n".join([f"(deleted) unallocated cmd.exe carved sample{i}" for i in range(8)])
    result = hunter._parse_tsk_output(output)
    # Can't exceed 5 in the joined summary regardless of how many raw matches existed.
    assert result.count("cmd.exe") <= 5


# --------------------------------------------------------------------------
# hunt_root_cause: full orchestration
# --------------------------------------------------------------------------

def test_hunt_invalid_pid_aborts_and_logs(hunter, isolated_stamp):
    result = hunter.hunt_root_cause(-5)
    assert result["status"] == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ABORTED"


def test_hunt_non_int_pid_aborts(hunter):
    result = hunter.hunt_root_cause("not_an_int")
    assert result["status"] == "ERROR"


def test_hunt_no_forensic_source_aborts_and_logs(hunter, isolated_stamp, monkeypatch):
    monkeypatch.setattr(hunter, "_resolve_forensic_source", lambda: None)
    result = hunter.hunt_root_cause(1234)
    assert result["status"] == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ABORTED"


def test_hunt_completes_with_tool_unavailable_messages_when_no_sift_tools(hunter, tmp_path, monkeypatch):
    monkeypatch.setenv("YOMI_FORENSIC_PATH", str(tmp_path))
    result = hunter.hunt_root_cause(1234)

    assert result["status"] == "HUNT_COMPLETE"
    assert result["target_pid"] == 1234
    assert "failed" in result["temporal_vector"].lower()
    assert "failed" in result["spatial_vector"].lower()


def test_hunt_seals_completion_to_ledger(hunter, isolated_stamp, tmp_path, monkeypatch):
    monkeypatch.setenv("YOMI_FORENSIC_PATH", str(tmp_path))
    hunter.hunt_root_cause(5678)

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ROOT_CAUSE_COMPILED"


def test_hunt_uses_real_plaso_result_when_tool_mocked_available(hunter, tmp_path, monkeypatch):
    monkeypatch.setenv("YOMI_FORENSIC_PATH", str(tmp_path))
    monkeypatch.setattr(
        hunter.arsenal, "run_plaso_timeline",
        lambda source: {"status": "SUCCESS", "output": "2026-01-01T10:00:00 pid 5678 bash"},
    )
    monkeypatch.setattr(
        hunter.arsenal, "run_tsk_fls",
        lambda source: {"status": "SUCCESS", "output": "clean filesystem"},
    )

    result = hunter.hunt_root_cause(5678)
    assert "Shell execution" in result["temporal_vector"]
    assert "No deleted or hidden droppers" in result["spatial_vector"]
