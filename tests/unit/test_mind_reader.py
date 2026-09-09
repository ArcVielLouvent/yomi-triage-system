"""
Unit tests for yomi_engine.mind_reader.MindReaderDecompiler.

__init__ constructs OmniLibrary() with no args (hardcoded default
data_dir, same isolation as test_library.py/test_dashboard.py) and
ImmutableStamp(). _derive_profile_from_assembly lazily imports and
constructs yomi_core.router.OpenClawGateway inside the method -- mocked at
the module level for LLM-related tests.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def mind_reader(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import library as library_module
    from yomi_engine import mind_reader as mind_reader_module

    fake_library_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_library_dir.mkdir(parents=True)
    monkeypatch.setattr(library_module, "__file__", str(fake_library_dir / "library.py"))
    monkeypatch.setattr(library_module.OmniLibrary, "_has_network", lambda self: False)
    monkeypatch.setattr("shutil.which", lambda name: None)

    instance = mind_reader_module.MindReaderDecompiler()
    yield instance
    instance.library.shutdown()


# --------------------------------------------------------------------------
# _fallback_string_extraction
# --------------------------------------------------------------------------

def test_fallback_extraction_finds_ascii_strings(mind_reader, tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00\x01\x02" + b"HelloWorldString" + b"\xff\xfe" + b"AnotherLongEnoughString")
    result = mind_reader._fallback_string_extraction(str(binary))
    assert "HelloWorldString" in result
    assert "AnotherLongEnoughString" in result


def test_fallback_extraction_ignores_short_strings(mind_reader, tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00ab\x00cd\x00")  # "ab"/"cd" are under the 4-char minimum
    result = mind_reader._fallback_string_extraction(str(binary))
    assert "ab" not in result.replace("STRINGS (R2 FALLBACK)", "")


def test_fallback_extraction_missing_file_returns_error_message_not_crash(mind_reader):
    result = mind_reader._fallback_string_extraction("/nonexistent/binary.bin")
    assert "failed" in result.lower()


def test_fallback_extraction_caps_read_at_1mb(mind_reader, tmp_path):
    binary = tmp_path / "huge.bin"
    binary.write_bytes(b"A" * 2_000_000)  # 2MB of a 4+-char-run string
    result = mind_reader._fallback_string_extraction(str(binary))
    longest_run = max((len(s) for s in result.split("\n")), default=0)
    assert longest_run <= 1_000_000


# --------------------------------------------------------------------------
# decompile_and_profile
# --------------------------------------------------------------------------

def test_decompile_missing_binary_aborts_and_logs(mind_reader, isolated_stamp):
    result = mind_reader.decompile_and_profile("/nonexistent/malware.bin", 1234)
    assert result["status"] == "ERROR"

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "ABORTED"


def test_decompile_uses_radare2_output_when_available(mind_reader, tmp_path, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"fake binary")

    monkeypatch.setattr(
        mind_reader.arsenal, "run_radare2_analysis",
        lambda path: {"status": "SUCCESS", "output": "mov eax, ebx; call connect socket ws2_32"},
    )
    monkeypatch.setattr(
        mind_reader, "_derive_profile_from_assembly",
        lambda assembly, ctx: {"skill_level": "Advanced", "methodology": "m", "psychology": "p", "mitre_tactics": ["T1055"]},
    )

    result = mind_reader.decompile_and_profile(str(binary), 5000)
    assert result["status"] == "SUCCESS"
    assert result["hacker_profile"]["skill_level"] == "Advanced"


def test_decompile_falls_back_to_string_extraction_when_r2_fails(mind_reader, tmp_path, isolated_stamp, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"UniqueMarkerString1234")

    monkeypatch.setattr(
        mind_reader.arsenal, "run_radare2_analysis",
        lambda path: {"status": "ERROR", "error": "radare2 not installed"},
    )
    captured_assembly = {}
    monkeypatch.setattr(
        mind_reader, "_derive_profile_from_assembly",
        lambda assembly, ctx: captured_assembly.setdefault("value", assembly) and {
            "skill_level": "x", "methodology": "y", "psychology": "z", "mitre_tactics": []
        },
    )

    mind_reader.decompile_and_profile(str(binary), 5000)
    assert "UniqueMarkerString1234" in captured_assembly["value"]

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "DECOMPILATION_FALLBACK" for l in lines)


def test_decompile_truncates_assembly_over_4000_chars(mind_reader, tmp_path, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")

    huge_output = "A" * 5000
    monkeypatch.setattr(
        mind_reader.arsenal, "run_radare2_analysis",
        lambda path: {"status": "SUCCESS", "output": huge_output},
    )
    captured_assembly = {}
    monkeypatch.setattr(
        mind_reader, "_derive_profile_from_assembly",
        lambda assembly, ctx: captured_assembly.setdefault("value", assembly) and {
            "skill_level": "x", "methodology": "y", "psychology": "z", "mitre_tactics": []
        },
    )

    mind_reader.decompile_and_profile(str(binary), 5000)
    assert len(captured_assembly["value"]) <= 4100
    assert "TRUNCATED" in captured_assembly["value"]


def test_decompile_injects_schema_mimicry_cve_into_library(mind_reader, tmp_path, monkeypatch):
    import datetime as dt

    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")

    monkeypatch.setattr(mind_reader.arsenal, "run_radare2_analysis", lambda path: {"status": "SUCCESS", "output": "asm"})
    monkeypatch.setattr(
        mind_reader, "_derive_profile_from_assembly",
        lambda assembly, ctx: {
            "skill_level": "Advanced", "methodology": "C2 beaconing",
            "psychology": "patient", "mitre_tactics": ["T1071", "T1055"],
        },
    )

    result = mind_reader.decompile_and_profile(str(binary), 7777)
    expected_year = dt.datetime.now(dt.timezone.utc).strftime("%Y")
    assert result["signature_id"] == f"CVE-{expected_year}-YOMI7777"

    stored = mind_reader.library.query_cve(result["signature_id"])
    assert stored is not None
    assert "C2 beaconing" in stored["description"]


def test_decompile_knowledge_updated_logged_only_when_actually_added(mind_reader, tmp_path, isolated_stamp, monkeypatch):
    binary = tmp_path / "malware.bin"
    binary.write_bytes(b"x")
    monkeypatch.setattr(mind_reader.arsenal, "run_radare2_analysis", lambda path: {"status": "SUCCESS", "output": "asm"})
    monkeypatch.setattr(
        mind_reader, "_derive_profile_from_assembly",
        lambda assembly, ctx: {"skill_level": "x", "methodology": "y", "psychology": "z", "mitre_tactics": []},
    )

    mind_reader.decompile_and_profile(str(binary), 8888)
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "KNOWLEDGE_UPDATED" for l in lines)
    assert any(l["action_type"] == "PROFILE_GENERATED" for l in lines)


# --------------------------------------------------------------------------
# _derive_profile_from_assembly
# --------------------------------------------------------------------------

def test_derive_profile_empty_assembly_returns_default(mind_reader):
    profile = mind_reader._derive_profile_from_assembly("", "context")
    assert profile["skill_level"] == "Unknown"
    assert "T1027" in profile["mitre_tactics"][0]


def test_derive_profile_uses_llm_response_when_valid(mind_reader, monkeypatch):
    fake_gateway = MagicMock()
    fake_gateway.analyze_artifact.return_value = '```json\n{"skill_level": "Expert", "methodology": "m", "psychology": "p", "mitre_tactics": ["T1055"]}\n```'
    fake_gateway._extract_json_payload.return_value = (
        '{"skill_level": "Expert", "methodology": "m", "psychology": "p", "mitre_tactics": ["T1055"]}'
    )
    monkeypatch.setattr("yomi_core.router.OpenClawGateway", lambda: fake_gateway)

    profile = mind_reader._derive_profile_from_assembly("some assembly code", "context")
    assert profile["skill_level"] == "Expert"


def test_derive_profile_llm_missing_required_keys_falls_back_to_heuristic(mind_reader, monkeypatch):
    fake_gateway = MagicMock()
    fake_gateway.analyze_artifact.return_value = '{"skill_level": "Expert"}'  # missing other required keys
    fake_gateway._extract_json_payload.return_value = '{"skill_level": "Expert"}'
    monkeypatch.setattr("yomi_core.router.OpenClawGateway", lambda: fake_gateway)

    profile = mind_reader._derive_profile_from_assembly("simple direct syscalls", "context")
    assert profile["skill_level"] == "Novice"  # fell through to heuristic default


def test_derive_profile_llm_exception_caught_and_logged(mind_reader, isolated_stamp, monkeypatch):
    def raise_error():
        raise RuntimeError("simulated LLM gateway crash")

    monkeypatch.setattr("yomi_core.router.OpenClawGateway", raise_error)

    profile = mind_reader._derive_profile_from_assembly("simple direct syscalls", "context")
    assert profile is not None  # didn't crash

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "LLM_ANALYSIS_ERROR" for l in lines)


@pytest.mark.parametrize(
    "assembly,expected_skill",
    [
        ("mov eax, ebx; connect socket ws2_32.dll", "Advanced (APT Behavior)"),
        ("call exec cmd.exe /c whoami", "Intermediate"),
        ("mov eax, 1; syscall exit", "Novice"),
    ],
)
def test_derive_profile_heuristic_classification(mind_reader, monkeypatch, assembly, expected_skill):
    def raise_error():
        raise RuntimeError("force heuristic fallback path")

    monkeypatch.setattr("yomi_core.router.OpenClawGateway", raise_error)
    profile = mind_reader._derive_profile_from_assembly(assembly, "context")
    assert profile["skill_level"] == expected_skill
