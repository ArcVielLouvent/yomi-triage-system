"""
Unit tests for yomi_engine.mitre_mapper.MitreMapper.

Includes explicit regression coverage for the module's own stated claim
("Hardened against Substring False Positives via Regex Escaping") -- a
claim worth verifying directly rather than trusting the docstring.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def mapper(isolated_stamp):
    from yomi_engine.mitre_mapper import MitreMapper

    return MitreMapper()


def test_single_keyword_match_returns_correct_mitre_id(mapper):
    results = mapper.map_anomalies(["Process high-entropy outbound connection detected."])
    assert len(results) == 1
    tactic_ids = {t["mitre_id"] for t in results[0]["matched_tactics"]}
    assert "T1486" in tactic_ids  # "high-entropy" -> YR_RANSOMWARE
    assert "T1071" in tactic_ids  # "outbound" -> C2_BEACON


def test_unmatched_anomaly_falls_back_to_generic(mapper):
    results = mapper.map_anomalies(["Completely unremarkable log line with no signatures."])
    assert len(results) == 1
    assert results[0]["matched_tactics"][0]["ioe_signature"] == "GENERIC_ANOMALY"
    assert results[0]["matched_tactics"][0]["mitre_id"] == "T1106"


def test_non_list_input_returns_empty_and_logs_error(mapper, isolated_stamp):
    result = mapper.map_anomalies("not a list, a plain string")
    assert result == []

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    import json
    last_entry = json.loads(lines[-1])
    assert last_entry["action_type"] == "ERROR"


def test_empty_list_returns_empty_results(mapper):
    assert mapper.map_anomalies([]) == []


def test_non_string_anomaly_entries_are_coerced_safely(mapper):
    # "Safe Type-Casting to prevent Triage crashes" per the module docstring.
    results = mapper.map_anomalies([12345, None, {"weird": "dict"}])
    assert len(results) == 3
    for r in results:
        assert isinstance(r["raw_evidence"], str)


def test_multiple_anomalies_each_get_own_result_entry(mapper):
    results = mapper.map_anomalies([
        "ransomware encrypt event",
        "unrelated benign log",
        "dkom bad dtb detected",
    ])
    assert len(results) == 3


def test_unique_mitre_id_count_deduplicates_across_anomalies(mapper, isolated_stamp):
    # Two anomalies both hitting T1071 (C2_BEACON) should count as 1 unique
    # tactic, not 2, in the ledger's summary message.
    mapper.map_anomalies(["beacon detected", "another beacon outbound"])

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    import json
    last_entry = json.loads(lines[-1])
    assert "1 unique tactics across 2 anomalies" in last_entry["description"]


# --------------------------------------------------------------------------
# Regression tests for the module's stated "no substring false positives" claim
# --------------------------------------------------------------------------

def test_keyword_as_substring_of_unrelated_word_does_not_match(mapper):
    # "vad" is a real keyword (PE_INJECT). "invader" contains "vad" as a
    # substring but is NOT a word-boundary match -- must not false-positive.
    results = mapper.map_anomalies(["The invader arrived quietly."])
    tactic_ids = {t["mitre_id"] for t in results[0]["matched_tactics"]}
    assert "T1055" not in tactic_ids
    assert results[0]["matched_tactics"][0]["ioe_signature"] == "GENERIC_ANOMALY"


def test_keyword_with_special_regex_characters_matches_literally(mapper):
    # "T1055.004" style keywords aren't in the keyword list, but some
    # keywords are phrases -- confirm phrase matching works via a real
    # multi-word keyword, and that regex-special chars in evidence text
    # (which re.escape doesn't need to touch, since they're in the
    # SEARCHED text not the pattern) don't break matching or crash.
    results = mapper.map_anomalies(["mass file io detected (rate: 99.9%) [flagged]"])
    tactic_ids = {t["mitre_id"] for t in results[0]["matched_tactics"]}
    assert "T1486" in tactic_ids  # "mass file io" -> YR_RANSOMWARE


def test_matching_is_case_insensitive(mapper):
    results = mapper.map_anomalies(["SHELLCODE INJECTION DETECTED"])
    tactic_ids = {t["mitre_id"] for t in results[0]["matched_tactics"]}
    assert "T1055" in tactic_ids


# --------------------------------------------------------------------------
# Known issue #33: KNOWN_MITRE_IDS must track the real signature table
# --------------------------------------------------------------------------

def test_known_mitre_ids_matches_signature_table_plus_generic_fallback():
    from yomi_engine.mitre_mapper import (
        GENERIC_ANOMALY_MITRE_ID,
        KNOWN_MITRE_IDS,
        RAW_SIGNATURES,
    )

    expected = {s["mitre_id"] for s in RAW_SIGNATURES.values()}
    expected.add(GENERIC_ANOMALY_MITRE_ID)
    assert KNOWN_MITRE_IDS == frozenset(expected)


def test_known_mitre_ids_importable_without_instantiating_mapper():
    # No `mapper`/`isolated_stamp` fixture: importing must not require
    # creating an ImmutableStamp.
    from yomi_engine.mitre_mapper import KNOWN_MITRE_IDS, MitreMapper

    assert isinstance(KNOWN_MITRE_IDS, frozenset)
    assert MitreMapper.KNOWN_MITRE_IDS is KNOWN_MITRE_IDS


def test_every_emitted_mitre_id_is_in_known_set(mapper):
    from yomi_engine.mitre_mapper import KNOWN_MITRE_IDS

    results = mapper.map_anomalies(
        [
            "inject unbacked vad shellcode",
            "ransom high-entropy encrypt",
            "dkom bad dtb",
            "peb masquerad svchost",
            "apc user-mode hook",
            "beacon outbound",
            "something no signature matches",
        ]
    )
    emitted = {t["mitre_id"] for r in results for t in r["matched_tactics"]}
    assert emitted <= KNOWN_MITRE_IDS
    assert emitted == set(KNOWN_MITRE_IDS)  # the table and the set cannot drift


def test_instances_do_not_share_signature_state(mapper, isolated_stamp):
    from yomi_engine.mitre_mapper import RAW_SIGNATURES, MitreMapper

    mapper.raw_signatures["PE_INJECT"]["keywords"].append("tampered")
    assert "tampered" not in RAW_SIGNATURES["PE_INJECT"]["keywords"]
    assert "tampered" not in MitreMapper().raw_signatures["PE_INJECT"]["keywords"]
