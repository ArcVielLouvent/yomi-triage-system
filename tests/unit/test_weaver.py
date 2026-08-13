"""
Unit tests for yomi_engine.weaver.TemporalNarrativeWeaver.

Includes the definitive root-cause regression test for the MITRE-dropping
bug tracked in docs/known_issues.md #7: weaver.py's mitre_regex searches
the `description` field text for literal "T1XXX" substrings, but
mitre_mapper.py's record_action() call writes a description like "Mapped 2
unique tactics across 5 anomalies" -- the actual MITRE IDs live only in
map_anomalies()'s return value, never in ledger description text. So the
regex is structurally guaranteed to find nothing from MITRE_MAPPER
entries, regardless of how many tactics were actually mapped. This isn't
a frequency-bias issue (as originally guessed from the hackathon report) --
it's a data-shape mismatch between what mitre_mapper.py writes and what
weaver.py reads.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def weaver(isolated_stamp):
    from yomi_engine.weaver import TemporalNarrativeWeaver

    return TemporalNarrativeWeaver()


def test_empty_ledger_returns_no_logs_message(weaver, isolated_stamp):
    # Genesis entry alone: generate_narrative should still produce a
    # narrative (genesis IS a log entry), not the "no logs" message.
    narrative = weaver.generate_narrative()
    assert "No audit logs available" not in narrative


def test_narrative_includes_agent_and_action_for_recorded_entries(weaver, isolated_stamp):
    isolated_stamp.record_action("SWARM", "SCAN_COMPLETE", "RAM scan finished, no anomalies.")
    narrative = weaver.generate_narrative()
    assert "SWARM" in narrative
    assert "SCAN_COMPLETE" in narrative
    assert "RAM scan finished" in narrative


def test_noise_action_types_are_filtered_from_narrative(weaver, isolated_stamp):
    isolated_stamp.record_action("TELEMETRY", "TRIAGE_ITERATION", "iteration 1")
    isolated_stamp.record_action("TELEMETRY", "BENCHMARK_RECORDED", "latency stuff")
    isolated_stamp.record_action("ROUTER", "MAX_ITERATIONS_REACHED", "gave up")
    narrative = weaver.generate_narrative()
    assert "TRIAGE_ITERATION" not in narrative
    assert "BENCHMARK_RECORDED" not in narrative
    assert "MAX_ITERATIONS_REACHED" not in narrative


def test_ansi_escape_codes_are_stripped_from_narrative(weaver, isolated_stamp):
    isolated_stamp.record_action(
        "SWARM", "SCAN", "\x1b[31mRED ALERT\x1b[0m anomaly found"
    )
    narrative = weaver.generate_narrative()
    assert "\x1b[31m" not in narrative
    assert "RED ALERT" in narrative


def test_newlines_in_description_are_visibly_marked_not_swallowed(weaver, isolated_stamp):
    isolated_stamp.record_action("SWARM", "SCAN", "line one\nline two")
    narrative = weaver.generate_narrative()
    assert "[LF]" in narrative


# --------------------------------------------------------------------------
# KNOWN BUG regression test (see docs/known_issues.md #7)
# --------------------------------------------------------------------------

def test_mitre_mapper_entries_are_NOT_detected_by_weaver_KNOWN_BUG(weaver, isolated_stamp):
    """
    Root-cause regression test for the "Dossier Generation Bias" bug.

    Writes a ledger entry in the EXACT shape mitre_mapper.py actually
    produces (see yomi_engine/mitre_mapper.py line 131-135:
    record_action("MITRE_MAPPER", "MAPPED", f"Mapped {n} unique tactics
    across {m} anomalies.")) -- no literal MITRE ID like "T1055" ever
    appears in that description string.

    This test asserts the CURRENT (buggy) behavior: the narrative reports
    "No explicit MITRE heuristics detected" even though real mapping
    happened. If weaver.py is ever fixed (e.g. by having mitre_mapper.py
    embed matched tactic IDs into the description, or by having weaver.py
    read a structured field instead of regex-scanning free text), this
    test should start failing and needs to be rewritten to assert the
    fixed behavior instead.
    """
    isolated_stamp.record_action(
        "MITRE_MAPPER",
        "MAPPED",
        "Mapped 2 unique tactics across 5 anomalies.",
    )
    narrative = weaver.generate_narrative()

    # The MITRE_MAPPER event IS in the narrative timeline...
    assert "MITRE_MAPPER" in narrative
    assert "MAPPED" in narrative
    # ...but the dedicated MITRE mapping section below still claims nothing
    # was found, because the regex never had a literal T1XXX to match.
    assert "No explicit MITRE heuristics detected in this sequence." in narrative


def test_mitre_id_IS_detected_when_literally_present_in_description(weaver, isolated_stamp):
    """
    Confirms the regex mechanism itself works correctly in isolation --
    the bug above is a data-shape mismatch (what mitre_mapper.py writes),
    not a broken regex. If some other module ever writes a description
    containing a literal MITRE ID, it IS picked up.
    """
    isolated_stamp.record_action(
        "HUNTER", "ROOT_CAUSE_FOUND", "Correlates to T1055 process injection."
    )
    narrative = weaver.generate_narrative()
    assert "T1055 : Autonomously extracted from ledger context." in narrative
    assert "No explicit MITRE heuristics detected" not in narrative


def test_mitre_regex_respects_valid_id_range_T1000_to_T1699(weaver, isolated_stamp):
    isolated_stamp.record_action("X", "Y", "Reference to T1999 which is out of the valid MITRE technique range.")
    narrative = weaver.generate_narrative()
    assert "T1999" not in narrative.split("[MITRE ATT&CK MAPPING CONFIRMED]")[1]


def test_secure_tail_logs_respects_limit(weaver, isolated_stamp):
    for i in range(60):
        isolated_stamp.record_action("AGENT", "ACTION", f"entry {i}")
    logs = weaver._secure_tail_logs(limit=10)
    assert len(logs) == 10


def test_secure_tail_logs_on_missing_ledger_returns_empty(weaver, tmp_path):
    weaver.ledger_path = str(tmp_path / "does_not_exist.jsonl")
    assert weaver._secure_tail_logs() == []


def test_sanitize_terminal_handles_non_string_input(weaver):
    assert weaver._sanitize_terminal(12345) == "12345"
    assert weaver._sanitize_terminal(None) == "None"
