"""
Unit tests for yomi_engine.correlator.CrossArtifactCorrelator.

Fixtures build inputs shaped exactly like the real return values of
Hunter.hunt_root_cause(), MitreMapper.map_anomalies(), and
SwarmOrchestrator.deploy_swarm()["reports"] -- correlate() is a pure
synthesis function over those shapes, no I/O of its own beyond the audit
ledger seal.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def correlator(isolated_stamp):
    from yomi_engine.correlator import CrossArtifactCorrelator
    return CrossArtifactCorrelator()


def _ledger_action_types(isolated_stamp):
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        return [json.loads(l)["action_type"] for l in f if l.strip()]


# --------------------------------------------------------------------------
# correlate: basic ingestion / coverage gaps
# --------------------------------------------------------------------------

def test_correlate_with_no_inputs_reports_full_coverage_gaps(correlator):
    case = correlator.correlate(1234)
    assert case.target_pid == 1234
    assert "timeline (Plaso) unavailable or empty" in case.coverage_gaps
    assert "filesystem (TSK) unavailable or empty" in case.coverage_gaps
    assert "registry (reglookup) unavailable or empty" in case.coverage_gaps
    assert "network agent did not report" in case.coverage_gaps
    assert "memory agent did not report" in case.coverage_gaps


def test_correlate_ingests_hunt_result_timeline_and_filesystem(correlator):
    case = correlator.correlate(
        1234,
        hunt_result={"temporal_vector": "Shell execution found", "spatial_vector": "Deleted mimikatz.exe found"},
    )
    assert any("Shell execution found" == e["detail"] for e in case.timeline_events)
    assert any("Deleted mimikatz.exe found" == e["detail"] for e in case.filesystem_artifacts)
    assert "timeline (Plaso) unavailable or empty" not in case.coverage_gaps


def test_correlate_registry_skipped_status_is_a_distinct_gap(correlator):
    case = correlator.correlate(1234, registry_result={"status": "SKIPPED", "registry_vector": None})
    assert "registry hunt skipped (no hive path configured)" in case.coverage_gaps
    assert "registry (reglookup) unavailable or empty" not in case.coverage_gaps


def test_correlate_ingests_registry_findings_when_present(correlator):
    case = correlator.correlate(
        1234,
        registry_result={"status": "HUNT_COMPLETE", "registry_vector": "Run key persistence found"},
    )
    assert any("Run key persistence found" == e["detail"] for e in case.registry_findings)


def test_correlate_buckets_swarm_reports_by_agent_name(correlator):
    case = correlator.correlate(
        1234,
        swarm_reports=[
            {"agent": "Network_Agent", "findings": ["clean scan"]},
            {"agent": "Memory_Agent", "findings": ["suspicious region"]},
        ],
    )
    assert any(f["detail"] == "clean scan" for f in case.network_findings)
    assert any(f["detail"] == "suspicious region" for f in case.memory_findings)
    assert "network agent did not report" not in case.coverage_gaps
    assert "memory agent did not report" not in case.coverage_gaps


def test_correlate_ingests_mitre_tactics(correlator):
    case = correlator.correlate(
        1234,
        mapped_tactics=[
            {
                "raw_evidence": "ransom encrypt",
                "matched_tactics": [{"mitre_id": "T1486", "tactical_desc": "Data Encrypted for Impact"}],
            }
        ],
    )
    assert any(t["mitre_id"] == "T1486" for t in case.mitre_tactics)


def test_correlate_ingests_mind_reader_signature_as_cve_correlation(correlator):
    case = correlator.correlate(
        1234,
        mind_reader_result={"status": "SUCCESS", "signature_id": "CVE-2026-YOMI1234"},
    )
    assert any(c["cve_id"] == "CVE-2026-YOMI1234" for c in case.cve_correlations)


def test_correlate_non_success_mind_reader_result_is_ignored(correlator):
    case = correlator.correlate(
        1234,
        mind_reader_result={"status": "ERROR", "message": "binary not found"},
    )
    assert case.cve_correlations == []


def test_correlate_seals_summary_to_ledger(correlator, isolated_stamp):
    correlator.correlate(1234)
    assert "CASE_FILE_COMPILED" in _ledger_action_types(isolated_stamp)


# --------------------------------------------------------------------------
# T1071 (C2) corroboration -- the key nuance: swarm.py's own "clean"
# findings contain the words "external" and "C2" (e.g. "...without
# obvious external C2 anomalies"), so a loose substring match would
# wrongly corroborate off a finding that explicitly found nothing.
# --------------------------------------------------------------------------

def test_t1071_corroborated_when_network_agent_confirms_external_connection(correlator):
    case = correlator.correlate(
        1234,
        mapped_tactics=[
            {"raw_evidence": "beacon", "matched_tactics": [{"mitre_id": "T1071", "tactical_desc": "Application Layer Protocol (C2)"}]}
        ],
        swarm_reports=[
            {"agent": "Network_Agent", "findings": ["Live Kernel Socket Scan: external connection(s) observed to 8.8.8.8."]}
        ],
    )
    assert "T1071" in case.corroborated_tactics
    assert case.contradictions == []


def test_t1071_is_a_contradiction_when_network_agent_finds_nothing(correlator):
    """
    Regression guard for the exact false-positive this correlator exists
    to prevent: a MitreMapper keyword hit on anomaly text alone, with the
    network agent's own "clean" wording ("without obvious external C2
    anomalies") mentioning the same words but confirming nothing.
    """
    case = correlator.correlate(
        1234,
        mapped_tactics=[
            {"raw_evidence": "outbound beacon", "matched_tactics": [{"mitre_id": "T1071", "tactical_desc": "Application Layer Protocol (C2)"}]}
        ],
        swarm_reports=[
            {"agent": "Network_Agent", "findings": ["TShark completed without obvious external C2 anomalies."]}
        ],
    )
    assert "T1071" not in case.corroborated_tactics
    assert any(c["claim"].startswith("T1071") for c in case.contradictions)


def test_t1071_is_a_contradiction_when_network_agent_did_not_report_at_all(correlator):
    case = correlator.correlate(
        1234,
        mapped_tactics=[
            {"raw_evidence": "beacon", "matched_tactics": [{"mitre_id": "T1071", "tactical_desc": "Application Layer Protocol (C2)"}]}
        ],
    )
    assert "T1071" not in case.corroborated_tactics
    assert any(c["claim"].startswith("T1071") for c in case.contradictions)


def test_no_t1071_claim_means_no_c2_contradiction_or_corroboration(correlator):
    case = correlator.correlate(1234)
    assert "T1071" not in case.corroborated_tactics
    assert not any(c["claim"].startswith("T1071") for c in case.contradictions)


# --------------------------------------------------------------------------
# T1055 (Process Injection) corroboration -- same principle, cross-checked
# against the Plaso timeline instead of network findings.
# --------------------------------------------------------------------------

def test_t1055_corroborated_when_timeline_confirms_injection(correlator):
    case = correlator.correlate(
        1234,
        hunt_result={"temporal_vector": "Unbacked executable region detected near PID 1234"},
        mapped_tactics=[
            {"raw_evidence": "shellcode inject", "matched_tactics": [{"mitre_id": "T1055", "tactical_desc": "Process Injection (VAD manipulation)"}]}
        ],
    )
    assert "T1055" in case.corroborated_tactics


def test_t1055_is_a_contradiction_when_timeline_does_not_confirm(correlator):
    case = correlator.correlate(
        1234,
        hunt_result={"temporal_vector": "Ordinary bash shell execution, nothing anomalous"},
        mapped_tactics=[
            {"raw_evidence": "shellcode inject", "matched_tactics": [{"mitre_id": "T1055", "tactical_desc": "Process Injection (VAD manipulation)"}]}
        ],
    )
    assert "T1055" not in case.corroborated_tactics
    assert any(c["claim"].startswith("T1055") for c in case.contradictions)


# --------------------------------------------------------------------------
# CorrelatedCaseFile.to_report_text / to_dict
# --------------------------------------------------------------------------

def test_to_dict_returns_plain_dict(correlator):
    case = correlator.correlate(1234)
    d = case.to_dict()
    assert isinstance(d, dict)
    assert d["target_pid"] == 1234


def test_to_report_text_includes_incident_id_and_pid(correlator):
    case = correlator.correlate(5678)
    text = case.to_report_text()
    assert "5678" in text
    assert case.incident_id in text


def test_to_report_text_shows_contradictions_section(correlator):
    case = correlator.correlate(
        1234,
        mapped_tactics=[
            {"raw_evidence": "beacon", "matched_tactics": [{"mitre_id": "T1071", "tactical_desc": "Application Layer Protocol (C2)"}]}
        ],
    )
    text = case.to_report_text()
    assert "CONTRADICTIONS" in text
    assert "T1071" in text
