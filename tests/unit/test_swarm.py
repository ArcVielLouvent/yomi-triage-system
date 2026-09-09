"""
Unit tests for yomi_engine.swarm.SwarmOrchestrator.

lock_vault is hardcoded relative to __file__ (same pattern as
remediator.py/sandbox.py) -- isolated the same way.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def swarm(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import swarm as swarm_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(swarm_module, "__file__", str(fake_module_dir / "swarm.py"))
    monkeypatch.setattr("shutil.which", lambda name: None)

    return swarm_module.SwarmOrchestrator()


# --------------------------------------------------------------------------
# _sanitize_log
# --------------------------------------------------------------------------

def test_sanitize_masks_password_field(swarm):
    result = swarm._sanitize_log("password: SuperSecret123 in the logs")
    assert "SuperSecret123" not in result
    assert "***MASKED***" in result


def test_sanitize_masks_api_key_with_equals_sign(swarm):
    result = swarm._sanitize_log("api_key=abc123XYZ")
    assert "abc123XYZ" not in result


def test_sanitize_masks_xml_style_secret_tag(swarm):
    result = swarm._sanitize_log("<token>eyJhbGciOiJIUzI1NiJ9</token>")
    assert "eyJhbGciOiJIUzI1NiJ9" not in result


def test_sanitize_masks_bearer_token(swarm):
    result = swarm._sanitize_log("Authorization: Bearer abc.def-ghi_123")
    assert "abc.def-ghi_123" not in result
    assert "Bearer ***MASKED***" in result


def test_sanitize_leaves_unrelated_text_untouched(swarm):
    text = "Process 1234 spawned child 5678 with no secrets here."
    assert swarm._sanitize_log(text) == text


# --------------------------------------------------------------------------
# _is_external_ip
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip,expected",
    [
        ("192.168.1.1", False),   # private
        ("10.0.0.1", False),      # private
        ("127.0.0.1", False),     # loopback
        ("169.254.1.1", False),   # link-local
        ("224.0.0.1", False),     # multicast
        ("8.8.8.8", True),        # public
        ("1.1.1.1", True),        # public
        ("not_an_ip", False),     # invalid
    ],
)
def test_is_external_ip(swarm, ip, expected):
    assert swarm._is_external_ip(ip) is expected


# --------------------------------------------------------------------------
# _extract_external_ips / _extract_suspect_pids
# --------------------------------------------------------------------------

def test_extract_external_ips_filters_private_and_finds_public(swarm):
    text = "connected to 192.168.1.5 and 8.8.8.8 and also 1.1.1.1"
    result = swarm._extract_external_ips(text)
    assert result == ["1.1.1.1", "8.8.8.8"]  # sorted, private excluded


def test_extract_external_ips_deduplicates(swarm):
    text = "8.8.8.8 appeared twice: 8.8.8.8"
    assert swarm._extract_external_ips(text) == ["8.8.8.8"]


def test_extract_suspect_pids_various_formats(swarm):
    text = "pid: 1234, PID=5678, pid 9999"
    result = swarm._extract_suspect_pids(text)
    assert result == [1234, 5678, 9999]


def test_extract_suspect_pids_deduplicates_and_sorts(swarm):
    text = "pid=500 pid=100 pid=500"
    assert swarm._extract_suspect_pids(text) == [100, 500]


# --------------------------------------------------------------------------
# _resolve_and_pin_inode
# --------------------------------------------------------------------------

def test_pin_inode_hardlink_success(swarm, tmp_path):
    source = tmp_path / "evidence.raw"
    source.write_bytes(b"memory dump content")

    result = swarm._resolve_and_pin_inode([str(source)])
    assert result is not None
    assert result.startswith(swarm.lock_vault)
    assert Path(result).read_bytes() == b"memory dump content"


def test_pin_inode_skips_nonexistent_candidates(swarm, tmp_path):
    source = tmp_path / "real.raw"
    source.write_bytes(b"data")
    result = swarm._resolve_and_pin_inode(["/nonexistent/fake.raw", str(source)])
    assert result is not None


def test_pin_inode_skips_non_regular_files(swarm, tmp_path):
    directory = tmp_path / "not_a_file"
    directory.mkdir()
    result = swarm._resolve_and_pin_inode([str(directory)])
    assert result is None


def test_pin_inode_all_candidates_fail_returns_none(swarm):
    result = swarm._resolve_and_pin_inode(["", None, "/nonexistent/a", "/nonexistent/b"])
    assert result is None


def test_pin_inode_falls_back_to_readonly_original_when_disk_low(swarm, tmp_path, monkeypatch):
    source = tmp_path / "evidence.raw"
    source.write_bytes(b"data")

    monkeypatch.setattr("os.link", MagicMock(side_effect=OSError("cross-device link")))

    fake_usage = MagicMock()
    fake_usage.free = 1000  # far below the 500MB safety margin
    monkeypatch.setattr("shutil.disk_usage", lambda path: fake_usage)

    result = swarm._resolve_and_pin_inode([str(source)])
    assert result == str(source.resolve())

    mode = stat.S_IMODE(source.stat().st_mode)
    assert mode & stat.S_IWUSR == 0  # write bit removed (anti-tampering)


def test_pin_inode_falls_back_to_copy_when_disk_has_space(swarm, tmp_path, monkeypatch):
    source = tmp_path / "evidence.raw"
    source.write_bytes(b"data")

    monkeypatch.setattr("os.link", MagicMock(side_effect=OSError("cross-device link")))

    fake_usage = MagicMock()
    fake_usage.free = 999_999_999_999  # plenty of space
    monkeypatch.setattr("shutil.disk_usage", lambda path: fake_usage)

    result = swarm._resolve_and_pin_inode([str(source)])
    assert result is not None
    assert result.startswith(swarm.lock_vault)
    assert Path(result).read_bytes() == b"data"


# --------------------------------------------------------------------------
# _live_network_findings
# --------------------------------------------------------------------------

def test_live_network_findings_detects_external_connection(swarm, monkeypatch):
    fake_conn = MagicMock()
    fake_conn.status = "ESTABLISHED"
    fake_conn.raddr = MagicMock(ip="8.8.8.8")
    fake_conn.pid = 4321

    monkeypatch.setattr("psutil.net_connections", lambda kind="inet": [fake_conn])
    findings = swarm._live_network_findings()
    joined = " ".join(findings)
    assert "8.8.8.8" in joined
    assert "4321" in joined


def test_live_network_findings_no_anomalies_reports_clean(swarm, monkeypatch):
    monkeypatch.setattr("psutil.net_connections", lambda kind="inet": [])
    findings = swarm._live_network_findings()
    assert any("without explicit external endpoint anomalies" in f for f in findings)


def test_live_network_findings_exception_is_caught(swarm, monkeypatch):
    def raise_error(kind="inet"):
        raise psutil_error

    import psutil as psutil_module
    psutil_error = psutil_module.AccessDenied(1234)
    monkeypatch.setattr("psutil.net_connections", raise_error)

    findings = swarm._live_network_findings()  # must not raise
    assert any("[ERROR]" in f for f in findings)


# --------------------------------------------------------------------------
# _memory_agent / _network_agent
# --------------------------------------------------------------------------

def test_memory_agent_no_dump_defers_to_network(swarm, monkeypatch):
    monkeypatch.setattr(swarm, "_resolve_and_pin_inode", lambda candidates: None)
    result = swarm._memory_agent()
    assert result["agent"] == "Memory_Agent"
    assert any("Deferring to network agent" in f for f in result["findings"])


def test_memory_agent_with_dump_extracts_findings_and_cleans_up(swarm, tmp_path, monkeypatch):
    pinned_path = os.path.join(swarm.lock_vault, "pinned_test.raw")
    Path(pinned_path).write_bytes(b"x")
    monkeypatch.setattr(swarm, "_resolve_and_pin_inode", lambda candidates: pinned_path)
    monkeypatch.setattr(
        swarm.arsenal, "run_volatility_netscan",
        lambda path: {"status": "SUCCESS", "output": "connection to 8.8.8.8 pid: 999"},
    )

    result = swarm._memory_agent()
    joined = " ".join(result["findings"])
    assert "8.8.8.8" in joined
    assert "999" in joined
    assert not os.path.exists(pinned_path)  # cleaned up after use


def test_memory_agent_tool_failure_reports_error(swarm, monkeypatch):
    monkeypatch.setattr(swarm, "_resolve_and_pin_inode", lambda candidates: "/fake/dump.raw")
    monkeypatch.setattr(
        swarm.arsenal, "run_volatility_netscan",
        lambda path: {"status": "ERROR", "error": "tool unavailable"},
    )
    result = swarm._memory_agent()
    assert any("unavailable" in f for f in result["findings"])


def test_network_agent_c2_precision_bare_hostname_does_not_false_positive(swarm, tmp_path, monkeypatch):
    """
    Confirms the documented "False Positive immune C2 query detection"
    claim: the bare string "http.host" (e.g. appearing as part of a local
    file path or unrelated text) must NOT trigger a C2 finding -- only a
    genuine query-style match (http.host==, dns.qry.name==, or a real
    'Host: ' header) should.
    """
    pinned_path = os.path.join(swarm.lock_vault, "pinned_test.pcap")
    Path(pinned_path).write_bytes(b"x")
    monkeypatch.setattr(swarm, "_resolve_and_pin_inode", lambda candidates: pinned_path)
    monkeypatch.setattr(
        swarm.arsenal, "run_tshark_pcap",
        lambda path: {"status": "SUCCESS", "output": "/var/log/http.host.access.log referenced"},
    )

    result = swarm._network_agent()
    joined = " ".join(result["findings"])
    assert "command-and-control" not in joined


def test_network_agent_c2_precision_real_query_syntax_matches(swarm, monkeypatch):
    pinned_path = os.path.join(swarm.lock_vault, "pinned_test2.pcap")
    Path(pinned_path).write_bytes(b"x")
    monkeypatch.setattr(swarm, "_resolve_and_pin_inode", lambda candidates: pinned_path)
    monkeypatch.setattr(
        swarm.arsenal, "run_tshark_pcap",
        lambda path: {"status": "SUCCESS", "output": "filter applied: http.host == evil.example.com"},
    )

    result = swarm._network_agent()
    joined = " ".join(result["findings"])
    assert "command-and-control" in joined


def test_network_agent_no_pcap_falls_back_to_live_inspection(swarm, monkeypatch):
    monkeypatch.setattr(swarm, "_resolve_and_pin_inode", lambda candidates: None)
    monkeypatch.setattr(swarm, "_live_network_findings", lambda: ["live finding marker"])

    result = swarm._network_agent()
    assert "live finding marker" in result["findings"]


# --------------------------------------------------------------------------
# deploy_swarm: orchestration wiring
# --------------------------------------------------------------------------

def test_deploy_swarm_collects_both_agent_reports(swarm, monkeypatch):
    monkeypatch.setattr(swarm, "_memory_agent", lambda: {"agent": "Memory_Agent", "findings": ["mem ok"]})
    monkeypatch.setattr(swarm, "_network_agent", lambda: {"agent": "Network_Agent", "findings": ["net ok"]})

    result = swarm.deploy_swarm()
    assert result["status"] == "SWARM_COMPLETE"
    agents = {r["agent"] for r in result["reports"]}
    assert agents == {"Memory_Agent", "Network_Agent"}


def test_deploy_swarm_seals_completion_to_ledger(swarm, isolated_stamp, monkeypatch):
    monkeypatch.setattr(swarm, "_memory_agent", lambda: {"agent": "Memory_Agent", "findings": []})
    monkeypatch.setattr(swarm, "_network_agent", lambda: {"agent": "Network_Agent", "findings": []})

    swarm.deploy_swarm()
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        import json
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "DEPLOYED"
