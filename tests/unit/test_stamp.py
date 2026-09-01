"""
Unit tests for yomi_audit.stamp.ImmutableStamp.

Scope: this is Lapisan 0 -- the trust foundation everything else forges
against. If these tests are wrong or incomplete, every higher-layer test
that assumes "the ledger is correct" is standing on nothing. Coverage
target for this file specifically is high: hash chaining, HMAC signing,
tamper detection, genesis handling, and the singleton contract.
"""
from __future__ import annotations

import json

import pytest


def test_singleton_returns_same_instance(isolated_stamp):
    from yomi_audit.stamp import ImmutableStamp

    second = ImmutableStamp()
    assert second is isolated_stamp


def test_fresh_ledger_creates_genesis_entry(isolated_stamp):
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    assert len(lines) == 1
    genesis = json.loads(lines[0])
    assert genesis["action_type"] == "GENESIS"
    assert genesis["previous_hash"] == isolated_stamp.GENESIS_PREVIOUS_HASH
    assert len(genesis["hash"]) == 64


def test_record_action_chains_to_previous_hash(isolated_stamp):
    genesis_hash = isolated_stamp.last_hash
    new_hash = isolated_stamp.record_action(
        agent_name="TEST_AGENT",
        action_type="TEST_ACTION",
        description="unit test entry",
    )
    assert new_hash != genesis_hash

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert len(lines) == 2
    assert lines[1]["previous_hash"] == genesis_hash
    assert lines[1]["hash"] == new_hash
    assert lines[1]["agent"] == "TEST_AGENT"


def test_record_action_returns_verifiable_ledger(isolated_stamp):
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "first")
    isolated_stamp.record_action("AGENT_B", "ACTION_2", "second")
    isolated_stamp.record_action("AGENT_C", "ACTION_3", "third")
    assert isolated_stamp.verify_ledger() is True
    assert isolated_stamp.get_ledger_summary()["entry_count"] == 4  # genesis + 3


def test_hmac_present_when_key_available(isolated_stamp):
    if not isolated_stamp.hmac_key:
        pytest.skip("HMAC key not generated in this environment")
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "hmac check")
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert "entry_hmac" in lines[-1]
    assert lines[-1]["entry_hmac"] is not None


def test_tampered_hash_fails_verification(isolated_stamp):
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "will be tampered")

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    tampered = json.loads(lines[-1])
    tampered["description"] = "MALICIOUSLY ALTERED AFTER THE FACT"
    lines[-1] = json.dumps(tampered) + "\n"
    with open(isolated_stamp.ledger_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert isolated_stamp.verify_ledger() is False


def test_broken_chain_fails_verification(isolated_stamp):
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "entry one")
    isolated_stamp.record_action("AGENT_B", "ACTION_2", "entry two")

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    entry = json.loads(lines[-1])
    entry["previous_hash"] = "f" * 64  # deliberately wrong link
    lines[-1] = json.dumps(entry) + "\n"
    with open(isolated_stamp.ledger_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert isolated_stamp.verify_ledger() is False


def test_missing_required_field_fails_verification(isolated_stamp):
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "entry one")

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    entry = json.loads(lines[-1])
    del entry["agent"]
    lines[-1] = json.dumps(entry) + "\n"
    with open(isolated_stamp.ledger_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert isolated_stamp.verify_ledger() is False


def test_record_action_defaults_are_safe_types(isolated_stamp):
    # tool_args / metadata omitted entirely -- must not raise, must default
    # to empty dict rather than None (downstream consumers assume dicts).
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "no optional args")
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert lines[-1]["tool_arguments"] == {}
    assert lines[-1]["metadata"] == {}


def test_get_ledger_summary_shape(isolated_stamp):
    summary = isolated_stamp.get_ledger_summary()
    assert set(summary.keys()) == {
        "ledger_file", "last_hash", "ledger_version", "entry_count", "hmac_enabled",
    }
    assert summary["entry_count"] == 1  # genesis only
