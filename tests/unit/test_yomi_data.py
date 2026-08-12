"""
Unit tests for yomi_data/__init__.py: symlink rejection, ownership/permission
assertions, manifest self-repair, corrupt-file quarantine, and the CVE year-store
read/write path.

Uses the `yomi_data_env` fixture (see conftest.py) which redirects this
module's path constants to a temp directory -- these tests never touch the
real repository's yomi_data/.
"""
from __future__ import annotations

import json
import os
import platform

import pytest


def test_validate_data_store_on_fresh_store_is_clean(yomi_data_env):
    result = yomi_data_env.validate_data_store()
    assert result["actual_total_count"] == 0
    assert result["counts_match"] is True
    assert result["manifest_needs_repair"] is False
    assert result["corrupt_year_files"] == []
    assert result["invalid_year_candidates"] == []


def test_write_and_load_year_store_round_trip(yomi_data_env):
    # NOTE: entry value MUST include a "cve_id" field matching its own dict
    # key -- _validate_year_file() enforces this on every read. See
    # test_write_year_store_silently_drops_entries_missing_cve_id below for
    # what happens when this invariant isn't met (it is NOT enforced on
    # write, only on the next read/scan -- that asymmetry is a real bug).
    entries = {"CVE-2026-0001": {"cve_id": "CVE-2026-0001", "cvss": 9.8, "desc": "test entry"}}
    yomi_data_env.write_year_store(2026, entries)

    loaded = yomi_data_env.load_year_store(2026)
    assert loaded == entries

    result = yomi_data_env.validate_data_store()
    assert result["actual_total_count"] == 1
    assert result["year_files"] == [2026]
    assert result["counts_match"] is True  # manifest self-repairs on validate


def test_manifest_repairs_when_year_files_drift(yomi_data_env):
    yomi_data_env.write_year_store(2025, {"CVE-2025-1": {"cve_id": "CVE-2025-1"}})
    yomi_data_env.write_year_store(
        2026, {"CVE-2026-1": {"cve_id": "CVE-2026-1"}, "CVE-2026-2": {"cve_id": "CVE-2026-2"}}
    )

    result = yomi_data_env.validate_data_store()
    assert result["actual_total_count"] == 3
    assert result["manifest_total_count"] == 3
    assert sorted(result["year_files"]) == [2025, 2026]


def test_write_year_store_silently_drops_entries_missing_cve_id(yomi_data_env):
    """
    KNOWN BUG (found via this test, not yet fixed in source):
    `write_year_store()` performs zero shape validation -- it will happily
    write an entry dict that doesn't carry a matching `cve_id` field. The
    mismatch is only caught later, by `_validate_year_file()`, which is
    invoked on *read* (`load_year_store`) or during a store *scan*
    (`validate_data_store`). When it's caught, the entire year file is
    quarantined and the caller silently gets back `{}` / a corrupt-file
    entry -- with no exception raised at write time to say why.

    This test exists to make that failure mode explicit and regression-safe:
    if `write_year_store` is ever fixed to validate on write (the correct
    fix), this test should start failing loudly and needs to be rewritten
    to assert the new (safe) behavior instead.
    """
    malformed_entries = {"CVE-2026-9999": {"cvss": 5.0}}  # missing cve_id field
    yomi_data_env.write_year_store(2026, malformed_entries)  # succeeds, no error

    loaded = yomi_data_env.load_year_store(2026)
    assert loaded == {}  # <-- data silently vanished

    result = yomi_data_env.validate_data_store()
    assert any("2026.json" in f for f in result["corrupt_year_files"])


def test_invalid_year_filename_is_flagged_not_crashed(yomi_data_env):
    bad_file = yomi_data_env.CVE_STORE_DIR / "not_a_year.json"
    bad_file.write_text("{}", encoding="utf-8")

    result = yomi_data_env.validate_data_store()
    assert str(bad_file) in result["invalid_year_candidates"]
    assert result["manifest_needs_repair"] is True


def test_corrupt_json_year_file_is_quarantined_not_crashed(yomi_data_env):
    corrupt_file = yomi_data_env.CVE_STORE_DIR / "2024.json"
    corrupt_file.write_text("{not valid json!!", encoding="utf-8")

    result = yomi_data_env.validate_data_store()
    assert str(corrupt_file) in result["corrupt_year_files"]
    # Original file must still exist untouched (quarantine backs up
    # separately rather than destroying the source on scan).
    assert corrupt_file.exists()


def test_corrupt_manifest_is_quarantined_and_reset_to_default(yomi_data_env):
    yomi_data_env.MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    yomi_data_env.MANIFEST_FILE.write_text("{{{ broken json", encoding="utf-8")

    manifest = yomi_data_env.validate_manifest()
    assert manifest == yomi_data_env.DEFAULT_MANIFEST

    quarantined = list(yomi_data_env.CVE_STORE_DIR.glob("manifest.json.corrupt.*.json"))
    assert len(quarantined) == 1
    backup_content = json.loads(quarantined[0].read_text(encoding="utf-8"))
    assert "broken json" in backup_content["raw_data"]


@pytest.mark.skipif(platform.system() == "Windows", reason="symlink semantics differ on Windows")
def test_symlinked_ledger_file_is_rejected(yomi_data_env, tmp_path):
    yomi_data_env._ensure_ledger_file()
    real_target = tmp_path / "evil_target.jsonl"
    real_target.write_text("", encoding="utf-8")

    yomi_data_env.LEDGER_FILE.unlink()
    os.symlink(real_target, yomi_data_env.LEDGER_FILE)

    with pytest.raises(ValueError, match="must not be a symlink"):
        yomi_data_env._assert_not_symlink(yomi_data_env.LEDGER_FILE)

    with pytest.raises(ValueError):
        yomi_data_env.validate_data_store()


def test_read_latest_ledger_entry_empty_ledger_returns_none(yomi_data_env):
    yomi_data_env._ensure_ledger_file()
    assert yomi_data_env.read_latest_ledger_entry() is None


def test_read_latest_ledger_entry_returns_last_json_line(yomi_data_env):
    yomi_data_env._ensure_ledger_file()
    entry1 = {"action": "FIRST"}
    entry2 = {"action": "SECOND"}
    with open(yomi_data_env.LEDGER_FILE, "w", encoding="utf-8") as f:
        f.write(json.dumps(entry1) + "\n")
        f.write(json.dumps(entry2) + "\n")

    assert yomi_data_env.read_latest_ledger_entry() == entry2


def test_read_latest_ledger_entry_malformed_last_line_returns_none(yomi_data_env):
    yomi_data_env._ensure_ledger_file()
    with open(yomi_data_env.LEDGER_FILE, "w", encoding="utf-8") as f:
        f.write("{not json")
    assert yomi_data_env.read_latest_ledger_entry() is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
def test_atomic_write_json_sets_owner_read_write_only(yomi_data_env, tmp_path):
    import stat as stat_module

    target = tmp_path / "secure_test.json"
    yomi_data_env._atomic_write_json(target, {"key": "value"})
    mode = stat_module.S_IMODE(target.stat().st_mode)
    assert mode == 0o600
