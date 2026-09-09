"""
Unit tests for yomi_engine.library.OmniLibrary.

CRITICAL SAFETY NOTE: __init__ calls _seed_recent_database(), which makes a
REAL HTTP HEAD request to nvd.nist.gov (_has_network) and, if reachable, a
REAL download attempt (_fetch_nvd_recent) -- and starts a background daemon
thread that repeats this every sync_interval seconds. Every fixture here
mocks _has_network to return False before construction, so no test in this
file ever makes real network I/O. Tests that specifically need network
behavior mock the HTTP layer explicitly instead of hitting the real NVD API.

data_dir is directly injectable via the constructor (unlike stamp.py's
hardcoded __file__-relative path), so isolation here is simpler -- just
pass tmp_path.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def library(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine.library import OmniLibrary

    # Prevent any real network I/O during __init__ (_seed_recent_database).
    monkeypatch.setattr(OmniLibrary, "_has_network", lambda self: False)

    lib = OmniLibrary(data_dir=str(tmp_path / "yomi_data"))
    yield lib
    lib.shutdown()  # stop the background scraping thread cleanly


def _sample_nvd_item(cve_id="CVE-2026-1234", published="2026-03-15T00:00:00.000"):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
            "references": [{"url": "https://example.com/advisory"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
            },
        }
    }


# --------------------------------------------------------------------------
# __init__ / data store setup
# --------------------------------------------------------------------------

def test_init_does_not_make_real_network_calls(library):
    # If this test hangs or errors with a connection error, _has_network
    # wasn't actually mocked correctly -- the fixture's mock is the real
    # assertion here.
    assert library.online is False


def test_init_creates_manifest_with_defaults(library):
    assert Path(library.manifest_file).exists()
    manifest = json.loads(Path(library.manifest_file).read_text())
    assert manifest["total_count"] == 0
    assert manifest["source"] == "LOCAL"


def test_store_permissions_are_restrictive_on_posix(library):
    if sys.platform == "win32":
        pytest.skip("POSIX permissions only")
    import stat as stat_module
    assert stat_module.S_IMODE(Path(library.db_dir).stat().st_mode) == 0o700
    assert stat_module.S_IMODE(Path(library.manifest_file).stat().st_mode) == 0o600


def test_corrupt_manifest_is_backed_up_and_reset(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine.library import OmniLibrary

    monkeypatch.setattr(OmniLibrary, "_has_network", lambda self: False)
    data_dir = tmp_path / "yomi_data"
    db_dir = data_dir / "cve_store"
    db_dir.mkdir(parents=True)
    manifest_file = db_dir / "manifest.json"
    manifest_file.write_text("{not valid json", encoding="utf-8")

    lib = OmniLibrary(data_dir=str(data_dir))
    try:
        corrupt_backups = list(db_dir.glob("manifest.json.corrupt.*"))
        assert len(corrupt_backups) == 1
        assert json.loads(manifest_file.read_text())["total_count"] == 0
    finally:
        lib.shutdown()


# --------------------------------------------------------------------------
# year file save/load round-trip + LRU cache invalidation
# --------------------------------------------------------------------------

def test_save_and_load_year_file_round_trip(library):
    data = {"CVE-2026-0001": {"cve_id": "CVE-2026-0001", "cvss_score": 7.5}}
    library._save_year_file(2026, data)
    library._load_year_file.cache_clear()  # ensure we read from disk, not cache
    assert library._load_year_file(2026) == data


def test_save_year_file_invalidates_cache_for_fresh_read(library):
    library._save_year_file(2026, {"CVE-2026-0001": {"cve_id": "CVE-2026-0001"}})
    library._load_year_file(2026)  # populate cache

    library._save_year_file(2026, {"CVE-2026-0002": {"cve_id": "CVE-2026-0002"}})
    # Without cache invalidation, this would still return the stale first version.
    assert library._load_year_file(2026) == {"CVE-2026-0002": {"cve_id": "CVE-2026-0002"}}


def test_load_year_file_handles_legacy_list_format(library):
    path = library._year_file(2025)
    legacy_list = [
        {"cve_id": "CVE-2025-0001", "cvss_score": 5.0},
        {"cve_id": "CVE-2025-0002", "cvss_score": 6.0},
        {"no_cve_id_field": "should be skipped"},
    ]
    Path(path).write_text(json.dumps(legacy_list), encoding="utf-8")
    library._load_year_file.cache_clear()

    result = library._load_year_file(2025)
    assert set(result.keys()) == {"CVE-2025-0001", "CVE-2025-0002"}


def test_load_year_file_missing_file_returns_empty_dict(library):
    assert library._load_year_file(1999) == {}


# --------------------------------------------------------------------------
# _extract_year_from_entry / _extract_year_from_cve_id
# --------------------------------------------------------------------------

def test_extract_year_prefers_published_date(library):
    entry = {"published_date": "2025-06-01T00:00:00", "cve_id": "CVE-2026-9999"}
    assert library._extract_year_from_entry(entry) == 2025


def test_extract_year_falls_back_to_cve_id_when_no_published_date(library):
    entry = {"cve_id": "CVE-2024-1234"}
    assert library._extract_year_from_entry(entry) == 2024


def test_extract_year_from_malformed_cve_id_returns_none(library):
    assert library._extract_year_from_cve_id("NOT-A-CVE-ID") is None
    assert library._extract_year_from_cve_id("CVE-NOTAYEAR-1234") is None


# --------------------------------------------------------------------------
# _normalize_entry / _compute_entry_hash
# --------------------------------------------------------------------------

def test_normalize_entry_extracts_expected_fields(library):
    result = library._normalize_entry(_sample_nvd_item())
    assert result["cve_id"] == "CVE-2026-1234"
    assert result["cvss_score"] == 9.8
    assert "Description for CVE-2026-1234" in result["description"]
    assert result["references"] == ["https://example.com/advisory"]


def test_normalize_entry_missing_cve_id_returns_none(library):
    assert library._normalize_entry({"cve": {}}) is None


def test_normalize_entry_non_dict_input_returns_none(library):
    assert library._normalize_entry("not a dict") is None


def test_compute_entry_hash_excludes_volatile_fields(library):
    entry_a = {"cve_id": "X", "cvss_score": 1.0, "ingested_at": "2026-01-01T00:00:00Z"}
    entry_b = {"cve_id": "X", "cvss_score": 1.0, "ingested_at": "2099-12-31T23:59:59Z"}
    # Differ only in ingested_at (excluded from the hash) -- hashes must match.
    assert library._compute_entry_hash(entry_a) == library._compute_entry_hash(entry_b)


def test_compute_entry_hash_changes_when_real_content_changes(library):
    entry_a = {"cve_id": "X", "cvss_score": 1.0}
    entry_b = {"cve_id": "X", "cvss_score": 9.9}
    assert library._compute_entry_hash(entry_a) != library._compute_entry_hash(entry_b)


# --------------------------------------------------------------------------
# _merge_external_entries: added/updated dedup logic
# --------------------------------------------------------------------------

def test_merge_new_entries_counts_as_added(library):
    added = library._merge_external_entries([_sample_nvd_item("CVE-2026-0001")])
    assert added == 1
    assert library.query_cve("CVE-2026-0001") is not None


def test_merge_identical_entry_twice_does_not_double_count(library):
    item = _sample_nvd_item("CVE-2026-0002")
    library._merge_external_entries([item])
    added_second_time = library._merge_external_entries([item])
    assert added_second_time == 0  # unchanged content -> not counted as "added"


def test_merge_changed_entry_updates_in_place(library):
    item_v1 = _sample_nvd_item("CVE-2026-0003")
    library._merge_external_entries([item_v1])

    item_v2 = _sample_nvd_item("CVE-2026-0003")
    item_v2["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 1.0
    library._merge_external_entries([item_v2])

    updated_entry = library.query_cve("CVE-2026-0003")
    assert updated_entry["cvss_score"] == 1.0


# --------------------------------------------------------------------------
# query_cve
# --------------------------------------------------------------------------

def test_query_cve_returns_deepcopy_not_shared_reference(library):
    library._merge_external_entries([_sample_nvd_item("CVE-2026-0004")])
    result_1 = library.query_cve("CVE-2026-0004")
    result_1["cvss_score"] = "MUTATED"

    result_2 = library.query_cve("CVE-2026-0004")
    assert result_2["cvss_score"] != "MUTATED"  # first mutation didn't leak through


def test_query_cve_unknown_id_returns_none(library):
    assert library.query_cve("CVE-1999-9999") is None


def test_query_cve_invalid_input_returns_none(library):
    assert library.query_cve("") is None
    assert library.query_cve(None) is None


# --------------------------------------------------------------------------
# analyze_artifact
# --------------------------------------------------------------------------

def test_analyze_artifact_finds_keyword_match(library):
    library._merge_external_entries([_sample_nvd_item("CVE-2026-0005")])
    result = library.analyze_artifact("CVE-2026-0005")
    assert result["status"] == "THREAT_FOUND"
    assert len(result["matches"]) == 1


def test_analyze_artifact_no_match_returns_clean(library):
    result = library.analyze_artifact("totally_benign_file.txt")
    assert result["status"] == "CLEAN_OR_UNKNOWN"
    assert result["matches"] == []


def test_analyze_artifact_realistic_decorated_filename_now_matches(library):
    """
    Regression test for the FIXED bug (previously
    test_analyze_artifact_KNOWN_BUG_realistic_filenames_never_match
    documented this as broken). A realistic filename with a CVE ID
    embedded among other text must now match, via the extracted-CVE-ID
    fast path added to analyze_artifact.
    """
    library._merge_external_entries([_sample_nvd_item("CVE-2026-0006")])
    result = library.analyze_artifact("suspicious_cve-2026-0006_dropper.exe")
    assert result["status"] == "THREAT_FOUND"
    assert result["matches"][0]["cve_id"] == "CVE-2026-0006"


def test_analyze_artifact_context_hint_matches_description_keyword(library):
    library._merge_external_entries([_sample_nvd_item("CVE-2026-0007")])
    # "Description for CVE-2026-0007" is the seeded description text --
    # a hint matching a word within it should still work (this direction
    # was already correct pre-fix, confirming the fix didn't break it).
    result = library.analyze_artifact("unrelated_file.exe", context_hints=["Description for"])
    assert result["status"] == "THREAT_FOUND"


def test_analyze_artifact_unrelated_filename_and_hints_stay_clean(library):
    library._merge_external_entries([_sample_nvd_item("CVE-2026-0008")])
    result = library.analyze_artifact("completely_unrelated_benign_tool.exe", context_hints=["nothing_matching_here"])
    assert result["status"] == "CLEAN_OR_UNKNOWN"


def test_analyze_artifact_invalid_name_returns_error(library):
    result = library.analyze_artifact("")
    assert result["status"] == "ERROR"


def test_analyze_artifact_caps_results_at_max(library):
    for i in range(5):
        library._merge_external_entries([_sample_nvd_item(f"CVE-2026-100{i}")])
    result = library.analyze_artifact("CVE-2026")  # matches all 5 via substring
    assert len(result["matches"]) <= 3


# --------------------------------------------------------------------------
# _fetch_nvd_recent: mocked HTTP + LZMA pipeline (one integration-flavored test)
# --------------------------------------------------------------------------

def test_fetch_nvd_recent_end_to_end_with_mocked_http(library, monkeypatch):
    import lzma
    import io as io_module

    payload = {"vulnerabilities": [_sample_nvd_item("CVE-2026-8888")]}
    compressed = lzma.compress(json.dumps(payload).encode("utf-8"))

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = compressed
    monkeypatch.setattr(library.session, "get", lambda *a, **k: fake_response)

    result = library._fetch_nvd_recent()
    assert result is True
    assert library.query_cve("CVE-2026-8888") is not None
    assert library.online is True


def test_fetch_url_network_error_returns_none(library, monkeypatch):
    import requests as requests_module

    def raise_error(*a, **k):
        raise requests_module.RequestException("simulated network failure")

    monkeypatch.setattr(library.session, "get", raise_error)
    assert library._fetch_url("https://example.com/whatever") is None


# --------------------------------------------------------------------------
# shutdown / background thread hygiene
# --------------------------------------------------------------------------

def test_shutdown_sets_stop_event(library):
    assert not library.stop_event.is_set()
    library.shutdown()
    assert library.stop_event.is_set()
