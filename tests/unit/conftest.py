"""
Shared fixtures for Lapisan 0 (foundation) unit tests.

Key problem these fixtures solve: `ImmutableStamp` is a strict singleton
whose `data_dir` is computed from `os.path.dirname(__file__)` at
`_initialize()` time -- there is no constructor argument to redirect it.
Left unguarded, importing/instantiating it in a test suite would write real
ledger entries into the actual project's `yomi_data/` directory.

`isolated_stamp` fixture below:
1. Resets the singleton (`ImmutableStamp._instance = None`) so a fresh
   instance is built for every test (no state leaking between tests).
2. Monkeypatches the module's `__file__` global to a path inside a pytest
   `tmp_path`, so `_initialize()`'s relative `../yomi_data` resolution lands
   in an isolated temp directory instead of the real one.
3. Forces ephemeral/no-KMS HMAC mode via env vars so tests never touch a
   real KMS/Vault/Secrets Manager endpoint or prompt for a password.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the project root importable when tests are run from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from yomi_audit import stamp as stamp_module


@pytest.fixture
def isolated_stamp(tmp_path, monkeypatch):
    """
    Yields a fresh, isolated ImmutableStamp instance backed by a temp dir.
    Ledger, HMAC key, checkpoint, and lock files all live under
    `tmp_path/fake_pkg/yomi_audit/../yomi_data` == `tmp_path/fake_pkg/yomi_data`,
    never touching the real repository's yomi_data/.
    """
    fake_module_dir = tmp_path / "fake_pkg" / "yomi_audit"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(stamp_module, "__file__", str(fake_module_dir / "stamp.py"))

    # Avoid interactive getpass() / network KMS calls during tests.
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", raising=False)
    monkeypatch.setenv("YOMI_AUDIT_HMAC_MODE", "generated")

    # Reset singleton so _initialize() runs again against the patched path.
    stamp_module.ImmutableStamp._instance = None
    instance = stamp_module.ImmutableStamp()
    yield instance

    # Clean up singleton state so it doesn't leak into the next test.
    stamp_module.ImmutableStamp._instance = None


@pytest.fixture
def yomi_data_env(tmp_path, monkeypatch):
    """
    Redirects yomi_data/__init__.py's module-level path constants
    (DATA_DIR, CVE_STORE_DIR, MANIFEST_FILE, LEDGER_FILE, MIGRATED_FILE) to
    an isolated temp directory, and returns the yomi_data module for the
    test to call functions on.
    """
    import yomi_data as yomi_data_module

    fake_data_dir = tmp_path / "fake_yomi_data"
    fake_cve_store = fake_data_dir / "cve_store"
    fake_data_dir.mkdir()
    fake_cve_store.mkdir()

    monkeypatch.setattr(yomi_data_module, "DATA_DIR", fake_data_dir)
    monkeypatch.setattr(yomi_data_module, "CVE_STORE_DIR", fake_cve_store)
    monkeypatch.setattr(yomi_data_module, "MANIFEST_FILE", fake_cve_store / "manifest.json")
    monkeypatch.setattr(yomi_data_module, "LEDGER_FILE", fake_data_dir / "yomi_chain_of_custody.jsonl")
    monkeypatch.setattr(yomi_data_module, "MIGRATED_FILE", fake_data_dir / "cve_database.json.migrated")

    return yomi_data_module
