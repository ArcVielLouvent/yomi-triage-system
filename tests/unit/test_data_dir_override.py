"""
Tests for the YOMI_DATA_DIR override (known issue #27).

Every module that persists data resolves its directory through
``yomi_data.resolve_data_dir``. These tests check the resolver itself and
that each module actually uses it, so a ``pip install``-ed daemon can keep
its evidence store somewhere predictable (e.g. /var/lib/yomi-triage) instead
of inside the venv's site-packages.

Nothing here touches the real repository's yomi_data/: every directory is
under pytest's tmp_path.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from yomi_audit import stamp as stamp_module  # noqa: E402


@pytest.fixture
def override_dir(tmp_path, monkeypatch):
    """Sets YOMI_DATA_DIR to a temp dir and makes stamp's HMAC key
    non-interactive; resets the ImmutableStamp singleton around the test."""
    target = tmp_path / "var_lib_yomi"
    monkeypatch.setenv("YOMI_DATA_DIR", str(target))
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", raising=False)
    monkeypatch.delenv("YOMI_AUDIT_HMAC_MODE", raising=False)
    stamp_module.ImmutableStamp._instance = None
    yield target
    stamp_module.ImmutableStamp._instance = None


# --------------------------------------------------------------------------
# resolve_data_dir
# --------------------------------------------------------------------------

def test_default_is_used_when_env_unset(monkeypatch, tmp_path):
    from yomi_data import resolve_data_dir

    monkeypatch.delenv("YOMI_DATA_DIR", raising=False)
    default = tmp_path / "pkg" / ".." / "yomi_data"
    assert resolve_data_dir(default) == os.path.abspath(default)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_env_falls_back_to_default(monkeypatch, tmp_path, blank):
    from yomi_data import resolve_data_dir

    monkeypatch.setenv("YOMI_DATA_DIR", blank)
    assert resolve_data_dir(tmp_path) == os.path.abspath(tmp_path)


def test_absolute_override_wins_and_is_normalized(monkeypatch, tmp_path):
    from yomi_data import resolve_data_dir

    monkeypatch.setenv("YOMI_DATA_DIR", str(tmp_path / "a" / ".." / "evidence"))
    assert resolve_data_dir("/ignored/default") == str(tmp_path / "evidence")


def test_tilde_is_expanded(monkeypatch, tmp_path):
    from yomi_data import resolve_data_dir

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("YOMI_DATA_DIR", "~/yomi-evidence")
    assert resolve_data_dir("/ignored") == str(tmp_path / "yomi-evidence")


def test_relative_override_is_rejected(monkeypatch):
    from yomi_data import resolve_data_dir

    monkeypatch.setenv("YOMI_DATA_DIR", "relative/evidence")
    with pytest.raises(ValueError, match="absolute"):
        resolve_data_dir("/ignored")


def test_module_level_data_dir_honors_env_at_import(tmp_path):
    """yomi_data.DATA_DIR is computed at import time, so check it in a
    fresh interpreter rather than reloading the module in-process."""
    target = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, "-c", "import yomi_data; print(yomi_data.DATA_DIR)"],
        cwd=ROOT,
        env={**os.environ, "YOMI_DATA_DIR": str(target)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == str(target)


# --------------------------------------------------------------------------
# every data-writing module actually uses it
# --------------------------------------------------------------------------

def test_immutable_stamp_uses_override(override_dir):
    stamp = stamp_module.ImmutableStamp()
    assert stamp.data_dir == str(override_dir)
    assert stamp.ledger_file.startswith(str(override_dir) + os.sep)
    assert stamp.hmac_key_file.startswith(str(override_dir) + os.sep)
    assert Path(stamp.ledger_file).exists()


def test_immutable_stamp_rejects_relative_override(monkeypatch):
    monkeypatch.setenv("YOMI_DATA_DIR", "not/absolute")
    monkeypatch.delenv("YOMI_AUDIT_HMAC_MODE", raising=False)
    stamp_module.ImmutableStamp._instance = None
    try:
        with pytest.raises(ValueError, match="absolute"):
            stamp_module.ImmutableStamp()
    finally:
        stamp_module.ImmutableStamp._instance = None


def test_mirage_uses_override(override_dir):
    from yomi_engine.mirage import MirageProtocol

    mirage = MirageProtocol()
    assert mirage.mirage_dir == str(override_dir / "lazarus_chamber" / "mirage_env")
    assert Path(mirage.mirage_dir).is_dir()


def test_sandbox_uses_override(override_dir):
    from yomi_engine.sandbox import SandboxEnvironment

    sandbox = SandboxEnvironment()
    assert sandbox.chamber_dir == str(override_dir / "lazarus_chamber")


def test_swarm_uses_override(override_dir):
    from yomi_engine.swarm import SwarmOrchestrator

    swarm = SwarmOrchestrator()
    assert swarm.lock_vault == str(override_dir / "locks")
    assert Path(swarm.lock_vault).is_dir()


def test_dossier_uses_override(override_dir):
    from yomi_engine.dossier import CourtReadyDossier

    dossier = CourtReadyDossier()
    assert os.path.abspath(dossier.report_dir) == str(override_dir / "reports")


def test_remediator_uses_override(override_dir):
    from yomi_engine.remediator import ReverserEngine

    engine = ReverserEngine()
    assert engine.remediation_dir == override_dir / "remediation"
    assert engine.remediation_dir.is_dir()


def test_library_uses_override_but_explicit_argument_still_wins(
    override_dir, tmp_path, monkeypatch
):
    from yomi_engine.library import OmniLibrary

    # Same isolation as tests/unit/test_library.py: no network I/O in
    # __init__, and stop the background scraping thread afterwards.
    monkeypatch.setattr(OmniLibrary, "_has_network", lambda self: False)

    from_env = OmniLibrary()
    explicit = OmniLibrary(data_dir=str(tmp_path / "explicit_dir"))
    try:
        assert from_env.data_dir == str(override_dir)
        assert explicit.data_dir == str(tmp_path / "explicit_dir")
    finally:
        from_env.shutdown()
        explicit.shutdown()


def test_everything_lands_under_one_root(override_dir):
    """The point of the override: one predictable directory for the whole
    evidence store, nothing stray left in the package directory."""
    from yomi_engine.mirage import MirageProtocol
    from yomi_engine.remediator import ReverserEngine
    from yomi_engine.swarm import SwarmOrchestrator

    stamp = stamp_module.ImmutableStamp()
    MirageProtocol()
    SwarmOrchestrator()
    ReverserEngine()

    created = {p.name for p in override_dir.iterdir()}
    assert {"lazarus_chamber", "locks", "remediation"} <= created
    assert Path(stamp.ledger_file).parent == override_dir
