"""
Unit tests for yomi_engine.dossier.CourtReadyDossier.

__init__ hardcodes report_dir relative to __file__ (same pattern as
remediator.py) and instantiates both TemporalNarrativeWeaver() and
ImmutableStamp() directly -- isolated the same way (monkeypatch __file__
before construction, reuse isolated_stamp's singleton for the audit ledger).
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def dossier(isolated_stamp, tmp_path, monkeypatch):
    from yomi_engine import dossier as dossier_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_engine"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(dossier_module, "__file__", str(fake_module_dir / "dossier.py"))
    monkeypatch.setattr("shutil.which", lambda name: None)

    return dossier_module.CourtReadyDossier()


def test_init_creates_report_dir(dossier, tmp_path):
    expected = tmp_path / "fake_pkg" / "yomi_data" / "reports"
    assert os.path.normpath(dossier.report_dir) == str(expected)
    assert expected.is_dir()


def test_generate_dossier_creates_pdf_and_txt(dossier, isolated_stamp):
    isolated_stamp.record_action("SWARM", "SCAN_COMPLETE", "Test evidence entry.")
    dossier.generate_pdf_dossier()

    pdf_files = list(Path(dossier.report_dir).glob("*.pdf"))
    txt_files = list(Path(dossier.report_dir).glob("*.txt"))
    assert len(pdf_files) == 1
    assert len(txt_files) == 1
    assert pdf_files[0].stat().st_size > 0


def test_txt_annex_contains_raw_narrative_verbatim(dossier, isolated_stamp):
    isolated_stamp.record_action("HUNTER", "ROOT_CAUSE_FOUND", "Unique marker XYZABC123.")
    dossier.generate_pdf_dossier()

    txt_file = next(Path(dossier.report_dir).glob("*.txt"))
    assert "XYZABC123" in txt_file.read_text(encoding="utf-8")


def test_generate_dossier_signs_both_artifacts(dossier):
    dossier.generate_pdf_dossier()

    sig_files = list(Path(dossier.report_dir).glob("*.sig"))
    assert len(sig_files) == 2  # one for .pdf, one for .txt


def test_generate_dossier_seals_action_to_ledger(dossier, isolated_stamp):
    dossier.generate_pdf_dossier()

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "REPORT_SIGNED"
    assert lines[-1]["metadata"]["pdf_file"].endswith(".pdf")


def test_multiple_dossiers_get_unique_filenames(dossier):
    import time

    dossier.generate_pdf_dossier()
    time.sleep(1.1)  # timestamp-based filenames need >=1s apart
    dossier.generate_pdf_dossier()

    pdf_files = list(Path(dossier.report_dir).glob("*.pdf"))
    assert len(pdf_files) == 2


# --------------------------------------------------------------------------
# _sign_artifact: GPG -> HMAC -> SHA256 fallback chain (same pattern as
# remediator.py's signing chain, tested the same way)
# --------------------------------------------------------------------------

def test_sign_artifact_falls_back_to_hmac_or_sha256_without_gpg(dossier, isolated_stamp, tmp_path):
    target = tmp_path / "test_artifact.txt"
    target.write_text("evidence content", encoding="utf-8")

    result = dossier._sign_artifact(str(target))
    assert result["status"] == "SUCCESS"
    if isolated_stamp.hmac_key:
        assert result["mode"] == "HMAC-SHA256"
    else:
        assert result["mode"] == "SHA256 (UNSEALED)"

    sig_path = Path(result["sig_file"])
    assert sig_path.exists()
    payload = json.loads(sig_path.read_text())
    assert payload["target_file"] == "test_artifact.txt"


def test_sign_artifact_signature_file_has_restrictive_permissions(dossier, tmp_path):
    target = tmp_path / "test_artifact.txt"
    target.write_text("x", encoding="utf-8")

    result = dossier._sign_artifact(str(target))
    mode = stat.S_IMODE(Path(result["sig_file"]).stat().st_mode)
    assert mode == 0o640


def test_sign_artifact_uses_gpg_when_available(dossier, monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    dossier.gpg_binary = "/usr/bin/gpg"
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("subprocess.run", fake_run)

    target = tmp_path / "artifact.txt"
    target.write_text("x", encoding="utf-8")
    result = dossier._sign_artifact(str(target))

    assert result["status"] == "SUCCESS"
    assert result["mode"] == "GPG"
    fake_run.assert_called_once()


def test_sign_artifact_falls_back_when_gpg_run_raises(dossier, monkeypatch, tmp_path):
    dossier.gpg_binary = "/usr/bin/gpg"

    def raise_error(*a, **k):
        raise OSError("simulated gpg execution failure")

    monkeypatch.setattr("subprocess.run", raise_error)
    target = tmp_path / "artifact.txt"
    target.write_text("x", encoding="utf-8")
    result = dossier._sign_artifact(str(target))  # must not raise

    assert result["status"] == "SUCCESS"
    assert result["mode"] != "GPG"


def test_sign_artifact_nonexistent_file_returns_error_not_crash(dossier):
    result = dossier._sign_artifact("/nonexistent/artifact.txt")
    assert result["status"] == "ERROR"


# --------------------------------------------------------------------------
# PDF-specific: non-Latin-1 characters must not crash FPDF generation
# --------------------------------------------------------------------------

def test_generate_dossier_handles_non_latin1_characters_without_crashing(dossier, isolated_stamp):
    # Unicode content (e.g. from an internationalized threat description)
    # must not crash FPDF's Latin-1-only rendering -- the module transliterates
    # rather than raising.
    isolated_stamp.record_action("SWARM", "SCAN", "Threat name: 恶意软件 malware detected \u2603")
    dossier.generate_pdf_dossier()  # must not raise

    pdf_files = list(Path(dossier.report_dir).glob("*.pdf"))
    assert len(pdf_files) == 1
    assert pdf_files[0].stat().st_size > 0

    # The TXT annex, unlike the PDF, must preserve the TRUE unicode content
    # verbatim (module docstring: "Prevents Evidence Spoliation").
    txt_file = next(Path(dossier.report_dir).glob("*.txt"))
    assert "恶意软件" in txt_file.read_text(encoding="utf-8")
