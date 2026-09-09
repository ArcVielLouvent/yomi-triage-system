"""
Additional coverage for yomi_audit.stamp.ImmutableStamp, targeting the
paths flagged in docs/known_issues.md #12 as never having been exercised
by any test: KMS/Vault/AWS-Secrets-Manager HMAC key retrieval,
password-derived ephemeral key generation, corrupted-ledger backup +
cleanup, and SOC checkpoint anchoring/verification.

These tests mock every network call (requests.get, boto3) -- nothing here
makes a real call to Vault, AWS, or any other external service.

test_stamp.py (Lapisan 0) stays the canonical "is the ledger correct"
suite; this file is purely about closing the coverage gap for the
security-relevant paths that file didn't touch.
"""
from __future__ import annotations

import base64
import json
import os
import time
from unittest.mock import MagicMock

import pytest


# --------------------------------------------------------------------------
# _decode_hmac_key
# --------------------------------------------------------------------------

def test_decode_hmac_key_valid_base64(isolated_stamp):
    raw = os.urandom(32)
    encoded = base64.b64encode(raw).decode("ascii")
    assert isolated_stamp._decode_hmac_key(encoded) == raw


def test_decode_hmac_key_non_base64_falls_back_to_utf8_bytes(isolated_stamp):
    # A string that isn't valid base64 (contains characters outside the
    # standard alphabet, so base64.b64decode(..., validate=True) raises)
    # but is >= 32 bytes when UTF-8 encoded.
    # NOTE: a plain repeated-letter string like "x" * 40 is deceptive here
    # -- it IS valid base64 (decodes to 30 bytes), so it doesn't exercise
    # this fallback path at all; it silently returns None instead.
    plain = "###not-valid-base64###" * 2
    assert len(plain) >= 32
    result = isolated_stamp._decode_hmac_key(plain)
    assert result == plain.encode("utf-8")


def test_decode_hmac_key_too_short_returns_none(isolated_stamp):
    assert isolated_stamp._decode_hmac_key("short") is None


def test_is_valid_hmac_key_rejects_wrong_types_and_short_keys(isolated_stamp):
    assert isolated_stamp._is_valid_hmac_key(None) is False
    assert isolated_stamp._is_valid_hmac_key("not bytes") is False
    assert isolated_stamp._is_valid_hmac_key(b"short") is False
    assert isolated_stamp._is_valid_hmac_key(os.urandom(32)) is True


# --------------------------------------------------------------------------
# HMAC key source priority: env var
# --------------------------------------------------------------------------

def test_env_var_hmac_key_takes_priority(tmp_path, monkeypatch):
    from yomi_audit import stamp as stamp_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_audit"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(stamp_module, "__file__", str(fake_module_dir / "stamp.py"))

    raw_key = os.urandom(32)
    monkeypatch.setenv("YOMI_AUDIT_HMAC_KEY", base64.b64encode(raw_key).decode("ascii"))
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", raising=False)
    monkeypatch.delenv("YOMI_AUDIT_HMAC_MODE", raising=False)

    stamp_module.ImmutableStamp._instance = None
    try:
        instance = stamp_module.ImmutableStamp()
        assert instance.hmac_key == raw_key
        assert instance.hmac_key_source == "env"
    finally:
        stamp_module.ImmutableStamp._instance = None


# --------------------------------------------------------------------------
# _load_hmac_key_from_kms: provider dispatch
# --------------------------------------------------------------------------

def test_kms_no_provider_configured_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", raising=False)
    assert isolated_stamp._load_hmac_key_from_kms() is None


def test_kms_unsupported_provider_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", "not-a-real-provider")
    assert isolated_stamp._load_hmac_key_from_kms() is None


def test_kms_vault_provider_dispatches_to_vault_loader(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", "vault")
    sentinel = object()
    monkeypatch.setattr(isolated_stamp, "_load_hmac_key_from_vault", lambda: sentinel)
    assert isolated_stamp._load_hmac_key_from_kms() is sentinel


def test_kms_aws_provider_dispatches_to_aws_loader(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", "aws-secrets-manager")
    sentinel = object()
    monkeypatch.setattr(
        isolated_stamp, "_load_hmac_key_from_aws_secrets_manager", lambda: sentinel
    )
    assert isolated_stamp._load_hmac_key_from_kms() is sentinel


# --------------------------------------------------------------------------
# _load_hmac_key_from_vault
# --------------------------------------------------------------------------

def test_vault_incomplete_config_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.delenv("YOMI_AUDIT_HMAC_VAULT_ADDR", raising=False)
    monkeypatch.delenv("YOMI_AUDIT_HMAC_VAULT_SECRET_PATH", raising=False)
    monkeypatch.delenv("YOMI_AUDIT_HMAC_VAULT_TOKEN", raising=False)
    assert isolated_stamp._load_hmac_key_from_vault() is None


def test_vault_success_flat_data_shape(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_SECRET_PATH", "secret/yomi")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_TOKEN", "s.faketoken")

    raw_key = os.urandom(32)
    encoded = base64.b64encode(raw_key).decode("ascii")

    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": {"hmac_key": encoded}}

    calls = {}

    def fake_get(url, headers=None, timeout=None):
        calls["url"] = url
        calls["headers"] = headers
        return resp

    monkeypatch.setattr("requests.get", fake_get)
    result = isolated_stamp._load_hmac_key_from_vault()

    assert result == raw_key
    assert calls["headers"]["X-Vault-Token"] == "s.faketoken"
    assert "secret/yomi" in calls["url"]


def test_vault_success_nested_kv2_data_shape(isolated_stamp, monkeypatch):
    # KV v2 wraps the payload one level deeper: {"data": {"data": {...}}}
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_SECRET_PATH", "secret/data/yomi")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_TOKEN", "s.faketoken")

    raw_key = os.urandom(32)
    encoded = base64.b64encode(raw_key).decode("ascii")

    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": {"data": {"hmac_key": encoded}}}

    monkeypatch.setattr("requests.get", lambda *a, **k: resp)
    result = isolated_stamp._load_hmac_key_from_vault()
    assert result == raw_key


def test_vault_custom_field_name(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_SECRET_PATH", "secret/yomi")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_TOKEN", "s.faketoken")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_FIELD", "custom_field")

    raw_key = os.urandom(32)
    encoded = base64.b64encode(raw_key).decode("ascii")
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": {"custom_field": encoded}}
    monkeypatch.setattr("requests.get", lambda *a, **k: resp)

    assert isolated_stamp._load_hmac_key_from_vault() == raw_key


def test_vault_request_exception_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_SECRET_PATH", "secret/yomi")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_TOKEN", "s.faketoken")

    def fake_get(*a, **k):
        raise ConnectionError("vault unreachable")

    monkeypatch.setattr("requests.get", fake_get)
    assert isolated_stamp._load_hmac_key_from_vault() is None


def test_vault_field_missing_from_response_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_SECRET_PATH", "secret/yomi")
    monkeypatch.setenv("YOMI_AUDIT_HMAC_VAULT_TOKEN", "s.faketoken")

    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": {}}
    monkeypatch.setattr("requests.get", lambda *a, **k: resp)

    assert isolated_stamp._load_hmac_key_from_vault() is None


# --------------------------------------------------------------------------
# _load_hmac_key_from_aws_secrets_manager
# --------------------------------------------------------------------------

def test_aws_missing_secret_id_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_SECRET_ID", raising=False)
    assert isolated_stamp._load_hmac_key_from_aws_secrets_manager() is None


def test_aws_boto3_not_installed_returns_none(isolated_stamp, monkeypatch):
    import builtins

    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_SECRET_ID", "yomi/hmac")

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("no boto3 installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert isolated_stamp._load_hmac_key_from_aws_secrets_manager() is None


def test_aws_secret_string_success(isolated_stamp, monkeypatch):
    import sys
    import types

    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_SECRET_ID", "yomi/hmac")

    raw_key = os.urandom(32)
    encoded = base64.b64encode(raw_key).decode("ascii")

    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretString": encoded}

    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    result = isolated_stamp._load_hmac_key_from_aws_secrets_manager()
    assert result == raw_key
    fake_boto3.client.assert_called_once_with("secretsmanager")
    fake_client.get_secret_value.assert_called_once_with(SecretId="yomi/hmac")


def test_aws_secret_binary_success(isolated_stamp, monkeypatch):
    import sys
    import types

    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_SECRET_ID", "yomi/hmac")

    raw_key = os.urandom(32)
    binary_secret = base64.b64encode(raw_key)

    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretBinary": binary_secret}

    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    result = isolated_stamp._load_hmac_key_from_aws_secrets_manager()
    assert result == raw_key


def test_aws_client_exception_returns_none(isolated_stamp, monkeypatch):
    import sys
    import types

    monkeypatch.setenv("YOMI_AUDIT_HMAC_KMS_SECRET_ID", "yomi/hmac")

    fake_client = MagicMock()
    fake_client.get_secret_value.side_effect = RuntimeError("AWS is down")

    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    assert isolated_stamp._load_hmac_key_from_aws_secrets_manager() is None


# --------------------------------------------------------------------------
# Ephemeral HMAC key derivation
# --------------------------------------------------------------------------

def test_ephemeral_mode_uses_master_password_env_var(tmp_path, monkeypatch):
    from yomi_audit import stamp as stamp_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_audit"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(stamp_module, "__file__", str(fake_module_dir / "stamp.py"))

    monkeypatch.delenv("YOMI_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", raising=False)
    monkeypatch.setenv("YOMI_AUDIT_HMAC_MODE", "ephemeral")
    monkeypatch.setenv("YOMI_AUDIT_MASTER_PASSWORD", "correct horse battery staple")

    stamp_module.ImmutableStamp._instance = None
    try:
        instance = stamp_module.ImmutableStamp()
        assert instance.hmac_key_source == "ephemeral"
        assert instance._is_valid_hmac_key(instance.hmac_key)
        # The key must never be written to disk anywhere in data_dir.
        assert not os.path.exists(os.path.join(instance.data_dir, "audit_hmac.key"))
    finally:
        stamp_module.ImmutableStamp._instance = None


def test_ephemeral_mode_deterministic_for_same_password_and_salt(isolated_stamp):
    salt = isolated_stamp._load_or_create_ephemeral_salt()
    key1 = isolated_stamp._derive_hmac_key_from_password("hunter2", salt)
    key2 = isolated_stamp._derive_hmac_key_from_password("hunter2", salt)
    key3 = isolated_stamp._derive_hmac_key_from_password("different", salt)
    assert key1 == key2
    assert key1 != key3
    assert len(key1) == isolated_stamp.HMAC_KEY_LENGTH_BYTES


def test_ephemeral_salt_persisted_and_reloaded(isolated_stamp):
    salt_file = os.path.join(isolated_stamp.data_dir, "audit_hmac.salt")
    assert not os.path.exists(salt_file)

    first_salt = isolated_stamp._load_or_create_ephemeral_salt()
    assert os.path.exists(salt_file)

    second_salt = isolated_stamp._load_or_create_ephemeral_salt()
    assert second_salt == first_salt


def test_ephemeral_mode_non_interactive_no_password_returns_none(isolated_stamp, monkeypatch):
    monkeypatch.delenv("YOMI_AUDIT_MASTER_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin", None)
    assert isolated_stamp._derive_ephemeral_hmac_key() is None


def test_ephemeral_mode_empty_password_rejected(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_AUDIT_MASTER_PASSWORD", "")
    monkeypatch.setattr("sys.stdin", None)
    assert isolated_stamp._derive_ephemeral_hmac_key() is None


# --------------------------------------------------------------------------
# _backup_corrupted_ledger / cleanup_corrupt_backups
# --------------------------------------------------------------------------

def test_backup_corrupted_ledger_creates_backup_and_metadata(isolated_stamp):
    isolated_stamp._backup_corrupted_ledger(reason="test-induced corruption")

    backups = [
        f for f in os.listdir(isolated_stamp.data_dir)
        if f.startswith(os.path.basename(isolated_stamp.ledger_file) + isolated_stamp.CORRUPT_SUFFIX)
        and f.endswith(".jsonl")
    ]
    assert len(backups) == 1

    metadata_files = [f for f in os.listdir(isolated_stamp.data_dir) if f.endswith(".metadata.json")]
    assert len(metadata_files) == 1
    with open(os.path.join(isolated_stamp.data_dir, metadata_files[0]), encoding="utf-8") as f:
        meta = json.loads(f.read().strip())
    assert meta["_corrupt_reason"] == "test-induced corruption"


def test_backup_corrupted_ledger_noop_if_ledger_missing(isolated_stamp):
    os.remove(isolated_stamp.ledger_file)
    # Must not raise even though there's nothing to back up.
    isolated_stamp._backup_corrupted_ledger(reason="doesn't matter")
    backups = [
        f for f in os.listdir(isolated_stamp.data_dir)
        if isolated_stamp.CORRUPT_SUFFIX in f
    ]
    assert backups == []


def test_backup_corrupted_ledger_handles_copy_failure_gracefully(isolated_stamp, monkeypatch):
    def fake_copy2(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("shutil.copy2", fake_copy2)
    # Must not raise -- failure is caught and logged.
    isolated_stamp._backup_corrupted_ledger(reason="whatever")


def _all_backup_related_files(instance):
    prefix = os.path.basename(instance.ledger_file) + instance.CORRUPT_SUFFIX
    return [f for f in os.listdir(instance.data_dir) if f.startswith(prefix)]


def _jsonl_backup_files(instance):
    return [f for f in _all_backup_related_files(instance) if f.endswith(".jsonl")]


def test_cleanup_corrupt_backups_retains_requested_count(isolated_stamp):
    for _ in range(3):
        isolated_stamp._backup_corrupted_ledger(reason="round")
        time.sleep(1.05)  # backup filenames resolve per-second, not per-ms

    assert len(_jsonl_backup_files(isolated_stamp)) == 3
    # Each backup round writes 2 files (the .jsonl copy + its
    # .metadata.json sidecar) -- see
    # test_cleanup_corrupt_backups_retain_last_counts_files_not_incidents
    # below for why "retain_last" doesn't mean "retain N incidents".
    assert len(_all_backup_related_files(isolated_stamp)) == 6

    deleted = isolated_stamp.cleanup_corrupt_backups(retain_last=1)
    assert deleted == 5
    assert len(_all_backup_related_files(isolated_stamp)) == 1


def test_cleanup_corrupt_backups_retain_zero_deletes_all(isolated_stamp):
    isolated_stamp._backup_corrupted_ledger(reason="only one")
    assert len(_all_backup_related_files(isolated_stamp)) == 2  # .jsonl + .metadata.json
    deleted = isolated_stamp.cleanup_corrupt_backups(retain_last=0)
    assert deleted == 2
    assert _all_backup_related_files(isolated_stamp) == []


def test_cleanup_corrupt_backups_retain_last_counts_files_not_incidents(isolated_stamp):
    """
    Documents a real design nuance (not a crash, not data loss of the
    ledger itself, but worth knowing): cleanup_corrupt_backups's
    retain_last operates on the flat, mtime-sorted list of every file
    whose name starts with the backup prefix -- and each "incident"
    produces TWO such files (the .jsonl copy and its .metadata.json
    sidecar), listed and counted as independent entries. So
    retain_last=1 does not mean "keep the most recent full incident"; it
    means "keep the single most-recently-modified file", which is
    whichever of the pair was written last (the metadata.json, since
    _backup_corrupted_ledger writes it after the .jsonl copy). The
    result can be a metadata.json with no matching .jsonl backup left
    beside it.
    """
    isolated_stamp._backup_corrupted_ledger(reason="only incident")
    isolated_stamp.cleanup_corrupt_backups(retain_last=1)

    remaining = _all_backup_related_files(isolated_stamp)
    assert len(remaining) == 1
    assert remaining[0].endswith(".metadata.json")


def test_cleanup_corrupt_backups_handles_missing_file_gracefully(isolated_stamp, monkeypatch):
    isolated_stamp._backup_corrupted_ledger(reason="will vanish")

    def fake_remove(path):
        raise OSError("already gone")

    monkeypatch.setattr("os.remove", fake_remove)
    # Must not raise; failed deletions are simply not counted.
    deleted = isolated_stamp.cleanup_corrupt_backups(retain_last=0)
    assert deleted == 0


def test_cleanup_corrupt_backups_triggered_by_env_flag(tmp_path, monkeypatch):
    from yomi_audit import stamp as stamp_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_audit"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(stamp_module, "__file__", str(fake_module_dir / "stamp.py"))
    monkeypatch.setenv("YOMI_AUDIT_HMAC_MODE", "generated")
    monkeypatch.delenv("YOMI_AUDIT_HMAC_KMS_PROVIDER", raising=False)

    stamp_module.ImmutableStamp._instance = None
    try:
        instance = stamp_module.ImmutableStamp()
        instance._backup_corrupted_ledger(reason="pre-existing junk")
        instance._backup_corrupted_ledger(reason="pre-existing junk 2")
    finally:
        stamp_module.ImmutableStamp._instance = None

    monkeypatch.setenv("YOMI_AUDIT_PURGE_CORRUPT", "true")
    stamp_module.ImmutableStamp._instance = None
    try:
        instance2 = stamp_module.ImmutableStamp()
        backups = [
            f for f in os.listdir(instance2.data_dir)
            if f.startswith(os.path.basename(instance2.ledger_file) + instance2.CORRUPT_SUFFIX)
            and f.endswith(".jsonl")
        ]
        # retain_last=1 is applied automatically on init when the flag is set.
        assert len(backups) <= 1
    finally:
        stamp_module.ImmutableStamp._instance = None


# --------------------------------------------------------------------------
# _create_or_verify_checkpoint
# --------------------------------------------------------------------------

def test_checkpoint_created_on_first_boot(isolated_stamp):
    assert os.path.exists(isolated_stamp.checkpoint_file)
    with open(isolated_stamp.checkpoint_file, "rb") as f:
        stored = f.read().decode("utf-8")
    import hashlib
    assert stored == hashlib.sha256(isolated_stamp.last_hash.encode("utf-8")).hexdigest()


def test_checkpoint_routine_update_on_ledger_advance(isolated_stamp, capsys):
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "advance the ledger")
    capsys.readouterr()  # discard prior output

    isolated_stamp._create_or_verify_checkpoint()
    captured = capsys.readouterr()

    # [FIXED] known_issues.md #13: wording no longer reads like a tamper
    # alert for this expected, routine case.
    assert "routine update" in captured.out.lower()
    assert "mismatch detected" not in captured.out.lower()


def test_checkpoint_creation_failure_handled_gracefully(isolated_stamp, monkeypatch):
    def fake_open(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("builtins.open", fake_open)
    # Must not raise.
    isolated_stamp._create_or_verify_checkpoint()


# --------------------------------------------------------------------------
# verify_soc_checkpoint
# --------------------------------------------------------------------------

def test_verify_soc_checkpoint_true_when_no_checkpoint_yet(isolated_stamp):
    # NOTE: the notary checkpoint file is actually created during the
    # very first genesis entry write (_anchor_soc_checkpoint runs on
    # every _append_entry call, including genesis), so by the time the
    # fixture yields, it already exists. To exercise the true "fresh
    # install / file deleted" branch, remove it first.
    if os.path.exists(isolated_stamp.notary_checkpoint_file):
        os.remove(isolated_stamp.notary_checkpoint_file)
    assert isolated_stamp.verify_soc_checkpoint() is True


def test_verify_soc_checkpoint_true_for_valid_attestation(isolated_stamp):
    if not isolated_stamp.hmac_key:
        pytest.skip("HMAC key not generated in this environment")
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "creates a notary checkpoint")
    assert os.path.exists(isolated_stamp.notary_checkpoint_file)
    assert isolated_stamp.verify_soc_checkpoint() is True


def test_verify_soc_checkpoint_false_when_signature_missing(isolated_stamp):
    if not isolated_stamp.hmac_key:
        pytest.skip("HMAC key not generated in this environment")
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "creates a notary checkpoint")

    with open(isolated_stamp.notary_checkpoint_file, encoding="utf-8") as f:
        manifest = json.load(f)
    del manifest["attestation_signature"]
    # _anchor_soc_checkpoint deliberately locks this file to 0o400
    # (read-only) as WORM-style protection. As a non-root user (e.g. in
    # Codespaces, unlike a root sandbox where permission checks are
    # bypassed) even the owner can't open("w") it without chmod'ing
    # first -- exactly what a real attacker tampering with the file
    # would have to do too, so this mirrors the realistic tamper path
    # rather than being a test-only workaround.
    os.chmod(isolated_stamp.notary_checkpoint_file, 0o600)
    with open(isolated_stamp.notary_checkpoint_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    assert isolated_stamp.verify_soc_checkpoint() is False


def test_verify_soc_checkpoint_false_when_tampered(isolated_stamp):
    if not isolated_stamp.hmac_key:
        pytest.skip("HMAC key not generated in this environment")
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "creates a notary checkpoint")

    with open(isolated_stamp.notary_checkpoint_file, encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["latest_hash"] = "f" * 64  # tamper with the attested value
    # See comment in test_verify_soc_checkpoint_false_when_signature_missing
    # above -- the file is locked 0o400 by design; chmod first, like a
    # real attacker would need to.
    os.chmod(isolated_stamp.notary_checkpoint_file, 0o600)
    with open(isolated_stamp.notary_checkpoint_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    assert isolated_stamp.verify_soc_checkpoint() is False


def test_verify_soc_checkpoint_false_on_read_error(isolated_stamp, monkeypatch):
    if not isolated_stamp.hmac_key:
        pytest.skip("HMAC key not generated in this environment")
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "creates a notary checkpoint")

    def fake_open(*a, **k):
        raise OSError("permission denied")

    monkeypatch.setattr("builtins.open", fake_open)
    assert isolated_stamp.verify_soc_checkpoint() is False


def test_anchor_soc_checkpoint_skipped_without_hmac_key(isolated_stamp, capsys):
    # Same reasoning as above: genesis already created a checkpoint file
    # with the real hmac_key, so it must be cleared first to observe the
    # "skipped, no file written" behavior in isolation.
    if os.path.exists(isolated_stamp.notary_checkpoint_file):
        os.remove(isolated_stamp.notary_checkpoint_file)
    isolated_stamp.hmac_key = None
    capsys.readouterr()
    isolated_stamp._anchor_soc_checkpoint({"hash": "abc"})
    captured = capsys.readouterr()
    assert "skipped" in captured.out.lower()
    assert not os.path.exists(isolated_stamp.notary_checkpoint_file)


# --------------------------------------------------------------------------
# _load_or_initialize_ledger: corruption recovery round trip
# --------------------------------------------------------------------------

def test_ledger_corruption_triggers_backup_and_reinit(isolated_stamp):
    isolated_stamp.record_action("AGENT_A", "ACTION_1", "one real entry")

    with open(isolated_stamp.ledger_file, "a", encoding="utf-8") as f:
        f.write("{not valid json\n")

    # Re-run initialization against the now-corrupted ledger.
    recovered_hash = isolated_stamp._load_or_initialize_ledger()
    assert recovered_hash == isolated_stamp.last_hash

    backups = [
        f for f in os.listdir(isolated_stamp.data_dir)
        if isolated_stamp.CORRUPT_SUFFIX in f and f.endswith(".jsonl")
    ]
    assert len(backups) == 1

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "LEDGER_RECOVERY" for l in lines)


# --------------------------------------------------------------------------
# _atomic_write: binary mode
# --------------------------------------------------------------------------

def test_atomic_write_binary_mode(isolated_stamp, tmp_path):
    target = os.path.join(isolated_stamp.data_dir, "binary_test.bin")
    payload = os.urandom(16)
    isolated_stamp._atomic_write(target, payload, binary=True)
    with open(target, "rb") as f:
        assert f.read() == payload


# --------------------------------------------------------------------------
# _compute_legacy_hash fallback during verification
# --------------------------------------------------------------------------

def test_legacy_hash_format_still_verifies(tmp_path, monkeypatch):
    """
    Entries hashed with json.dumps(sort_keys=True) but WITHOUT the
    compact separators=(",", ":") (the "legacy" canonicalization) must
    still pass _verify_ledger() via the legacy-hash fallback comparison.

    HMAC enforcement is disabled for this instance from the start (the
    genesis entry itself must be written without an entry_hmac, or line 1
    fails its own "HMAC present but key unavailable" check before we ever
    get to the legacy-hash line under test) so the test isolates the
    legacy-hash fallback specifically, rather than also exercising the
    separate "missing HMAC" rejection path.
    """
    from yomi_audit import stamp as stamp_module

    fake_module_dir = tmp_path / "fake_pkg" / "yomi_audit"
    fake_module_dir.mkdir(parents=True)
    monkeypatch.setattr(stamp_module, "__file__", str(fake_module_dir / "stamp.py"))
    monkeypatch.setattr(
        stamp_module.ImmutableStamp, "_load_or_generate_hmac_key", lambda self: None
    )

    stamp_module.ImmutableStamp._instance = None
    isolated_stamp = stamp_module.ImmutableStamp()
    assert isolated_stamp.hmac_key is None

    entry_copy = {
        "record_id": "legacy-entry",
        "ledger_version": isolated_stamp.LEDGER_VERSION,
        "created_at": "2026-01-01T00:00:00+00:00",
        "timestamp_utc": "2026-01-01T00:00:00+00:00",
        "unix_time": 1767225600.0,
        "agent": "LEGACY_AGENT",
        "action_type": "LEGACY_ACTION",
        "description": "written with legacy (non-compact) json.dumps",
        "raw_command": "",
        "tool_arguments": {},
        "metadata": {},
        "previous_hash": isolated_stamp.last_hash,
    }
    legacy_hash = isolated_stamp._compute_legacy_hash(entry_copy)
    entry = dict(entry_copy)
    entry["hash"] = legacy_hash

    with open(isolated_stamp.ledger_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    assert isolated_stamp.verify_ledger() is True
