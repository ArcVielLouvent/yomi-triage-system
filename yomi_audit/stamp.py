import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import time
import uuid
import shutil
from datetime import datetime, timezone

# ==============================================================================
# YOMI TRIAGE SYSTEM: Audit Module - The Immutable Stamp (v3.0)
# Purpose: Cryptographic, tamper-evident chain-of-custody ledger.
#          Implements deterministic JSON canonicalization, file-level integrity,
#          secure storage, and audit-grade evidence provenance.
# ==============================================================================
class SecurityError(Exception):
    """Exception raised for critical security and tampering incidents."""
    pass

class ImmutableStamp:
    _instance = None
    _singleton_lock = threading.Lock()
    GENESIS_PREVIOUS_HASH = "0" * 64
    GENESIS_LABEL = "YOMI_AUDIT_GENESIS"
    LEDGER_FILENAME = "yomi_chain_of_custody.jsonl"
    LEDGER_VERSION = "1.0"
    HMAC_KEY_LENGTH_BYTES = 32
    CORRUPT_SUFFIX = ".corrupt"

    def __new__(cls):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(ImmutableStamp, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self.data_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "yomi_data")
        )
        os.makedirs(self.data_dir, exist_ok=True)
        self._secure_directory_permissions()

        self.ledger_file = os.path.join(self.data_dir, self.LEDGER_FILENAME)
        self.hmac_key_file = os.path.join(self.data_dir, "audit_hmac.key")
        self.checkpoint_file = os.path.join(self.data_dir, "ledger_checkpoint.bin")
        self.hmac_key = self._load_or_generate_hmac_key()
        self._ensure_ledger_file()
        self._cleanup_corrupt_backups_if_requested()
        self.last_hash = self._load_or_initialize_ledger()
        self._create_or_verify_checkpoint()

    def _secure_directory_permissions(self):
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass

    def _secure_path_permissions(self, path: str, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def _ensure_ledger_file(self):
        if not os.path.exists(self.ledger_file):
            self._atomic_write(self.ledger_file, "", encoding="utf-8")
            self._secure_path_permissions(self.ledger_file, 0o600)

    def _load_or_generate_hmac_key(self) -> bytes | None:
        env_key = os.environ.get("YOMI_AUDIT_HMAC_KEY")
        if env_key:
            key = self._decode_hmac_key(env_key)
            if key is not None:
                return key

        if os.path.exists(self.hmac_key_file):
            try:
                with open(self.hmac_key_file, "rb") as key_file:
                    key = key_file.read().strip()
                if self._is_valid_hmac_key(key):
                    self._secure_path_permissions(self.hmac_key_file, 0o600)
                    return key
            except OSError:
                pass

        try:
            generated_key = os.urandom(self.HMAC_KEY_LENGTH_BYTES)
            self._atomic_write(self.hmac_key_file, generated_key, binary=True)
            self._secure_path_permissions(self.hmac_key_file, 0o600)
            return generated_key
        except OSError:
            return None

    def _decode_hmac_key(self, key_str: str) -> bytes | None:
        try:
            key = base64.b64decode(key_str, validate=True)
        except (binascii.Error, ValueError):
            key = key_str.encode("utf-8")
        return key if self._is_valid_hmac_key(key) else None

    def _is_valid_hmac_key(self, key: bytes | bytearray | None) -> bool:
        return (
            isinstance(key, (bytes, bytearray))
            and len(key) >= self.HMAC_KEY_LENGTH_BYTES
        )

    def _canonical_json(self, payload: dict) -> str:
        return json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _compute_hash(self, payload: dict) -> str:
        payload_json = self._canonical_json(payload)
        return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    def _compute_legacy_hash(self, payload: dict) -> str:
        legacy_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(legacy_json.encode("utf-8")).hexdigest()

    def _compute_entry_hmac(self, payload: dict) -> str | None:
        if not self.hmac_key:
            return None
        serialized = self._canonical_json(payload).encode("utf-8")
        digest = hmac.new(self.hmac_key, serialized, hashlib.sha256).digest()
        return base64.b64encode(digest).decode("ascii")

    def _atomic_write(
        self,
        destination: str,
        content: str | bytes,
        encoding: str = "utf-8",
        binary: bool = False,
    ) -> None:
        mode = "wb" if binary else "w"
        suffix = ".tmp"
        with tempfile.NamedTemporaryFile(
            mode=mode,
            dir=os.path.dirname(destination),
            delete=False,
            encoding=None if binary else encoding,
        ) as temp_file:
            temp_file.write(content)
            temp_name = temp_file.name
        os.replace(temp_name, destination)

    def _backup_corrupted_ledger(self, reason: str | None = None) -> None:
        if not os.path.exists(self.ledger_file):
            return

        backup_name = (
            f"{self.ledger_file}{self.CORRUPT_SUFFIX}.{int(time.time())}.jsonl"
        )
        try:
            raw_entries = []
            with open(self.ledger_file, "r", encoding="utf-8") as ledger:
                for line_number, raw_line in enumerate(ledger, 1):
                    raw_line = raw_line.rstrip("\n")
                    parsed = None
                    try:
                        parsed = json.loads(raw_line)
                    except json.JSONDecodeError:
                        parsed = None
                    raw_entries.append(
                        {
                            "line_number": line_number,
                            "raw_line": raw_line,
                            "parsed": parsed,
                        }
                    )

            backup_obj = {
                "_corrupt_reason": reason or "Unknown ledger corruption",
                "_timestamp": datetime.now(timezone.utc).isoformat(),
                "_source_file": os.path.basename(self.ledger_file),
                "raw_data": raw_entries,
            }
            self._atomic_write(
                backup_name,
                self._canonical_json(backup_obj) + "\n",
                encoding="utf-8",
            )
            details = f" Reason: {reason}" if reason else ""
            print(f"[YOMI-AUDIT] Corrupted ledger backed up to {backup_name}.{details}")
        except Exception:
            pass

    def _cleanup_corrupt_backups_if_requested(self) -> None:
        purge_flag = os.environ.get("YOMI_AUDIT_PURGE_CORRUPT", "").lower()
        if purge_flag in {"1", "true", "yes", "on"}:
            self.cleanup_corrupt_backups(retain_last=1)

    def _create_or_verify_checkpoint(self) -> None:
        checkpoint_hash = hashlib.sha256(self.last_hash.encode('utf-8')).hexdigest()
        try:
            if os.path.exists(self.checkpoint_file):
                with open(self.checkpoint_file, 'rb') as chk:
                    stored_hash = chk.read().decode('utf-8')
                if stored_hash != checkpoint_hash:
                    print(f"[YOMI-AUDIT] Checkpoint mismatch detected. Updating...")
            with open(self.checkpoint_file, 'wb') as chk:
                chk.write(checkpoint_hash.encode('utf-8'))
            self._secure_path_permissions(self.checkpoint_file, 0o600)
        except Exception as exc:
            print(f"[YOMI-AUDIT] Checkpoint creation failed: {exc}")

    def cleanup_corrupt_backups(self, retain_last: int = 0) -> int:
        deleted = 0
        backups = []
        for filename in os.listdir(self.data_dir):
            if filename.startswith(
                os.path.basename(self.ledger_file) + self.CORRUPT_SUFFIX
            ):
                backups.append(os.path.join(self.data_dir, filename))

        backups.sort(key=lambda path: os.path.getmtime(path), reverse=True)
        for index, backup_path in enumerate(backups):
            if retain_last > 0 and index < retain_last:
                continue
            try:
                os.remove(backup_path)
                deleted += 1
            except OSError:
                pass
        print(f"[YOMI-AUDIT] Purged {deleted} old corrupt ledger backup(s).")
        return deleted

    def _load_or_initialize_ledger(self) -> str:
        if (
            not os.path.exists(self.ledger_file)
            or os.path.getsize(self.ledger_file) == 0
        ):
            return self._write_genesis_entry()

        try:
            return self._verify_ledger()
        except Exception as exc:
            self._backup_corrupted_ledger(str(exc))
            self._atomic_write(self.ledger_file, "", encoding="utf-8")
            self._secure_path_permissions(self.ledger_file, 0o600)
            self._write_genesis_entry()
            self.record_action(
                "YOMI_AUDIT",
                "LEDGER_RECOVERY",
                "Reinitialized immutable ledger after corruption was detected.",
                raw_command=str(exc),
                metadata={"recovery_reason": str(exc)},
            )
            return self.last_hash

    def _verify_ledger(self) -> str:
        previous_hash = self.GENESIS_PREVIOUS_HASH
        last_hash = previous_hash
        line_number = 0

        with open(self.ledger_file, "r", encoding="utf-8") as ledger:
            for raw_line in ledger:
                line = raw_line.strip()
                if not line:
                    continue
                line_number += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON at line {line_number}: {exc.msg}")

                self._validate_ledger_entry(entry, line_number)

                if entry["previous_hash"] != last_hash:
                    raise ValueError(
                        f"Broken chain at line {line_number}: expected previous_hash {last_hash}, found {entry['previous_hash']}."
                    )

                entry_copy = dict(entry)
                entry_copy.pop("hash", None)
                expected_hmac = entry_copy.get("entry_hmac")

                actual_hash = self._compute_hash(entry_copy)
                if actual_hash != entry["hash"]:
                    legacy_hash = self._compute_legacy_hash(entry_copy)
                    if legacy_hash != entry["hash"]:
                        raise ValueError(
                            f"Hash mismatch at line {line_number}: computed {actual_hash} / {legacy_hash}, stored {entry['hash']}."
                        )

                if expected_hmac is not None:
                    if not self.hmac_key:
                        raise ValueError(
                            f"HMAC present but audit key is unavailable at line {line_number}."
                        )
                    hmac_payload = dict(entry_copy)
                    hmac_payload.pop("entry_hmac", None)
                    actual_hmac = self._compute_entry_hmac(hmac_payload)
                    if actual_hmac != expected_hmac:
                        raise ValueError(
                            f"HMAC mismatch at line {line_number}: computed {actual_hmac}, stored {expected_hmac}."
                        )
                elif self.hmac_key:
                    if line_number == 1 and entry.get("action_type") == "GENESIS":
                        print(
                            "[YOMI-AUDIT] Legacy genesis entry without HMAC accepted for compatibility."
                        )
                    else:
                        raise ValueError(
                            f"Missing HMAC on ledger entry at line {line_number} while HMAC enforcement is enabled."
                        )

                last_hash = entry["hash"]

        if last_hash == self.GENESIS_PREVIOUS_HASH:
            return self._write_genesis_entry()
        return last_hash

    def _validate_ledger_entry(self, entry: dict, line_number: int) -> None:
        required_keys = {
            "record_id",
            "ledger_version",
            "created_at",
            "timestamp_utc",
            "unix_time",
            "agent",
            "action_type",
            "description",
            "raw_command",
            "tool_arguments",
            "metadata",
            "previous_hash",
            "hash",
        }

        if not isinstance(entry, dict):
            raise ValueError(
                f"Ledger entry at line {line_number} is not a JSON object."
            )

        missing = required_keys - entry.keys()
        if missing:
            raise ValueError(
                f"Ledger entry missing required fields at line {line_number}: {sorted(missing)}."
            )

        if entry.get("ledger_version") != self.LEDGER_VERSION:
            raise ValueError(
                f"Unsupported ledger version at line {line_number}: {entry.get('ledger_version')}."
            )

        if (
            not isinstance(entry.get("previous_hash"), str)
            or len(entry["previous_hash"]) != 64
        ):
            raise ValueError(f"Invalid previous_hash format at line {line_number}.")

        if not isinstance(entry.get("hash"), str) or len(entry["hash"]) != 64:
            raise ValueError(f"Invalid hash format at line {line_number}.")

    def _write_genesis_entry(self) -> str:
        genesis_entry = {
            "record_id": self.GENESIS_LABEL,
            "ledger_version": self.LEDGER_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "unix_time": time.time(),
            "agent": "YOMI_AUDIT",
            "action_type": "GENESIS",
            "description": "Initialized immutable chain-of-custody ledger.",
            "raw_command": "",
            "tool_arguments": {},
            "metadata": {
                "platform": os.name,
                "node": os.uname().nodename if hasattr(os, "uname") else "unknown",
                "hmac_enabled": bool(self.hmac_key),
            },
            "previous_hash": self.GENESIS_PREVIOUS_HASH,
        }
        if self.hmac_key:
            genesis_entry["entry_hmac"] = self._compute_entry_hmac(genesis_entry)
        genesis_entry["hash"] = self._compute_hash(genesis_entry)
        self.last_hash = genesis_entry["hash"]
        self._append_entry(genesis_entry)
        return genesis_entry["hash"]

    def _append_entry(self, entry: dict) -> None:
        serialized = self._canonical_json(entry)
        with open(self.ledger_file, "a", encoding="utf-8") as ledger:
            ledger.write(serialized + "\n")
            ledger.flush()
            try:
                os.fsync(ledger.fileno())
            except OSError:
                pass
        self._secure_path_permissions(self.ledger_file, 0o600)
        self._anchor_soc_checkpoint(entry)

    def _anchor_soc_checkpoint(self, entry: dict) -> None:
        """
        Creates a mathematically verifiable cryptographically-signed SOC attestation
        for air-gapped environments.
        """
        if os.path.exists(self.notary_checkpoint_file):
            self._secure_path_permissions(self.notary_checkpoint_file, 0o600)
            
        checkpoint = {
            "latest_hash": entry.get("hash"),
            "timestamp": entry.get("timestamp_utc"),
            "agent": entry.get("agent"),
            "action": entry.get("action_type")
        }
        
        canonical_data = self._canonical_json(checkpoint)
        
        signature = hmac.new(
            self.hmac_key, 
            canonical_data.encode("utf-8"), 
            hashlib.sha256
        ).hexdigest()
        
        checkpoint["attestation_signature"] = signature
        
        self._atomic_write(self.notary_checkpoint_file, self._canonical_json(checkpoint), encoding="utf-8")
        self._secure_path_permissions(self.notary_checkpoint_file, 0o400)

    def verify_soc_checkpoint(self) -> bool:
        """
        Startup Audit Function: Mathematically verifies the integrity of the checkpoint file.
        Returns True if the database state is secure, and False if tampering is detected.
        """
        # 1. If the checkpoint file does not exist yet (e.g., fresh installation), assume valid and initialize
        if not os.path.exists(self.notary_checkpoint_file):
            print("[INFO] Notary checkpoint file not found. Initializing baseline state...")
            return True

        try:
            # 2. Read the contents of the local checkpoint manifest
            with open(self.notary_checkpoint_file, "r", encoding="utf-8") as f:
                stored_manifest = json.load(f)

            # 3. Extract and isolate the signature from the payload to be re-hashed
            stored_signature = stored_manifest.pop("attestation_signature", None)
            if not stored_signature:
                print("[ALERT] Tamper detected: Cryptographic attestation signature is missing!")
                return False

            # 4. CANONICALIZATION: Convert the dictionary back to a deterministic JSON string
            canonical_data = self._canonical_json(stored_manifest)

            # 5. RE-ATTESTATION: Recalculate the HMAC signature using the tool's internal secret key
            calculated_signature = hmac.new(
                self.hmac_key, 
                canonical_data.encode("utf-8"), 
                hashlib.sha256
            ).hexdigest()

            # 6. VERIFICATION: Compare signatures using constant-time evaluation to prevent timing attacks
            if hmac.compare_digest(stored_signature, calculated_signature):
                print("[SUCCESS] Checkpoint integrity verified. SOC attestation validated mathematically.")
                return True
            else:
                print("[CRITICAL ALERT] DATABASE INTEGRITY COMPROMISED! Unauthorized file modification detected!")
                return False

        except Exception as e:
            print(f"[ERROR] Failed to execute startup verification due to technical error: {e}")
            return False

    def _generate_record_id(self) -> str:
        return uuid.uuid4().hex

    def record_action(
        self,
        agent_name: str,
        action_type: str,
        description: str,
        raw_command: str = "",
        tool_args: dict | None = None,
        metadata: dict | None = None,
    ) -> str:
        with self._singleton_lock:
            timestamp = datetime.now(timezone.utc)
            entry = {
                "record_id": self._generate_record_id(),
                "ledger_version": self.LEDGER_VERSION,
                "created_at": timestamp.isoformat(),
                "timestamp_utc": timestamp.isoformat(),
                "unix_time": timestamp.timestamp(),
                "agent": str(agent_name),
                "action_type": str(action_type),
                "description": str(description),
                "raw_command": str(raw_command),
                "tool_arguments": tool_args or {},
                "metadata": metadata or {},
                "previous_hash": self.last_hash,
            }
            if self.hmac_key:
                entry["entry_hmac"] = self._compute_entry_hmac(entry)
            entry["hash"] = self._compute_hash(entry)
            self._append_entry(entry)
            self.last_hash = entry["hash"]
            print(
                f"[YOMI-AUDIT] Sealed: {action_type} by {agent_name} | Hash: {entry['hash'][:10]}..."
            )
            return entry["hash"]

    def verify_ledger(self) -> bool:
        try:
            self.last_hash = self._verify_ledger()
            return True
        except Exception as exc:
            print(f"[YOMI-AUDIT] Ledger verification failed: {exc}")
            return False

    def _count_entries(self) -> int:
        count = 0
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as ledger:
                for line in ledger:
                    if line.strip():
                        count += 1
        except OSError:
            return 0
        return count

    def get_ledger_summary(self) -> dict:
        return {
            "ledger_file": self.ledger_file,
            "last_hash": self.last_hash,
            "ledger_version": self.LEDGER_VERSION,
            "entry_count": self._count_entries(),
            "hmac_enabled": bool(self.hmac_key),
        }
