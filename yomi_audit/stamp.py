import os
import json
import time
import hashlib
import threading

# ==============================================================================
# YOMI TRIAGE SYSTEM: Audit Module - The Immutable Stamp (v3.0)
# Purpose: Cryptographic, tamper-evident ledger for SANS Evidence Integrity.
#          Implements strict hash-chaining and granular tool-call logging.
# ==============================================================================


class ImmutableStamp:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        # Singleton pattern ensures all modules write to the exact same hash-chain
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ImmutableStamp, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self.log_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "yomi_data", "audit_logs")
        )
        os.makedirs(self.log_dir, exist_ok=True)
        self.ledger_file = os.path.join(self.log_dir, "cryptographic_ledger.jsonl")
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Reads the hash of the last entry to maintain the cryptographic chain."""
        genesis_hash = hashlib.sha256(b"YOMI_GENESIS_BLOCK_SANS_FIND_EVIL").hexdigest()
        if not os.path.exists(self.ledger_file):
            return genesis_hash
        try:
            with open(self.ledger_file, "r") as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1].strip())
                    return last_entry.get("hash", genesis_hash)
        except Exception:
            pass
        return genesis_hash

    def record_action(
        self,
        agent_name: str,
        action_type: str,
        description: str,
        raw_command: str = "N/A",
        tool_args: dict = None,
    ) -> str:
        """
        Records a granular forensic event with a cryptographic signature linking it to the previous event.
        Secures the file permissions immediately after writing.
        """
        with self._lock:  # Thread-safe writing for parallel Swarm agents
            timestamp = time.time()

            formatted_utc_time = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp)
            )

            # Granular SANS Audit Structure
            entry = {
                "timestamp": timestamp,
                "human_readable_time": formatted_utc_time,
                "agent": agent_name,
                "action": action_type,
                "description": description,
                "raw_command": raw_command,
                "tool_arguments": tool_args or {},
                "previous_hash": self.last_hash,
            }

            # Create deterministic string for hashing (sort_keys ensures consistent JSON stringification)
            entry_string = json.dumps(entry, sort_keys=True)
            new_hash = hashlib.sha256(entry_string.encode("utf-8")).hexdigest()

            # Append the new hash to the entry
            entry["hash"] = new_hash
            self.last_hash = new_hash

            # Atomic append to ledger
            with open(self.ledger_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Anti-Spoliation: Restrict file permissions (Read/Write for owner only, no execution)
            try:
                os.chmod(self.ledger_file, 0o600)
            except OSError:
                pass  # Silently pass on Windows environments where chmod 0600 might behave differently

            # Print minimal output to terminal for visual feedback
            print(
                f"[YOMI-AUDIT] Sealed: {action_type} by {agent_name} | Hash: {new_hash[:8]}..."
            )
            return new_hash
