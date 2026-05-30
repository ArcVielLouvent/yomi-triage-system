import os
import json
import fcntl
import hashlib
from datetime import datetime, timezone

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - Immutable Stamp
# Purpose: Cryptographically secure, append-only audit trail for SANS compliance.
# ==============================================================================

class ImmutableStamp:
    """
    Maintains a cryptographic chain of custody for all AI actions within YTS.
    """
    def __init__(self):
        self.log_dir = "/workspaces/yomi-triage-system/yomi_data"
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.log_file = os.path.join(self.log_dir, "yomi_chain_of_custody.jsonl")
        self.last_hash = self._get_last_hash()

    def _ensure_log_exists(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'a', encoding='utf-8'):
                pass
            os.chmod(self.log_file, 0o600)

    def _get_last_hash(self):
        """Retrieves the hash of the last log entry to maintain the chain."""
        self._ensure_log_exists()
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                lines = f.readlines()
                fcntl.flock(f, fcntl.LOCK_UN)
                if lines:
                    last_entry = json.loads(lines[-1])
                    return last_entry.get("hash", "")
        except Exception:
            pass
        return "0" * 64

    def record_action(self, agent_name, action_type, description, raw_command=""):
        """
        Records an agent's action with a UTC timestamp and SHA-256 hash.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "agent": agent_name,
            "action_type": action_type, # e.g., 'EXECUTE', 'ANALYZE', 'REMEDIATE'
            "description": description,
            "raw_command": raw_command,
            "previous_hash": self.last_hash
        }
        
        log_string = json.dumps(log_entry, sort_keys=True)
        current_hash = hashlib.sha256(log_string.encode('utf-8')).hexdigest()
        
        log_entry["hash"] = current_hash
        self.last_hash = current_hash

        self._ensure_log_exists()
        with open(self.log_file, 'a', encoding='utf-8') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(log_entry) + '\n')
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f, fcntl.LOCK_UN)

        # Terminal feedback (Will be replaced by TUI later)
        print(f"[YOMI-AUDIT] Sealed: {action_type} by {agent_name} | Hash: {current_hash[:8]}...")
        return current_hash

# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    print("Initializing Yomi Immutable Stamp...\n")
    audit = ImmutableStamp()
    
    # Simulating AI actions
    audit.record_action("Swarm-Network", "SCAN", "Scanning active ports in memory dump", "vol.py -f dump.raw netscan")
    audit.record_action("Omni-Library", "MATCH", "Found vulnerability match for CVE-2023-1234", "")
    
    print("\nAudit trail successfully updated. Check yomi_data/yomi_chain_of_custody.jsonl")