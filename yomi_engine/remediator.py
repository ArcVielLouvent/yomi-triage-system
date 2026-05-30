import os
import time
import sys

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Reverser (v2.0)
# Purpose: Chronos Reversion Engine. Automatically generates safe, human-readable
#          remediation scripts (Bash/PS1) for frozen threats. Enforces the
#          "Human-in-the-Loop" requirement prior to destructive actions.
# ==============================================================================


class ReverserEngine:
    def __init__(self):
        self.audit = ImmutableStamp()
        # Ensure the quarantine and remediation output directories exist
        self.remediation_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "yomi_data", "remediation")
        )
        os.makedirs(self.remediation_dir, exist_ok=True)

    def generate_rollback_script(self, anomaly_data: dict) -> dict:
        """
        Dynamically writes a targeted cleanup script based on the threat's profile.
        Does NOT execute the script natively to prevent spoliation.
        """
        threat_pid = anomaly_data.get("pid", "UNKNOWN_PID")
        threat_path = anomaly_data.get("file_path", "/tmp/unknown_malware.bin")
        timestamp = int(time.time())

        script_filename = f"remediation_plan_PID{threat_pid}_{timestamp}.sh"
        script_filepath = os.path.join(self.remediation_dir, script_filename)

        # Constructing a safe, structured Bash script for Linux environments
        bash_payload = f"""#!/bin/bash
# ==============================================================================
# YOMI TRIAGE: AUTOMATED REMEDIATION PLAN
# TARGET PID : {threat_pid}
# TARGET FILE: {threat_path}
# GENERATED  : {time.ctime()}
# WARNING    : Review this script before execution. Requires ROOT privileges.
# ==============================================================================

echo "[*] Initiating Yomi Remediation Sequence for PID {threat_pid}..."

# 1. Isolate the binary (Quarantine) BEFORE termination to prevent self-deletion
echo "[*] Quarantining malicious executable..."
mkdir -p /tmp/yomi_quarantine
mv {threat_path} /tmp/yomi_quarantine/malware_{threat_pid}.quarantined 2>/dev/null
chmod -x /tmp/yomi_quarantine/malware_{threat_pid}.quarantined

# 2. Dump process memory footprint (Backup evidence before it dies)
echo "[*] Extracting raw process memory for post-mortem analysis..."
gcore -o /tmp/yomi_quarantine/memdump_{threat_pid}.core {threat_pid} 2>/dev/null

# 3. Terminate the cryogenically frozen process (Bypasses malware exit-handlers)
echo "[*] Executing 'Frozen Kill' on PID {threat_pid}..."
kill -9 {threat_pid} 2>/dev/null

echo "[+] Remediation Complete. Threat neutralized, memory dumped, and secured for reverse engineering."
"""
        try:
            with open(script_filepath, "w") as f:
                f.write(bash_payload)

            # Make the generated script executable
            os.chmod(script_filepath, 0o755)

            msg = f"Remediation script generated successfully at: {script_filepath}"
            print(f"\n[YOMI-REVERSER] [PLASMA BLUE] {msg}")
            print("[YOMI-REVERSER] [BLOOD RED] Awaiting SOC Analyst manual execution.")

            self.audit.record_action("REVERSER", "SCRIPT_GENERATED", msg)
            return {"status": "SUCCESS", "script_path": script_filepath}

        except Exception as e:
            error_msg = f"Failed to write remediation script: {str(e)}"
            self.audit.record_action("REVERSER", "ERROR", error_msg)
            return {"status": "ERROR", "message": error_msg}


# ==============================================================================
# DEVELOPMENT TESTING BLOCK (DO NOT DELETE - Used for Modular SANS Demo)
# ==============================================================================
if __name__ == "__main__":
    print("\n[+] Initializing The Reverser Engine...")
    reverser = ReverserEngine()

    # Simulating a threat payload passed down from the Triad Council / Sentinel
    mock_threat = {
        "pid": 4092,
        "file_path": "/tmp/suspicious_file.exe",
        "threat_type": "xz-utils backdoor",
    }

    print(f"[+] Generating rollback plan for frozen PID: {mock_threat['pid']}")
    result = reverser.generate_rollback_script(mock_threat)

    if result["status"] == "SUCCESS":
        print(
            f"\n[+] Validation: Check the folder '{reverser.remediation_dir}' to see the generated .sh file!"
        )
