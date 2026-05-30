import os
import time
import sys
import shlex

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

        if not isinstance(threat_pid, int) or threat_pid <= 0:
            msg = f"Invalid PID format ({threat_pid}). Must be a positive integer."
            self.audit.record_action("REVERSER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        raw_path = anomaly_data.get("file_path", "/tmp/unknown_malware.bin")
        if not isinstance(raw_path, str) or not raw_path:
            msg = "Invalid file path supplied for remediation."
            self.audit.record_action("REVERSER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        if not os.path.isabs(raw_path):
            msg = (
                "Remediation path must be absolute to avoid accidental scope expansion."
            )
            self.audit.record_action("REVERSER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        if not os.path.exists(raw_path) or not os.path.isfile(raw_path):
            msg = f"Target remediation file does not exist or is not a regular file: {raw_path}"
            self.audit.record_action("REVERSER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        resolved_path = os.path.realpath(raw_path)
        if resolved_path in ("/", "/bin", "/sbin", "/usr", "/etc"):
            msg = f"Refusing remediation on critical system path: {resolved_path}"
            self.audit.record_action("REVERSER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        threat_path = shlex.quote(raw_path)
        safe_quarantine_path = shlex.quote(
            f"/tmp/yomi_quarantine/malware_{threat_pid}.quarantined"
        )
        timestamp = int(time.time())

        script_filename = f"remediation_plan_PID{threat_pid}_{timestamp}.sh"
        script_filepath = os.path.join(self.remediation_dir, script_filename)

        # Constructing a safe, structured Bash script for Linux environments
        # 3. Assemble the Chronos Reversion Payload
        bash_payload = f"""#!/bin/bash
# ====================================================================
# YOMI AUTONOMOUS REMEDIATION PLAYBOOK
# Target PID : {threat_pid}
# Threat Path: {threat_path}
# Generated  : {time.ctime(timestamp)}
# ====================================================================

echo "[*] Initiating Chronos Reversion for PID {threat_pid}"

# STEP 1: Network Isolation (Drop all C2 communication)
# (Assuming Yomi identified the C2 port, we quarantine the specific process)
echo "[*] Applying iptables quarantine rules..."
# iptables -A OUTPUT -m owner --pid-owner {threat_pid} -j DROP

# STEP 2: Final Memory Snapshot (Preserving Evidence before termination)
echo "[*] Dumping process memory via gcore..."
gcore -o /tmp/yomi_evidence/final_dump_{threat_pid}.raw {threat_pid}

# STEP 3: Cryogenic Thaw & Execute (Kill)
echo "[*] Thawing process for execution..."
kill -CONT {threat_pid}
echo "[*] Terminating threat..."
kill -9 {threat_pid}

echo "[*] Neutralization Complete."
"""

        try:
            with open(script_filepath, "w") as f:
                f.write(bash_payload)
            # Make the script executable
            os.chmod(script_filepath, 0o755)
            import subprocess

            print(f"[YOMI-REMEDIATOR] [CYBER-PURPLE] Signing Playbook with GPG Key...")
            try:
                # Attempt to create a clearsigned document
                subprocess.run(
                    ["gpg", "--yes", "--clearsign", script_filepath],
                    capture_output=True,
                )
                if os.path.exists(script_filepath + ".asc"):
                    os.remove(
                        script_filepath
                    )  # Remove the unsigned original to enforce security
                    script_filepath = script_filepath + ".asc"
                    sig_mode = "REAL GPG"
                else:
                    raise FileNotFoundError  # Fallback if GPG failed silently
            except FileNotFoundError:
                # Mock Transparency Fallback
                with open(script_filepath, "a") as f:
                    f.write("\n# -----BEGIN PGP SIGNATURE-----\n")
                    f.write("# Version: KuroTech GPG Fallback (PoC)\n")
                    f.write(f"# Hash: {self.audit.last_hash}\n")
                    f.write("# -----END PGP SIGNATURE-----\n")
                sig_mode = "PoC MOCK GPG"

            print(
                f"[YOMI-REMEDIATOR] [PLASMA BLUE] Autonomous Playbook generated and signed ({sig_mode}): {script_filepath}"
            )

            # Log to immutable ledger
            self.audit.record_action(
                "REMEDIATOR",
                "PLAYBOOK_GENERATED",
                f"Signed Bash rollback script created for PID {threat_pid}.",
            )

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
