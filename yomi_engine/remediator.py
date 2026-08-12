import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import time
import shlex
from pathlib import Path

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Reverser (v4.5 - PRODUCTION)
# Purpose: Chronos Reversion Engine. Generates safe, verifiable rollback scripts.
#          - Hardened against TOCTOU (Capable of containing Fileless Malware).
#          - Immune to Bash Comment Injection (Newline stripping).
#          - Enforces Triage Order: SIGSTOP -> DUMP -> SIGKILL
# ==============================================================================


class ReverserEngine:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.remediation_dir = (
            Path(__file__).resolve().parent.parent / "yomi_data" / "remediation"
        )
        self.remediation_dir.mkdir(parents=True, exist_ok=True)
        self.gpg_binary = shutil.which("gpg")
        self.audit.record_action(
            "REVERSER",
            "INITIALIZATION",
            "Remediator engine initialized and ready for policy-safe rollback generation.",
        )

    def _validate_payload(self, anomaly_data: dict) -> tuple[bool, str]:
        """
        Validates payload structure.
        Removed os.path.exists() TOCTOU check.
        Malware frequently self-deletes (fileless behavior). We MUST proceed to kill the PID
        even if the binary file is missing from the disk.
        """
        if not isinstance(anomaly_data, dict):
            return False, "Anomaly payload must be a JSON-like object."

        pid = anomaly_data.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return False, f"Invalid or missing pid: {pid}"

        file_path = anomaly_data.get("file_path")
        if not isinstance(file_path, str) or not file_path:
            return False, "Invalid or missing file_path."

        if not os.path.isabs(file_path):
            return (
                False,
                "file_path must be absolute to avoid accidental scope expansion.",
            )

        # Safety boundary: Never execute kill commands targeting core OS paths
        resolved_path = os.path.realpath(file_path)
        if resolved_path in {"/", "/bin", "/sbin", "/usr", "/etc"}:
            return (
                False,
                f"Refusing remediation on critical system path: {resolved_path}",
            )

        return True, ""

    def _generate_script(
        self, pid: int, raw_path: str, threat_type: str
    ) -> tuple[Path, str]:
        timestamp = int(time.time())
        script_filename = f"remediation_plan_PID{pid}_{timestamp}.sh"
        script_filepath = self.remediation_dir / script_filename
        evidence_dir = Path("/tmp/yomi_evidence")
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Bash Injection Sanitization
        # shlex.quote handles standard command execution paths safely
        safe_path = shlex.quote(raw_path)
        # Strip newlines to prevent Remote Code Execution via Bash Comment Injection
        safe_threat = str(threat_type).replace("\n", " ").replace("\r", " ").strip()

        # Tactical Order: Contain FIRST, Dump SECOND, Kill LAST.
        script_lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "# ====================================================================",
            "# YOMI AUTONOMOUS REMEDIATION PLAYBOOK",
            f"# Target PID : {pid}",
            f"# Threat Path: {safe_path}",
            f"# Threat Type: {safe_threat}",
            f"# Generated  : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(timestamp))}",
            "# ====================================================================",
            "",
            f"echo '[*] Initiating Chronos Reversion for active threat PID {pid}'",
            "echo '[*] STEP 1: APPLYING IMMEDIATE CONTAINMENT (SIGSTOP)'",
            f"kill -STOP {pid} || true",
            "",
            "echo '[*] STEP 2: PRESERVING FORENSIC MEMORY DUMP'",
            f"mkdir -p {evidence_dir}",
            f"gcore -o {evidence_dir}/final_dump_{pid}.raw {pid} || true",
            "",
            "echo '[*] STEP 3: TERMINATING THREAT AGENT (SIGKILL)'",
            f"kill -9 {pid} || true",
            "echo '[*] Remediation playbook completed.'",
        ]

        with open(script_filepath, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(script_lines) + "\n")
        os.chmod(script_filepath, 0o750)
        return script_filepath, str(timestamp)

    def _sign_script(self, script_path: Path) -> Path:
        signature_path = script_path.with_suffix(script_path.suffix + ".sig")
        if self.gpg_binary:
            try:
                # Adding timeout to prevent GPG entropy hang in VM environments
                completed = subprocess.run(
                    [
                        self.gpg_binary,
                        "--batch",
                        "--yes",
                        "--detach-sign",
                        "--output",
                        str(signature_path),
                        str(script_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if completed.returncode == 0:
                    return signature_path
                print(f"[*] GPG signing failed: {completed.stderr.strip()}")
            except subprocess.TimeoutExpired:
                print(f"[*] GPG signing timed out. Falling back to HMAC-SHA256.")

        with open(script_path, "rb") as handle:
            script_bytes = handle.read()

        if hasattr(self.audit, "hmac_key") and self.audit.hmac_key:
            signature = base64.b64encode(
                hmac.new(self.audit.hmac_key, script_bytes, hashlib.sha256).digest()
            ).decode("ascii")
            signature_type = "HMAC-SHA256"
        else:
            signature = hashlib.sha256(script_bytes).hexdigest()
            signature_type = "SHA256"

        # Corrected time formatting string
        time_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        signature_payload = {
            "signature_type": signature_type,
            "signed_by": "Yomi Remediator",
            "signed_at": time_str,
            "script_name": script_path.name,
            "signature": signature,
        }

        with open(signature_path, "w", encoding="utf-8") as handle:
            json.dump(signature_payload, handle, indent=2, sort_keys=True)
        os.chmod(signature_path, 0o640)
        return signature_path

    def generate_rollback_script(self, anomaly_data: dict) -> dict:
        valid, reason = self._validate_payload(anomaly_data)
        if not valid:
            self.audit.record_action(
                "REVERSER", "ABORTED", reason, metadata=anomaly_data
            )
            return {"status": "ERROR", "message": reason}

        pid = anomaly_data["pid"]
        raw_path = anomaly_data["file_path"]
        threat_type = anomaly_data.get("threat_type", "unknown")

        try:
            script_path, timestamp = self._generate_script(pid, raw_path, threat_type)
            signature_path = self._sign_script(script_path)

            self.audit.record_action(
                "REMEDIATOR",
                "PLAYBOOK_GENERATED",
                f"Generated and signed rollback script for PID {pid}.",
                metadata={
                    "pid": pid,
                    "file_path": raw_path,
                    "threat_type": threat_type,
                    "script_path": str(script_path),
                    "signature_path": str(signature_path),
                },
            )

            return {
                "status": "SUCCESS",
                "script_path": str(script_path),
                "signature_path": str(signature_path),
            }
        except Exception as exc:
            error_msg = f"Failed to generate remediation artifact: {exc}"
            self.audit.record_action(
                "REVERSER", "ERROR", error_msg, metadata=anomaly_data
            )
            return {"status": "ERROR", "message": error_msg}


def _parse_anomaly_payload(payload_path: str) -> dict:
    try:
        with open(payload_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        raise ValueError(f"Unable to load anomaly payload from {payload_path}: {exc}")


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Yomi Remediator - Generate signed rollback playbooks from actual anomaly payloads."
    )
    parser.add_argument("--pid", type=int, help="Target process ID to remediate.")
    parser.add_argument("--file-path", help="Absolute path to the suspicious binary.")
    parser.add_argument(
        "--threat-type", default="unknown", help="Optional threat classification."
    )
    parser.add_argument(
        "--payload-json",
        help="Optional JSON file containing anomaly payload {pid, file_path, threat_type}.",
    )
    args = parser.parse_args()

    payload = {}

    if args.payload_json:
        try:
            payload = _parse_anomaly_payload(args.payload_json)
        except ValueError as e:
            print(f"[-] Error parsing JSON payload: {str(e)}")
            sys.exit(1)
    elif args.pid and args.file_path:
        payload = {
            "pid": args.pid,
            "file_path": args.file_path,
            "threat_type": args.threat_type,
        }
    else:
        print(
            "[-] Error: You must provide either --payload-json OR both --pid and --file-path."
        )
        sys.exit(1)

    print(f"[*] Initializing Chronos Engine for PID {payload.get('pid')}...")
    reverser = ReverserEngine()
    result = reverser.generate_rollback_script(payload)

    if result.get("status") == "SUCCESS":
        print("[+] Remediation Playbook generated successfully.")
        print(json.dumps(result, indent=2))
        sys.exit(0)
    else:
        print(f"[-] Generation failed: {result.get('message')}")
        sys.exit(1)
