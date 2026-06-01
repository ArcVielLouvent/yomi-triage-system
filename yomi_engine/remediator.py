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
from pathlib import Path

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Reverser (v3.0)
# Purpose: Chronos Reversion Engine. Generates safe, verifiable rollback scripts
#          from real threat artifact payloads and signs them with strong metadata.
# ==============================================================================


class ReverserEngine:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.remediation_dir = Path(__file__).resolve().parent.parent / "yomi_data" / "remediation"
        self.remediation_dir.mkdir(parents=True, exist_ok=True)
        self.gpg_binary = shutil.which("gpg")
        self.audit.record_action(
            "REVERSER",
            "INITIALIZATION",
            "Remediator engine initialized and ready for policy-safe rollback generation.",
        )

    def _validate_payload(self, anomaly_data: dict) -> tuple[bool, str]:
        if not isinstance(anomaly_data, dict):
            return False, "Anomaly payload must be a JSON-like object."

        pid = anomaly_data.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return False, f"Invalid or missing pid: {pid}"

        file_path = anomaly_data.get("file_path")
        if not isinstance(file_path, str) or not file_path:
            return False, "Invalid or missing file_path."

        if not os.path.isabs(file_path):
            return False, "file_path must be absolute to avoid accidental scope expansion."

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False, f"Target remediation file does not exist or is not a regular file: {file_path}"

        resolved_path = os.path.realpath(file_path)
        if resolved_path in {"/", "/bin", "/sbin", "/usr", "/etc"}:
            return False, f"Refusing remediation on critical system path: {resolved_path}"

        return True, ""

    def _generate_script(self, pid: int, raw_path: str, threat_type: str) -> tuple[Path, str]:
        timestamp = int(time.time())
        script_filename = f"remediation_plan_PID{pid}_{timestamp}.sh"
        script_filepath = self.remediation_dir / script_filename
        evidence_dir = Path("/tmp/yomi_evidence")
        evidence_dir.mkdir(parents=True, exist_ok=True)

        script_lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "# ====================================================================",
            "# YOMI AUTONOMOUS REMEDIATION PLAYBOOK",
            f"# Target PID : {pid}",
            f"# Threat Path: {raw_path}",
            f"# Threat Type: {threat_type}",
            f"# Generated  : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(timestamp))}",
            "# ====================================================================",
            "",
            f"echo '[*] Initiating Chronos Reversion for active threat PID {pid}'",
            "echo '[*] Preserving evidence before process control is exercised.'",
            f"mkdir -p {evidence_dir}",
            f"gcore -o {evidence_dir}/final_dump_{pid}.raw {pid} || true",
            "echo '[*] Applying kill chain containment controls.'",
            f"kill -STOP {pid} || true",
            "sleep 1",
            "echo '[*] Terminating agent while preserving forensic trace.'",
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
            completed = subprocess.run(
                [self.gpg_binary, "--batch", "--yes", "--detach-sign", "--output", str(signature_path), str(script_path)],
                capture_output=True,
                text=True,
            )
            if completed.returncode == 0:
                return signature_path
            print(f"[YOMI-REMEDIATOR] GPG signing failed: {completed.stderr.strip()}")

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

        signature_payload = {
            "signature_type": signature_type,
            "signed_by": "Yomi Remediator",
            "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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
            self.audit.record_action("REVERSER", "ABORTED", reason, metadata=anomaly_data)
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
            self.audit.record_action("REVERSER", "ERROR", error_msg, metadata=anomaly_data)
            return {"status": "ERROR", "message": error_msg}


def _parse_anomaly_payload(payload_path: str) -> dict:
    try:
        with open(payload_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        raise ValueError(f"Unable to load anomaly payload from {payload_path}: {exc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Yomi Remediator - Generate signed rollback playbooks from actual anomaly payloads."
    )
    parser.add_argument("--pid", type=int, help="Target process ID to remediate.")
    parser.add_argument("--file-path", help="Absolute path to the suspicious binary.")
    parser.add_argument("--threat-type", default="unknown", help="Optional threat classification.")
    parser.add_argument(
        "--payload-json",
        help="Optional JSON file containing anomaly payload {pid, file_path, threat_type}."
    )
    args = parser.parse_args()

    if args.payload_json:
        payload = _parse_anomaly_payload(args.payload_json)
    else:
        payload = {
            "pid": args.pid,
            "file_path": args.file_path,
            "threat_type": args.threat_type,
        }

    reverser = ReverserEngine()
    result = reverser.generate_rollback_script(payload)
    print(json.dumps(result, indent=2))
