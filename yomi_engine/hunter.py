import os
import sys
import re

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Root-Cause Hunter (v3.0)
# Purpose: Traces the origin (Patient Zero) of a detected anomaly.
#          Utilizes Plaso for timeline reconstruction and TSK for deleted artifacts.
# ==============================================================================


class OmniVectorHunter:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()

    def _resolve_forensic_source(self) -> str | None:
        candidates = [
            os.environ.get("YOMI_FORENSIC_PATH", ""),
            "/dev/sda1",
            "/mnt/forensic/disk.img",
            "/tmp/forensic_image.img",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def _parse_plaso_output(self, output: str) -> str:
        if not output:
            return "Plaso output was empty or unavailable."

        events = []
        for line in output.splitlines():
            normalized = line.lower()
            if "logon" in normalized and "success" in normalized:
                events.append("Suspicious successful logon event detected.")
            if "powershell" in normalized or "cmd.exe" in normalized:
                events.append("Command shell activity observed near time of compromise.")
            if "mimikatz" in normalized or "lsass" in normalized:
                events.append("Credential dumping behavior observed in timeline output.")
            if len(events) >= 3:
                break

        return events[0] if events else "No suspicious temporal artifacts found."

    def _parse_tsk_output(self, output: str) -> str:
        if not output:
            return "TSK output was empty or unavailable."

        if re.search(r"mimikatz|powershell|cmd\.exe|unallocated|deleted", output, flags=re.IGNORECASE):
            return "Suspicious deleted or orphaned binary artifacts identified by TSK."
        return "No obvious deleted or hidden droppers found in TSK output."

    def hunt_root_cause(self, target_pid: int) -> dict:
        print(f"\n[YOMI-HUNTER] [CYBER-PURPLE] Initiating Root-Cause Hunt for PID {target_pid}...")

        if not isinstance(target_pid, int) or target_pid <= 0:
            msg = f"Invalid PID for root-cause hunt: {target_pid}. Aborting."
            self.audit.record_action("HUNTER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        forensic_source = self._resolve_forensic_source()
        if not forensic_source:
            msg = "No forensic image or device path available for root-cause analysis."
            self.audit.record_action("HUNTER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        print("[YOMI-HUNTER] Querying Plaso super-timeline for temporal anomalies...")
        plaso_result = self.arsenal.run_plaso_timeline(forensic_source)

        temporal_clue = self._parse_plaso_output(plaso_result.get("output", ""))
        if plaso_result.get("status") != "SUCCESS":
            temporal_clue = f"Plaso analysis failed: {plaso_result.get('error', 'unknown error')}"

        print("[YOMI-HUNTER] Querying The Sleuth Kit for filesystem artifacts...")
        tsk_result = self.arsenal.run_tsk_fls(forensic_source)

        spatial_clue = self._parse_tsk_output(tsk_result.get("output", ""))
        if tsk_result.get("status") != "SUCCESS":
            spatial_clue = f"TSK analysis failed: {tsk_result.get('error', 'unknown error')}"

        hunt_summary = {
            "status": "HUNT_COMPLETE",
            "target_pid": target_pid,
            "forensic_source": forensic_source,
            "temporal_vector": temporal_clue,
            "spatial_vector": spatial_clue,
            "conclusion": "Root-cause trace assembled from live forensic outputs and timeline data.",
        }

        self.audit.record_action("HUNTER", "ROOT_CAUSE_FOUND", str(hunt_summary))
        print("[YOMI-HUNTER] [PLASMA BLUE] Root-Cause trace finalized. Awaiting Triad Council assessment.")

        return hunt_summary


if __name__ == "__main__":
    print("\n[+] Activating Root-Cause Hunter...")
    hunter = OmniVectorHunter()
    result = hunter.hunt_root_cause(4092)
    print(f"\n[+] Hunt Conclusion: {result.get('conclusion')}\n")
