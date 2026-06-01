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

        suspicious_events = []
        timestamp_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
        event_patterns = [
            (re.compile(r"logon.*success", flags=re.IGNORECASE), "Suspicious successful logon event"),
            (re.compile(r"powershell|cmd\.exe", flags=re.IGNORECASE), "Command shell execution event"),
            (re.compile(r"mimikatz|lsass", flags=re.IGNORECASE), "Credential dumping or LSASS access event"),
            (re.compile(r"delete|unallocated|carved", flags=re.IGNORECASE), "Deleted/orphaned artifact event"),
        ]

        for line in output.splitlines():
            match = timestamp_pattern.search(line)
            timestamp = match.group(1) if match else "UNKNOWN_TIME"
            normalized = line.strip()
            for pattern, description in event_patterns:
                if pattern.search(normalized):
                    suspicious_events.append((timestamp, description, normalized))

        if not suspicious_events:
            return "No suspicious temporal artifacts found."

        suspicious_events.sort(key=lambda item: item[0])
        window_start = suspicious_events[0][0]
        window_end = suspicious_events[-1][0]
        summary_lines = [
            f"[{evt[0]}] {evt[1]}: {evt[2]}" for evt in suspicious_events[:3]
        ]
        return (
            f"Suspicious timeline cluster detected between {window_start} and {window_end}. "
            f"Key events: {' | '.join(summary_lines)}"
        )

    def _parse_tsk_output(self, output: str) -> str:
        if not output:
            return "TSK output was empty or unavailable."

        deleted_patterns = re.compile(r"mimikatz|powershell|cmd\.exe|unallocated|deleted|carved|shadow|sam", flags=re.IGNORECASE)
        matches = deleted_patterns.findall(output)
        if matches:
            unique_matches = sorted(set(matches), key=str.lower)
            return (
                "Suspicious file system artifacts identified by TSK: "
                f"{', '.join(unique_matches)}"
            )
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
    target_pid = int(os.environ.get("YOMI_HUNTER_PID", "9999"))
    result = hunter.hunt_root_cause(target_pid)
    print(f"\n[+] Hunt Conclusion: {result.get('conclusion')}\n")
