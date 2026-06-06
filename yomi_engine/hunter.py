import os
import sys
import re

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Root-Cause Hunter 
# Purpose: Traces the origin (Patient Zero) of a detected anomaly using SIFT tools.
#          - Strictly headless execution.
#          - Strict Word-Boundary (Regex \b) for PID accuracy.
#          - Memory-safe string generator to prevent Plaso OOM crashes.
# ==============================================================================


class OmniVectorHunter:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()

    def _resolve_forensic_source(self) -> str | None:
        """
        Resolves the target evidence path safely.
        Prioritizes user-defined environment variables, defaults to root filesystem
        on SIFT/Linux, and provides a safe fallback for local testing.
        """
        env_path = os.environ.get("YOMI_FORENSIC_PATH")
        if env_path and os.path.exists(env_path):
            return env_path

        # Live Triage for Linux (SIFT Target)
        if os.name == "posix" and os.path.exists("/"):
            return "/"

        # Local Development Fallback (Testing only)
        if os.name == "nt" and os.path.exists("C:\\"):
            return "C:\\"

        return None

    def _parse_plaso_output(self, output: str, target_pid: int) -> str:
        """
        Parses Plaso timeline, strictly correlating events with the target PID using
        word-boundary regex to prevent partial match pollution.
        Utilizes a memory-safe generator to prevent Out-Of-Memory (OOM) crashes.
        """
        if not output:
            return "Plaso output was empty or unavailable."

        suspicious_events = []
        timestamp_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

        # Strict word boundary to prevent partial matches (e.g., matching 1234 in 812345)
        pid_pattern = re.compile(rf"\b{target_pid}\b")

        event_patterns = [
            (re.compile(r"logon.*success", flags=re.IGNORECASE), "Successful logon"),
            (
                re.compile(r"powershell|cmd\.exe|bash|sh", flags=re.IGNORECASE),
                "Shell execution",
            ),
            (
                re.compile(r"mimikatz|lsass|dump", flags=re.IGNORECASE),
                "Credential access",
            ),
            (
                re.compile(r"service.*start|runkey", flags=re.IGNORECASE),
                "Persistence mechanism",
            ),
        ]

        # Memory-safe generator to avoid duplicating massive strings into RAM lists
        def memory_safe_line_generator(text):
            start = 0
            while True:
                end = text.find("\n", start)
                if end == -1:
                    yield text[start:]
                    break
                yield text[start:end]
                start = end + 1

        for line in memory_safe_line_generator(output):
            normalized = line.strip()
            if not normalized:
                continue

            # Use regex search instead of simple string 'in' for strict matching
            if pid_pattern.search(normalized) or "MALICIOUS" in normalized.upper():
                match = timestamp_pattern.search(normalized)
                timestamp = match.group(1) if match else "UNKNOWN_TIME"

                desc = "Associated PID Activity"
                for pattern, description in event_patterns:
                    if pattern.search(normalized):
                        desc = description
                        break

                # Preserve encoded payloads up to 500 chars
                suspicious_events.append((timestamp, desc, normalized[:500]))

        if not suspicious_events:
            return f"No temporal artifacts directly correlated with PID {target_pid}."

        suspicious_events.sort(key=lambda item: item[0])
        window_start = suspicious_events[0][0]
        window_end = suspicious_events[-1][0]

        summary_lines = [
            f"[{evt[0]}] {evt[1]}: {evt[2]}" for evt in suspicious_events[:5]
        ]

        return (
            f"Temporal cluster linked to PID {target_pid} between {window_start} and {window_end}. "
            f"Key correlations:\n" + "\n".join(summary_lines)
        )

    def _parse_tsk_output(self, output: str) -> str:
        if not output:
            return "TSK output was empty or unavailable."

        deleted_patterns = re.compile(
            r"(?:\*|\(deleted\)|unallocated|carved).*?(?:mimikatz|powershell|cmd\.exe|shadow|sam|id_rsa)",
            flags=re.IGNORECASE,
        )
        matches = deleted_patterns.findall(output)

        if matches:
            unique_matches = sorted(set(matches), key=str.lower)
            return (
                f"Suspicious filesystem artifacts (TSK): "
                f"{', '.join(unique_matches[:5])}"
            )
        return "No deleted or hidden droppers found in TSK spatial output."

    def hunt_root_cause(self, target_pid: int) -> dict:
        print(f"[*] Initiating Root-Cause Hunt for PID {target_pid}...")

        if not isinstance(target_pid, int) or target_pid <= 0:
            msg = f"Invalid PID {target_pid}. Hunt aborted."
            self.audit.record_action("HUNTER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        forensic_source = self._resolve_forensic_source()
        if not forensic_source:
            msg = (
                "No live system root or forensic mapped drive identified. Hunt aborted."
            )
            self.audit.record_action("HUNTER", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        # Temporal Hunt
        print("[*] Querying Plaso super-timeline...")
        plaso_result = self.arsenal.run_plaso_timeline(forensic_source)

        temporal_clue = self._parse_plaso_output(
            plaso_result.get("output", ""), target_pid
        )
        if plaso_result.get("status") != "SUCCESS":
            temporal_clue = f"Plaso temporal analysis failed: {plaso_result.get('error', 'unknown error')}"

        # Spatial Hunt
        print("[*] Querying The Sleuth Kit for spatial artifacts...")
        tsk_result = self.arsenal.run_tsk_fls(forensic_source)

        spatial_clue = self._parse_tsk_output(tsk_result.get("output", ""))
        if tsk_result.get("status") != "SUCCESS":
            spatial_clue = f"TSK spatial analysis failed: {tsk_result.get('error', 'unknown error')}"

        hunt_summary = {
            "status": "HUNT_COMPLETE",
            "target_pid": target_pid,
            "forensic_source": forensic_source,
            "temporal_vector": temporal_clue,
            "spatial_vector": spatial_clue,
            "conclusion": f"Root-cause trace for PID {target_pid} compiled.",
        }

        self.audit.record_action(
            "HUNTER",
            "ROOT_CAUSE_COMPILED",
            f"PID {target_pid} Hunt Completed.",
            metadata={"source": forensic_source},
        )
        print(f"[*] Root-Cause trace finalized.")

        return hunt_summary


# ==============================================================================
# CLI EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 hunter.py <TARGET_PID>")
        sys.exit(1)

    try:
        target_pid = int(sys.argv[1])
    except ValueError:
        print("Error: Invalid PID format. Please provide an integer.")
        sys.exit(1)

    hunter = OmniVectorHunter()
    result = hunter.hunt_root_cause(target_pid)

    print("\n" + "=" * 50)
    print("HUNT CONCLUSION SUMMARY")
    print("=" * 50)
    print(f"Temporal Vector : {result.get('temporal_vector')}")
    print(f"Spatial Vector  : {result.get('spatial_vector')}")
    print(f"Status          : {result.get('conclusion')}")
    print("=" * 50)
