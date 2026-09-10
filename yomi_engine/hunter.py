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

    def _resolve_registry_hive_path(self) -> str | None:
        """
        Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT) are not part of a
        live Linux SIFT host's own filesystem the way a forensic source
        root is -- they're artifacts already carved out of the disk image
        under examination. Unlike _resolve_forensic_source(), there is
        deliberately NO automatic fallback here: guessing a path would
        silently analyze the wrong (or no) hive. Operators must point at
        one explicitly.
        """
        env_path = os.environ.get("YOMI_REGISTRY_HIVE_PATH")
        if env_path and os.path.exists(env_path):
            return env_path
        return None

    def _parse_reglookup_output(self, output: str) -> str:
        """
        reglookup emits a flat CSV-like dump of every key/value in the
        hive -- far too much to hand an LLM directly. Filters down to
        keys historically associated with persistence mechanisms (Run/
        RunOnce autostart, service creation, Winlogon shell hijack,
        AppInit_DLLs injection, IFEO debugger hijack), the same
        keyword-narrowing philosophy as _parse_tsk_output's deleted-file
        filter above.
        """
        if not output:
            return "Registry output was empty or unavailable."

        persistence_pattern = re.compile(
            r"(?:\\Run\b|\\RunOnce\b|\\Services\\|Winlogon\\Shell|"
            r"AppInit_DLLs|Image File Execution Options|"
            r"ShellServiceObjectDelayLoad)",
            flags=re.IGNORECASE,
        )

        def memory_safe_line_generator(text):
            start = 0
            while True:
                end = text.find("\n", start)
                if end == -1:
                    yield text[start:]
                    break
                yield text[start:end]
                start = end + 1

        persistence_hits = []
        for line in memory_safe_line_generator(output):
            normalized = line.strip()
            if not normalized:
                continue
            if persistence_pattern.search(normalized):
                persistence_hits.append(normalized[:500])

        if not persistence_hits:
            return "No known persistence-related registry keys found."

        unique_hits = sorted(set(persistence_hits), key=str.lower)[:5]
        return (
            f"Registry persistence artifacts detected "
            f"({len(persistence_hits)} total, showing up to 5): "
            + " | ".join(unique_hits)
        )

    def hunt_registry_persistence(self) -> dict:
        """
        Separate from hunt_root_cause() deliberately: registry findings
        aren't scoped to a single target PID the way Plaso/TSK timeline
        correlation is (a Run key doesn't carry a PID), and a hive isn't
        always available (live Linux host with no carved Windows hive
        yet). SKIPPED is an expected, common outcome here, not an error.
        """
        print("[*] Initiating Registry Persistence Hunt...")

        hive_path = self._resolve_registry_hive_path()
        if not hive_path:
            msg = (
                "No registry hive path configured (set "
                "YOMI_REGISTRY_HIVE_PATH to a carved SYSTEM/SOFTWARE/"
                "NTUSER.DAT hive file). Registry hunt skipped -- expected "
                "on a live Linux SIFT host with no extracted Windows hive "
                "available yet."
            )
            self.audit.record_action("HUNTER", "REGISTRY_HUNT_SKIPPED", msg)
            return {"status": "SKIPPED", "message": msg, "registry_vector": None}

        reg_result = self.arsenal.run_reglookup(hive_path)
        registry_clue = self._parse_reglookup_output(reg_result.get("output", ""))
        if reg_result.get("status") != "SUCCESS":
            registry_clue = (
                f"Registry analysis failed: {reg_result.get('error', 'unknown error')}"
            )

        self.audit.record_action(
            "HUNTER",
            "REGISTRY_HUNT_COMPLETE",
            f"Registry persistence hunt completed against {hive_path}.",
            metadata={"hive_path": hive_path},
        )
        return {
            "status": "HUNT_COMPLETE",
            "hive_path": hive_path,
            "registry_vector": registry_clue,
        }

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
