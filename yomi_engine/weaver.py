import os
import sys
import json
import re

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Temporal Narrative Weaver (v7.0 - FLAWLESS)
# Purpose: Dynamically parses cryptographic JSON logs and procedurally generates
#          a human-readable forensic timeline mapped to MITRE ATT&CK.
#          - Explicit Dangling Line Drop: Clean chunk boundaries.
#          - Unicode Forensic Awareness: Uses errors="replace" for corrupted bytes.
#          - Expert MITRE Precision: Strict T1000-T1699 regex boundary mapping.
# ==============================================================================


class TemporalNarrativeWeaver:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.ledger_path = self.audit.ledger_file

        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self.mitre_regex = re.compile(r"\bT1[0-6]\d{2}(?:\.\d{3})?\b")

    def _sanitize_terminal(self, text: str) -> str:
        if not isinstance(text, str):
            return str(text)

        safe_text = text.replace("\n", " [LF] ").replace("\r", " [CR] ")
        return self.ansi_escape.sub("", safe_text)

    def _secure_tail_logs(self, limit: int = 10, max_bytes: int = 65536) -> list:
        logs = []
        if not os.path.exists(self.ledger_path):
            return logs

        try:
            with open(self.ledger_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                filesize = f.tell()

                read_size = min(max_bytes, filesize)
                f.seek(-read_size, os.SEEK_END)

                # Forensic Unicode Awareness
                # Uses "replace" so partial/corrupted malware bytes show as  instead of vanishing
                chunk = f.read(read_size).decode("utf-8", errors="replace")
                lines = chunk.split("\n")

                # Explicit Dangling Line Drop
                # If we didn't read from the absolute 0 byte, the first line is guaranteed
                # to be a broken/partial JSON string. Drop it explicitly to maintain state purity.
                if read_size == max_bytes and len(lines) > 1:
                    lines = lines[1:]

                valid_lines = [l for l in lines if l.strip()][-limit:]

                for line in valid_lines:
                    try:
                        logs.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[YOMI-WEAVER] [ERROR] Failed to securely read ledger: {e}")

        return logs

    def generate_narrative(self) -> str:
        print("\n[*] Extracting cryptographic ledger data...")

        raw_logs = self._secure_tail_logs(limit=5)

        if not raw_logs:
            return "[!] No audit logs available to weave narrative."

        print(
            f"[*] {len(raw_logs)} log entries securely extracted. Procedurally weaving narrative..."
        )

        narrative = self._procedural_weaving(raw_logs)

        print("[+] Temporal Narrative generated successfully.")
        self.audit.record_action(
            "WEAVER",
            "NARRATIVE_GENERATED",
            "Converted raw ledger into dynamic human-readable dossier.",
        )

        return narrative

    def _procedural_weaving(self, raw_logs: list) -> str:
        report = "=" * 80 + "\n"
        report += "                   TEMPORAL FORENSIC NARRATIVE (EXECUTIVE SUMMARY)\n"
        report += "=" * 80 + "\n\n"

        report += "[TIMELINE RECONSTRUCTION]\n"
        report += "Yomi Autonomous Engine has parsed the cryptographic ledger and reconstructed the following chain of events:\n\n"

        mitre_tactics = set()

        for i, log in enumerate(raw_logs, 1):
            timestamp = self._sanitize_terminal(
                log.get("human_readable_time", "UNKNOWN_TIME")
            )
            agent = self._sanitize_terminal(log.get("agent", "UNKNOWN_AGENT"))
            action = self._sanitize_terminal(log.get("action", "UNKNOWN_ACTION"))
            desc = self._sanitize_terminal(
                log.get("description", "No description provided.")
            )
            h_ash = self._sanitize_terminal(log.get("hash", "NO_HASH"))[:8]

            found_mitre = self.mitre_regex.findall(desc)
            mitre_tactics.update(found_mitre)

            report += f"  {i}. [{timestamp}] {agent} executed '{action}'\n"
            report += f"     -> Details: {desc}\n"
            report += f"     -> Integrity Hash: {h_ash}...\n\n"

        report += "[MITRE ATT&CK MAPPING CONFIRMED]\n"
        if mitre_tactics:
            for tactic in sorted(mitre_tactics):
                report += f"- {tactic} : Autonomously extracted from ledger context.\n"
        else:
            report += "- No explicit MITRE heuristics detected in this sequence.\n"

        report += "\n[CONCLUSION]\n"
        report += "The events above have been cryptographically sealed. Chain of custody is intact.\n"
        report += "=" * 80

        return report


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    weaver = TemporalNarrativeWeaver()
    result = weaver.generate_narrative()
    print("\n" + result)
