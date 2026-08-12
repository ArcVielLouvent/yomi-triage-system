import os
import sys
import json
import re

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - IoE MITRE ATT&CK Mapper (v3.0)
# Purpose: Translates raw heuristic strings into standardized MITRE tactical IDs.
#          - Hardened against Substring False Positives via Regex Escaping.
#          - De-duplicated MITRE metric reporting for SANS compliance.
#          - Safe Type-Casting to prevent Triage crashes.
#          - Standalone CLI Runner enabled for rapid SIFT evaluation.
# ==============================================================================


class MitreMapper:
    def __init__(self):
        self.audit = ImmutableStamp()

        # The exact IoE Dictionary from the KuroTech Whitepaper
        self.raw_signatures = {
            "PE_INJECT": {
                "mitre_id": "T1055",
                "desc": "Process Injection (VAD manipulation)",
                "keywords": ["inject", "unbacked", "vad", "shellcode"],
            },
            "YR_RANSOMWARE": {
                "mitre_id": "T1486",
                "desc": "Data Encrypted for Impact",
                "keywords": ["ransom", "high-entropy", "mass file io", "encrypt"],
            },
            "PROC_BAD_DTB": {
                "mitre_id": "T1014",
                "desc": "Rootkit (Direct Kernel Object Manipulation)",
                "keywords": ["dkom", "bad dtb", "directorytablebase", "hidden"],
            },
            "PEB_MASQ": {
                "mitre_id": "T1036.004",
                "desc": "Masquerading: Task or Service",
                "keywords": ["peb", "masquerad", "fake name", "svchost"],
            },
            "UM_APC": {
                "mitre_id": "T1055.004",
                "desc": "Process Injection: Asynchronous Procedure Call",
                "keywords": ["apc", "user-mode hook"],
            },
            "C2_BEACON": {
                "mitre_id": "T1071",
                "desc": "Application Layer Protocol (C2)",
                "keywords": [
                    "beacon",
                    "outbound",
                    "established",
                    "command-and-control",
                    "connection",
                ],
            },
        }

        self.ioe_signatures = {}
        for ioe, data in self.raw_signatures.items():
            # Full boundary wrapper and re.escape to handle spaces/hyphens perfectly
            pattern_str = (
                r"\b(?:" + "|".join(re.escape(k) for k in data["keywords"]) + r")\b"
            )
            self.ioe_signatures[ioe] = {
                "mitre_id": data["mitre_id"],
                "desc": data["desc"],
                "regex": re.compile(pattern_str, re.IGNORECASE),
            }

    def map_anomalies(self, anomalies: list) -> list:
        """
        Scans raw anomaly text and maps it to official MITRE tactics.
        """
        mapped_results = []

        if not isinstance(anomalies, list):
            self.audit.record_action(
                "MITRE_MAPPER", "ERROR", "Invalid input type. Expected a list."
            )
            return mapped_results

        unique_mitre_ids = set() 

        for anomaly in anomalies:
            anomaly_str = str(anomaly)
            matched_tactics = []

            for ioe, data in self.ioe_signatures.items():
                if data["regex"].search(anomaly_str):
                    matched_tactics.append(
                        {
                            "ioe_signature": ioe,
                            "mitre_id": data["mitre_id"],
                            "tactical_desc": data["desc"],
                        }
                    )
                    unique_mitre_ids.add(data["mitre_id"])

            if matched_tactics:
                mapped_results.append(
                    {"raw_evidence": anomaly_str, "matched_tactics": matched_tactics}
                )
            else:
                mapped_results.append(
                    {
                        "raw_evidence": anomaly_str,
                        "matched_tactics": [
                            {
                                "ioe_signature": "GENERIC_ANOMALY",
                                "mitre_id": "T1106",
                                "tactical_desc": "Suspicious execution without explicit signature match",
                            }
                        ],
                    }
                )
                unique_mitre_ids.add("T1106")

        total_unique_tactics = len(unique_mitre_ids)

        # Cleaned UI output, retaining module tag for the central Dashboard
        print(
            f"[YOMI-MAPPER] Tactical mapping complete. {total_unique_tactics} unique MITRE signatures identified."
        )
        self.audit.record_action(
            "MITRE_MAPPER",
            "MAPPED",
            f"Mapped {total_unique_tactics} unique tactics across {len(anomalies)} anomalies.",
        )

        return mapped_results


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            'Usage: python3 mitre_mapper.py "<anomaly_string_1>" "<anomaly_string_2>" ...'
        )
        print(
            'Example: python3 mitre_mapper.py "Process high-entropy outbound connection detected."'
        )
        sys.exit(1)

    anomalies_input = sys.argv[1:]
    mapper = MitreMapper()

    print("[*] Initializing MitreMapper Engine...")
    results = mapper.map_anomalies(anomalies_input)

    print("\n[+] Mapping Results:")
    print(json.dumps(results, indent=2))
    sys.exit(0)
