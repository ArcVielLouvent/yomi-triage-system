import os
import sys
import json

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - IoE MITRE ATT&CK Mapper
# Purpose: Translates raw heuristic strings from the Predator Swarm into
#          standardized MITRE ATT&CK tactical IDs and Indicators of Evil (IoE).
# ==============================================================================

class MitreMapper:
    def __init__(self):
        self.audit = ImmutableStamp()
        
        # The exact IoE Dictionary from the KuroTech Whitepaper
        self.ioe_signatures = {
            "PE_INJECT": {
                "mitre_id": "T1055", 
                "desc": "Process Injection (VAD manipulation)", 
                "keywords": ["inject", "unbacked", "vad", "shellcode"]
            },
            "YR_RANSOMWARE": {
                "mitre_id": "T1486", 
                "desc": "Data Encrypted for Impact", 
                "keywords": ["ransom", "high-entropy", "mass file io", "encrypt"]
            },
            "PROC_BAD_DTB": {
                "mitre_id": "T1014", 
                "desc": "Rootkit (Direct Kernel Object Manipulation)", 
                "keywords": ["dkom", "bad dtb", "directorytablebase", "hidden"]
            },
            "PEB_MASQ": {
                "mitre_id": "T1036.004", 
                "desc": "Masquerading: Task or Service", 
                "keywords": ["peb", "masquerad", "fake name", "svchost"]
            },
            "UM_APC": {
                "mitre_id": "T1055.004", 
                "desc": "Process Injection: Asynchronous Procedure Call", 
                "keywords": ["apc", "user-mode hook"]
            },
            "C2_BEACON": {
                "mitre_id": "T1071", 
                "desc": "Application Layer Protocol (C2)", 
                "keywords": ["beacon", "outbound", "established", "103.45.0.0", "connection"]
            }
        }

    def map_anomalies(self, anomalies: list) -> list:
        """
        Scans raw anomaly text and maps it to official MITRE tactics.
        """
        mapped_results = []
        
        for anomaly in anomalies:
            anomaly_lower = anomaly.lower()
            matched = False
            
            for ioe, data in self.ioe_signatures.items():
                # Check if any signature keywords exist in the raw anomaly text
                if any(kw in anomaly_lower for kw in data["keywords"]):
                    mapping = {
                        "ioe_signature": ioe,
                        "mitre_id": data["mitre_id"],
                        "tactical_desc": data["desc"],
                        "raw_evidence": anomaly
                    }
                    mapped_results.append(mapping)
                    matched = True
                    break # Stop at first matching signature
            
            # Fallback for unrecognized anomalies
            if not matched:
                mapped_results.append({
                    "ioe_signature": "GENERIC_ANOMALY",
                    "mitre_id": "T1106", # Native API execution
                    "tactical_desc": "Suspicious execution without explicit signature match",
                    "raw_evidence": anomaly
                })
        
        print(f"\n[YOMI-MAPPER] [VOID BLACK] Tactical mapping complete. {len(mapped_results)} MITRE signatures identified.")
        self.audit.record_action("MITRE_MAPPER", "MAPPED", f"Mapped {len(mapped_results)} anomalies to MITRE framework.")
        
        return mapped_results

# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    mapper = MitreMapper()
    mock_anomalies = [
        "Rogue C2 connection to 103.45.0.0:80 detected on PID 4092 via Volatility.",
        "Unbacked memory VAD region execution found."
    ]
    results = mapper.map_anomalies(mock_anomalies)
    print(json.dumps(results, indent=4))