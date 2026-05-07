import os
import json

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Omni-Library
# Purpose: Localized Threat Intelligence & CVE Retrieval System (RAG Backend).
# ==============================================================================

class OmniLibrary:
    def __init__(self):
        self.data_dir = "/workspaces/yomi-triage-system/yomi_data"
        self.db_file = os.path.join(self.data_dir, "cve_database.json")
        self._initialize_database()

    def _initialize_database(self):
        """Creates a high-speed local vulnerability database if it doesn't exist."""
        if not os.path.exists(self.db_file):
            # Pre-loading with critical SANS-level vulnerabilities for Hackathon Demo
            initial_data = [
                {
                    "cve_id": "CVE-2024-3094",
                    "target": "xz-utils",
                    "description": "Malicious backdoor introduced in xz compression library allowing unauthenticated remote code execution.",
                    "indicators": ["liblzma", "sshd high CPU", "hidden sshd process"],
                    "remediation": "Downgrade xz-utils to 5.4.6 or earlier. Kill malicious sshd spawned processes."
                },
                {
                    "cve_id": "CVE-2023-46805",
                    "target": "Ivanti VPN",
                    "description": "Authentication bypass vulnerability in the web component of Ivanti ICS allowing remote attackers to access restricted resources.",
                    "indicators": ["curl requests to /api/v1/totp", "unrecognized python scripts in /tmp"],
                    "remediation": "Apply vendor mitigation XML and factory reset if compromised."
                },
                {
                    "cve_id": "MAL-RANSOM-01",
                    "target": "Windows File System",
                    "description": "Generic behavior for ransomware encrypting user directories.",
                    "indicators": ["vssadmin.exe Delete Shadows", "high disk I/O on personal folders", ".enc file extensions"],
                    "remediation": "Isolate host from network immediately. Terminate encrypting PID."
                }
            ]
            with open(self.db_file, 'w') as f:
                json.dump(initial_data, f, indent=4)
            print("[YOMI-LIBRARY] Initialized Local Threat Database.")

    def analyze_artifact(self, artifact_name, context_hints=[]):
        """
        Simulates a RAG retrieval process by cross-referencing artifacts
        with known threat indicators.
        """
        with open(self.db_file, 'r') as f:
            database = json.load(f)

        matches = []
        search_terms = [artifact_name.lower()] + [h.lower() for h in context_hints]

        for entry in database:
            # Check if any search term matches the target, description, or indicators
            combined_text = f"{entry['target']} {entry['description']} {' '.join(entry['indicators'])}".lower()
            
            if any(term in combined_text for term in search_terms):
                matches.append(entry)

        if matches:
            return {
                "status": "THREAT_FOUND",
                "matches": matches,
                "analysis": f"Found {len(matches)} potential vulnerabilities related to the artifact."
            }
        else:
            return {
                "status": "CLEAN_OR_UNKNOWN",
                "analysis": "No immediate threats found in the Omni-Library for this artifact."
            }

# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    library = OmniLibrary()
    print("\n[Testing Omni-Library Retrieval]")
    
    # Simulate the AI asking about 'xz-utils'
    result = library.analyze_artifact("xz-utils", ["liblzma"])
    print(json.dumps(result, indent=2))