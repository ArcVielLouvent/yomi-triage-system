import os
import json
import time
import threading
import requests

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Omni-Library (v2.0)
# Purpose: Localized Threat Intelligence & CVE Retrieval System.
#          Features a background daemon for continuous asynchronous scraping.
# ==============================================================================


class OmniLibrary:
    def __init__(self):
        self.data_dir = "/workspaces/yomi-triage-system/yomi_data"
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_file = os.path.join(self.data_dir, "cve_database.json")

        # Thread Lock ensures data integrity if AI and Daemon access DB simultaneously
        self.database_lock = threading.Lock()
        self.database = []

        self._load_database()
        self._start_continuous_scraping()

    def _load_database(self):
        """Loads the CVE database from disk safely into memory."""
        with self.database_lock:
            if os.path.exists(self.db_file):
                try:
                    with open(self.db_file, "r") as f:
                        self.database = json.load(f)
                except json.JSONDecodeError:
                    self.database = []

    def _save_database(self):
        """Saves the in-memory database back to disk using Atomic Write."""
        with self.database_lock:
            temp_file = self.db_file + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(self.database, f, indent=4)
            # PATCH: Atomic replace guarantees the JSON is never corrupted on sudden exit
            os.replace(temp_file, self.db_file)

    def _scraping_worker(self):
        """
        Continuous Scraping Daemon.
        Silently polls NVD/GitHub threat feeds every 1 hour in the background.
        """
        print("[YOMI-LIBRARY] [VOID BLACK] Continuous Scraping Daemon armed. Polling for global zero-days...")
        
        while True:
            try:
                # Simulated connection to National Vulnerability Database (NVD) or CIRCL API
                # In production, this uses valid API keys and rate limits
                response = requests.get("https://cve.circl.lu/api/last", timeout=10)
                
                if response.status_code == 200:
                    cves = response.json()[:5] # Take latest 5 threats
                    
                    with self.database_lock:
                        for item in cves:
                            new_entry = {
                                "target": item.get('id', 'Unknown_CVE'),
                                "description": item.get('summary', 'No description'),
                                "indicators": [item.get('cvss', 'No CVSS')]
                            }
                            # Only add if it doesn't already exist
                            if not any(db_item.get('target') == new_entry['target'] for db_item in self.database):
                                self.database.append(new_entry)
                        
                        self._save_database()
                    print(f"\n[YOMI-LIBRARY] [CYBER-PURPLE] Omni-Library Updated. Absorbed {len(cves)} new global threats.")
            except Exception as e:
                # Fail silently to prevent disrupting the main Triage engine
                pass
            
            # Sleep for 1 hour before scraping again
            time.sleep(3600)

    def _start_continuous_scraping(self):
        """Spins up the scraping daemon in a separate background thread."""
        scraper_thread = threading.Thread(target=self._scraping_worker, daemon=True)
        scraper_thread.start()

    def analyze_artifact(self, artifact_name: str, context_hints: list) -> dict:
        """
        Cross-references suspicious artifacts with the live threat database.
        Thread-safe read operation.
        """
        if not isinstance(artifact_name, str) or not artifact_name:
            return {
                "status": "ERROR",
                "analysis": "Invalid artifact name supplied.",
                "matches": [],
            }

        if context_hints is None:
            context_hints = []
        if not isinstance(context_hints, list):
            return {
                "status": "ERROR",
                "analysis": "Context hints must be a list of strings.",
                "matches": [],
            }

        context_hints = [str(h) for h in context_hints]
        matches = []
        search_terms = [artifact_name.lower()] + [h.lower() for h in context_hints]

        with self.database_lock:
            for entry in self.database:
                combined_text = f"{entry.get('target', '')} {entry.get('description', '')} {' '.join(entry.get('indicators', []))}".lower()

                if any(term in combined_text for term in search_terms):
                    matches.append(entry)

        if matches:
            return {
                "status": "THREAT_FOUND",
                "matches": matches[
                    :3
                ],  # Return top 3 matches to prevent LLM context overload
                "analysis": f"Found {len(matches)} potential vulnerabilities related to the artifact.",
            }

        return {
            "status": "CLEAN_OR_UNKNOWN",
            "analysis": "No immediate threats found in the Omni-Library for this artifact.",
        }
