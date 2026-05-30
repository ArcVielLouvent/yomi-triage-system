import os
import json
import time
import threading

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Omni-Library (v2.0)
# Purpose: Localized Threat Intelligence & CVE Retrieval System.
#          Features a background daemon for continuous asynchronous scraping.
# ==============================================================================


class OmniLibrary:
    def __init__(self):
        self.data_dir = "/workspaces/yomi-triage-system/yomi_data"
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
        """Saves the in-memory database back to disk."""
        with self.database_lock:
            with open(self.db_file, "w") as f:
                json.dump(self.database, f, indent=4)

    def _scraping_worker(self):
        """
        Background daemon that periodically fetches new threat intelligence.
        Operates asynchronously without blocking the main triage execution.
        """
        # In a real environment, this would use requests.get() to pull from MITRE/NVD APIs.
        # For this prototype, we simulate the autonomous discovery of a zero-day threat.
        time.sleep(5)  # Delay before first background scrape

        while True:
            # Generate a simulated zero-day threat payload
            new_threat = {
                "cve_id": f"CVE-ZERO-DAY-{int(time.time())}",
                "target": "Unknown Autonomous Agent",
                "description": "Background scraping detected a newly published zero-day signature.",
                "indicators": ["dynamic_memory_hook", "shadow_net_evasion"],
                "remediation": "Engage Cryogenic Freeze immediately.",
            }

            with self.database_lock:
                # Only add if it's not bloating the DB during testing (keep it under 50 entries)
                if len(self.database) < 50:
                    self.database.append(new_threat)

            self._save_database()

            # Polling interval: Waits 15 seconds before scraping the internet again
            time.sleep(15)

    def _start_continuous_scraping(self):
        """Spins up the scraping daemon in a separate background thread."""
        scraper_thread = threading.Thread(target=self._scraping_worker, daemon=True)
        scraper_thread.start()

    def analyze_artifact(self, artifact_name: str, context_hints: list) -> dict:
        """
        Cross-references suspicious artifacts with the live threat database.
        Thread-safe read operation.
        """
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
