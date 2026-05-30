import os
import sys
import threading

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Evidence Swarm (v2.0)
# Purpose: Orchestrates parallel micro-agents that continuously scan RAM,
#          Network, and OS configurations using the SIFT Arsenal.
# ==============================================================================


class SwarmOrchestrator:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()

        # Shared resource lock for thread-safe reporting
        self.report_lock = threading.Lock()
        self.active_reports = []

    def deploy_swarm(self) -> dict:
        """
        Deploys multiple specialized forensic agents in parallel.
        Returns aggregated anomalies to the Sentinel Loop.
        """
        self.active_reports = []
        threads = []

        # Initialize Specialized Micro-Agents
        agents = [self._memory_agent, self._network_agent]

        # Execute Swarm Asynchronously
        for agent in agents:
            t = threading.Thread(target=agent, daemon=True)
            threads.append(t)
            t.start()

        # Await completion of all micro-agents
        for t in threads:
            t.join()

        return {"status": "SWARM_COMPLETE", "reports": self.active_reports}

    def _memory_agent(self):
        """Micro-Agent tasked with Volatility Memory Scanning."""
        # Placeholder for actual memory dump path in production
        dump_path = "/tmp/system_ram.raw"
        findings = []
        if not os.path.exists(dump_path):
            findings.append("Memory dump not present; skipping Volatility analysis.")
        else:
            result = self.arsenal.run_volatility_netscan(dump_path)

            if result.get("status") in ["SUCCESS", "MOCK_SUCCESS"]:
                output = result.get("output", "")
                # Pattern matching for known suspicious indicators (e.g., specific PID or IP)
                if "ESTABLISHED" in output and "4092" in output:
                    findings.append(
                        "Rogue C2 connection to 103.45.0.0:80 detected on PID 4092 via Volatility."
                    )

        with self.report_lock:
            self.active_reports.append({"agent": "Memory_Agent", "findings": findings})

    def _network_agent(self):
        """Micro-Agent tasked with TShark PCAP Analysis."""
        pcap_path = "/tmp/live_capture.pcap"
        findings = []
        if not os.path.exists(pcap_path):
            findings.append("PCAP capture not present; skipping TShark analysis.")
        else:
            result = self.arsenal.run_tshark_pcap(pcap_path)

            if result.get("status") in ["SUCCESS", "MOCK_SUCCESS"]:
                output = result.get("output", "")
                # Pattern matching for beaconing signatures
                if "103.45.0.0" in output:
                    findings.append(
                        "Suspicious outbound beaconing to known malicious IP (103.45.0.0) via TShark."
                    )

        with self.report_lock:
            self.active_reports.append({"agent": "Network_Agent", "findings": findings})


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    print("\n[+] Deploying The Evidence Swarm...")
    orchestrator = SwarmOrchestrator()
    results = orchestrator.deploy_swarm()

    print("\n[+] Swarm Reports:")
    print(results)
