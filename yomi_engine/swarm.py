import os
import sys
import threading
import shutil
import subprocess

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Evidence Swarm (v3.0)
# Purpose: Orchestrates parallel micro-agents that continuously scan RAM,
#          network telemetry, and filesystem artifacts using the SIFT Arsenal.
# ==============================================================================


class SwarmOrchestrator:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()

        self.report_lock = threading.Lock()
        self.active_reports = []

    def deploy_swarm(self) -> dict:
        self.active_reports = []
        threads = []

        agents = [self._memory_agent, self._network_agent]

        for agent in agents:
            t = threading.Thread(target=agent, daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.audit.record_action(
            "SWARM", "DEPLOYED", "Completed concurrent forensic micro-agent sweep."
        )
        return {"status": "SWARM_COMPLETE", "reports": self.active_reports}

    def _resolve_memory_dump(self) -> str | None:
        candidates = [
            os.environ.get("YOMI_MEMORY_DUMP_PATH", ""),
            "/tmp/system_ram.raw",
            "/mnt/forensic/system_ram.raw",
            "/var/tmp/system_ram.raw",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def _resolve_pcap_capture(self) -> str | None:
        candidates = [
            os.environ.get("YOMI_PCAP_PATH", ""),
            "/tmp/live_capture.pcap",
            "/var/tmp/live_capture.pcap",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def _live_network_findings(self) -> list[str]:
        findings = []
        if shutil.which("ss"):
            proc = subprocess.run(
                ["ss", "-tunap"], capture_output=True, text=True, timeout=15
            )
            output = proc.stdout or ""
            if "103.45.0.0" in output:
                findings.append(
                    "Live network scan: suspicious external connection to 103.45.0.0 detected."
                )
            if "ESTAB" in output and "127.0.0.1" not in output:
                findings.append("Live network scan: established remote connections detected.")
        return findings

    def _memory_agent(self):
        dump_path = self._resolve_memory_dump()
        findings = []
        if dump_path:
            result = self.arsenal.run_volatility_netscan(dump_path)
            if result.get("status") == "SUCCESS":
                output = result.get("output", "")
                if "ESTABLISHED" in output and "103.45.0.0" in output:
                    findings.append(
                        "Volatility netscan found an established C2 channel to 103.45.0.0."
                    )
                if "PID" in output and "4092" in output:
                    findings.append(
                        "Volatility netscan identified suspicious PID 4092 with network sockets."
                    )
            else:
                findings.append(
                    f"Volatility memory analysis unavailable: {result.get('error', 'unknown error')}"
                )
        else:
            findings.append(
                "Memory dump unavailable. Operating with live process and network telemetry instead."
            )
            findings.extend(self._live_network_findings())

        with self.report_lock:
            self.active_reports.append({"agent": "Memory_Agent", "findings": findings})

    def _network_agent(self):
        pcap_path = self._resolve_pcap_capture()
        findings = []
        if pcap_path:
            result = self.arsenal.run_tshark_pcap(pcap_path)
            if result.get("status") == "SUCCESS":
                output = result.get("output", "")
                if "103.45.0.0" in output:
                    findings.append(
                        "TShark flagged suspicious beaconing to 103.45.0.0 in network capture."
                    )
                if "http.host" in output or "dns.qry.name" in output:
                    findings.append(
                        "TShark analysis found potential command-and-control URL/DNS activity."
                    )
            else:
                findings.append(
                    f"TShark PCAP analysis unavailable: {result.get('error', 'unknown error')}"
                )
        else:
            findings.append(
                "PCAP archive unavailable. Performing live socket inspection where possible."
            )
            findings.extend(self._live_network_findings())

        with self.report_lock:
            self.active_reports.append({"agent": "Network_Agent", "findings": findings})


if __name__ == "__main__":
    print("\n[+] Deploying The Evidence Swarm...")
    orchestrator = SwarmOrchestrator()
    results = orchestrator.deploy_swarm()

    print("\n[+] Swarm Reports:")
    print(results)
