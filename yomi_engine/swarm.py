import ipaddress
import multiprocessing
import os
import re
import sys
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

        self.active_reports = []

    def deploy_swarm(self) -> dict:
        self.active_reports = []
        manager = multiprocessing.Manager()
        shared_reports = manager.list()
        processes = []

        for agent_name in ["memory", "network"]:
            p = multiprocessing.Process(
                target=self._agent_process,
                args=(agent_name, shared_reports),
            )
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        self.active_reports = list(shared_reports)
        self.audit.record_action(
            "SWARM", "DEPLOYED", "Completed concurrent forensic micro-agent sweep."
        )
        return {"status": "SWARM_COMPLETE", "reports": self.active_reports}

    def _agent_process(self, agent_name: str, shared_reports) -> None:
        if agent_name == "memory":
            result = self._memory_agent()
        else:
            result = self._network_agent()

        shared_reports.append(result)

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

    def _is_external_ip(self, candidate: str) -> bool:
        try:
            ip = ipaddress.ip_address(candidate)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_link_local
            )
        except ValueError:
            return False

    def _extract_external_ips(self, text: str) -> list[str]:
        ips = set()
        for match in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text):
            candidate = match.group(0)
            if self._is_external_ip(candidate):
                ips.add(candidate)
        return sorted(ips)

    def _extract_suspect_pids(self, text: str) -> list[int]:
        pids = set()
        for match in re.finditer(r"\bPID\s*[:=]?\s*(\d+)\b", text, flags=re.IGNORECASE):
            pids.add(int(match.group(1)))
        for match in re.finditer(r"\b(\d{3,5})\b", text):
            value = int(match.group(1))
            if value > 1000 and value < 65535:
                pids.add(value)
        return sorted(pids)

    def _live_network_findings(self) -> list[str]:
        findings = []
        if shutil.which("ss"):
            proc = subprocess.run(
                ["ss", "-tunap"], capture_output=True, text=True, timeout=15
            )
            output = proc.stdout or ""
            external_ips = self._extract_external_ips(output)
            suspect_pids = self._extract_suspect_pids(output)
            if external_ips:
                findings.append(
                    f"Live network scan: external connection(s) observed to {', '.join(external_ips)}."
                )
            if suspect_pids:
                findings.append(
                    f"Live network scan: suspect process IDs observed: {', '.join(str(pid) for pid in suspect_pids)}."
                )
            if "ESTAB" in output and not any(addr in output for addr in ["127.0.0.1", "::1"]):
                findings.append("Live network scan: established remote connections detected.")
        return findings

    def _memory_agent(self):
        dump_path = self._resolve_memory_dump()
        findings = []
        if dump_path:
            result = self.arsenal.run_volatility_netscan(dump_path)
            if result.get("status") == "SUCCESS":
                output = result.get("output", "")
                external_ips = self._extract_external_ips(output)
                suspect_pids = self._extract_suspect_pids(output)

                if external_ips:
                    findings.append(
                        f"Volatility netscan detected external connection(s): {', '.join(external_ips)}."
                    )
                if suspect_pids:
                    findings.append(
                        f"Volatility netscan flagged suspicious process IDs: {', '.join(str(pid) for pid in suspect_pids)}."
                    )
                if not external_ips and not suspect_pids:
                    findings.append(
                        "Volatility netscan completed without explicit external endpoint or PID anomalies."
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

        return {"agent": "Memory_Agent", "findings": findings}

    def _network_agent(self):
        pcap_path = self._resolve_pcap_capture()
        findings = []
        if pcap_path:
            result = self.arsenal.run_tshark_pcap(pcap_path)
            if result.get("status") == "SUCCESS":
                output = result.get("output", "")
                external_ips = self._extract_external_ips(output)
                suspect_pids = self._extract_suspect_pids(output)

                if external_ips:
                    findings.append(
                        f"TShark flagged external destination(s): {', '.join(external_ips)}."
                    )
                if suspect_pids:
                    findings.append(
                        f"TShark found suspicious PID references: {', '.join(str(pid) for pid in suspect_pids)}."
                    )
                if "http.host" in output or "dns.qry.name" in output:
                    findings.append(
                        "TShark analysis found potential command-and-control URL/DNS activity."
                    )
                if not external_ips and not suspect_pids:
                    findings.append(
                        "TShark completed without obvious external C2 or PID anomalies."
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

        return {"agent": "Network_Agent", "findings": findings}


if __name__ == "__main__":
    print("\n[+] Deploying The Evidence Swarm...")
    orchestrator = SwarmOrchestrator()
    results = orchestrator.deploy_swarm()

    print("\n[+] Swarm Reports:")
    print(results)
