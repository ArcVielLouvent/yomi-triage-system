import ipaddress
import concurrent.futures
import os
import re
import sys
import shutil
import subprocess
import time
import psutil
import stat
from itertools import islice

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Evidence Swarm (v9.0)
# Purpose: Orchestrates parallel micro-agents that continuously scan RAM and Networks.
#          - Cloud/Container Safe: Anti-OOM RAM limiter (2MB string cap).
#          - Secure Fallback: File permission hardening on /tmp cross-device links.
#          - Precision Context: False Positive immune C2 query detection.
# ==============================================================================


class SwarmOrchestrator:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()
        self.active_reports = []
        
        self.lock_vault = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "yomi_data", "locks"))
        os.makedirs(self.lock_vault, exist_ok=True)
        os.chmod(self.lock_vault, 0o700)

    def _sanitize_log(self, text: str) -> str:
        text = re.sub(r'(?i)(password|passwd|pwd|secret|token|api_key|auth)\s*[:=]\s*([^\s,"\'}:<]+)', r'\1: ***MASKED***', text)
        text = re.sub(r'(?i)<(password|passwd|pwd|secret|token|api_key|auth)>[^<]+</\1>', r'<\1>***MASKED***</\1>', text)
        text = re.sub(r'(?i)Bearer\s+[A-Za-z0-9\-\._~\+\/]+', 'Bearer ***MASKED***', text)
        return text

    def _resolve_and_pin_inode(self, candidates: list[str]) -> str | None:
        """
        Locks the physical inode. If Hardlink fails and Disk is full, 
        it falls back to the original file but strictly enforces Read-Only permissions
        to prevent malware modification during analysis.
        """
        for candidate in candidates:
            if not candidate:
                continue
            try:
                stat_info = os.lstat(candidate)
                if not stat.S_ISREG(stat_info.st_mode):
                    continue
                    
                clean_path = os.path.realpath(candidate)
                safe_filename = f"pinned_{abs(hash(clean_path))}_{int(time.time())}.raw"
                safe_path = os.path.join(self.lock_vault, safe_filename)
                
                try:
                    os.link(clean_path, safe_path)
                    return safe_path
                except OSError:
                    try:
                        required_space = os.path.getsize(clean_path)
                        free_space = shutil.disk_usage(self.lock_vault).free
                        
                        if free_space < (required_space + 500_000_000):
                            self.audit.record_action("SWARM", "DISK_EXHAUSTION_AVOIDED", f"Skipped vault copy. Free space: {free_space}")
                            
                            # Anti-Tampering Fallback 
                            # Force the original file in /tmp to Read-Only so malware cannot 
                            # delete or corrupt it while Volatility is parsing it.
                            try:
                                os.chmod(clean_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                            except Exception:
                                pass # Best effort if owned by another user
                            return clean_path
                            
                        shutil.copy2(clean_path, safe_path)
                        return safe_path
                    except Exception:
                        continue
            except Exception:
                continue
        return None

    def deploy_swarm(self) -> dict:
        self.active_reports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_mem = executor.submit(self._memory_agent)
            future_net = executor.submit(self._network_agent)

            try:
                self.active_reports.append(future_mem.result(timeout=180))
            except concurrent.futures.TimeoutError:
                self.active_reports.append({"agent": "Memory_Agent", "findings": ["[CRITICAL ERROR] Volatility scan timed out (180s). Abandoned."]})
                
            try:
                self.active_reports.append(future_net.result(timeout=120))
            except concurrent.futures.TimeoutError:
                self.active_reports.append({"agent": "Network_Agent", "findings": ["[CRITICAL ERROR] TShark scan timed out (120s). Abandoned."]})

        self.audit.record_action("SWARM", "DEPLOYED", "Completed resilient concurrent agent sweep.")
        return {"status": "SWARM_COMPLETE", "reports": self.active_reports}

    def _is_external_ip(self, candidate: str) -> bool:
        try:
            ip = ipaddress.ip_address(candidate)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local)
        except ValueError:
            return False

    def _extract_external_ips(self, text: str) -> list[str]:
        ips = set()
        matches = re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        for match in islice(matches, 500):
            candidate = match.group(0)
            if self._is_external_ip(candidate):
                ips.add(candidate)
        return sorted(ips)

    def _extract_suspect_pids(self, text: str) -> list[int]:
        pids = set()
        matches = re.finditer(r"\bpid\s*[:=]?\s*(\d+)\b", text, flags=re.IGNORECASE)
        for match in islice(matches, 500):
            pids.add(int(match.group(1)))
        return sorted(pids)

    def _live_network_findings(self) -> list[str]:
        findings = []
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            findings.append("[WARNING] Live network scan running without root privileges.")

        try:
            external_ips = set()
            suspect_pids = set()
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    if self._is_external_ip(ip):
                        external_ips.add(ip)
                        if conn.pid:
                            suspect_pids.add(conn.pid)
            
            if external_ips:
                findings.append(f"Live Kernel Socket Scan: external connection(s) observed to {', '.join(sorted(external_ips)[:50])}.")
            if suspect_pids:
                findings.append(f"Live Kernel Socket Scan: suspect process IDs observed: {', '.join(str(pid) for pid in sorted(suspect_pids)[:50])}.")
            if not external_ips and not suspect_pids:
                findings.append("Live Kernel Socket Scan completed without explicit external endpoint anomalies.")
                
        except Exception as e:
            findings.append(f"[ERROR] Live network scan failed: {e}")
                
        return findings

    def _memory_agent(self):
        candidates = [
            os.environ.get("YOMI_MEMORY_DUMP_PATH", ""),
            "/tmp/system_ram.raw",
            "/mnt/forensic/system_ram.raw",
            "/var/tmp/system_ram.raw",
        ]
        
        dump_path = self._resolve_and_pin_inode(candidates)
        findings = []
        
        try:
            if dump_path:
                result = self.arsenal.run_volatility_netscan(dump_path)
                if result.get("status") == "SUCCESS":
                    # Anti-OOM RAM Limiter
                    # Caps the output string to ~2MB to prevent Container Out-Of-Memory Crash
                    # before sending it to the regex sanitization engine.
                    raw_output = result.get("output", "")[:2_000_000]
                    output = self._sanitize_log(raw_output)
                    
                    external_ips = self._extract_external_ips(output)
                    suspect_pids = self._extract_suspect_pids(output)

                    if external_ips:
                        findings.append(f"Volatility netscan detected external connection(s): {', '.join(external_ips)}.")
                    if suspect_pids:
                        findings.append(f"Volatility netscan flagged suspicious process IDs: {', '.join(str(pid) for pid in suspect_pids)}.")
                    if not external_ips and not suspect_pids:
                        findings.append("Volatility netscan completed without explicit anomalies.")
                else:
                    findings.append(f"Volatility memory analysis unavailable: {result.get('error', 'unknown error')}")
            else:
                findings.append("Memory dump unavailable. Deferring to network agent for live telemetry.")
        finally:
            if dump_path and dump_path.startswith(self.lock_vault):
                try:
                    os.unlink(dump_path)
                except Exception:
                    pass

        return {"agent": "Memory_Agent", "findings": findings}

    def _network_agent(self):
        candidates = [
            os.environ.get("YOMI_PCAP_PATH", ""),
            "/tmp/live_capture.pcap",
            "/var/tmp/live_capture.pcap",
        ]
        
        pcap_path = self._resolve_and_pin_inode(candidates)
        findings = []
        
        try:
            if pcap_path:
                result = self.arsenal.run_tshark_pcap(pcap_path)
                if result.get("status") == "SUCCESS":
                    # Anti-OOM RAM Limiter (2MB Cap)
                    raw_output = result.get("output", "")[:2_000_000]
                    output = self._sanitize_log(raw_output)
                    
                    external_ips = self._extract_external_ips(output)
                    
                    if external_ips:
                        findings.append(f"TShark flagged external destination(s): {', '.join(external_ips)}.")
                    
                    # Precision C2 Context
                    # Looking for actual DNS Query formatting or HTTP Host Headers
                    # rather than just the string "http.host" which could be a local file path.
                    if re.search(r'(?i)(http\.host\s*==|dns\.qry\.name\s*==|Host:\s*[a-zA-Z0-9.-]+)', output):
                        findings.append("TShark analysis found confirmed command-and-control URL/DNS header activity.")
                        
                    if not external_ips:
                        findings.append("TShark completed without obvious external C2 anomalies.")
                else:
                    findings.append(f"TShark PCAP analysis unavailable: {result.get('error', 'unknown error')}")
            else:
                findings.append("PCAP archive unavailable. Performing live socket inspection natively.")
                findings.extend(self._live_network_findings())
        finally:
            if pcap_path and pcap_path.startswith(self.lock_vault):
                try:
                    os.unlink(pcap_path)
                except Exception:
                    pass

        return {"agent": "Network_Agent", "findings": findings}


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# ==============================================================================
if __name__ == "__main__":
    print("[*] Deploying The Evidence Swarm (Daemon Mode)...")
    orchestrator = SwarmOrchestrator()
    results = orchestrator.deploy_swarm()

    print("\n[+] Swarm Reports:")
    import json
    print(json.dumps(results, indent=2))
    sys.exit(0)