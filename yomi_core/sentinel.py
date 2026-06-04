import time
import json
import os
import sys
import re
import threading
import traceback
import psutil

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_engine.swarm import SwarmOrchestrator
from yomi_engine.hunter import OmniVectorHunter
from yomi_core.router import YomiRouter
from yomi_engine.telemetry import TelemetryEngine
from yomi_engine.mitre_mapper import MitreMapper

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - Infinite Sentinel Loop (v4.0)
# Purpose: Event-driven sentinel with adaptive polling, real host telemetry,
#          and direct integration into the AI triage pipeline.
# ============================================================================== 


class SentinelDaemon:
    def __init__(self):
        self.swarm = SwarmOrchestrator()
        self.hunter = OmniVectorHunter()
        self.router = YomiRouter()
        self.telemetry = TelemetryEngine()

        self.threat_level = "SAFE"  # SAFE, ESCALATED, CRITICAL
        self.is_running = False
        self._lock = threading.Lock()
        self._wake_event = threading.Event()
        self._cycle_count = 0

    def _get_polling_interval(self) -> float:
        if self.threat_level == "SAFE":
            return 5.0
        if self.threat_level == "ESCALATED":
            return 1.0
        return 0.2

    def _load_average(self) -> float:
        try:
            return os.getloadavg()[0]
        except Exception:
            return 0.0

    def _free_memory_percent(self) -> float:
        try:
            return psutil.virtual_memory().available / psutil.virtual_memory().total * 100.0
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return 0.0

    def _score_threat(self, anomalies: list, host_metrics: dict) -> str:
        if anomalies:
            if any("c2" in a.lower() or "ransom" in a.lower() or "credential" in a.lower() for a in anomalies):
                return "CRITICAL"
            return "ESCALATED"

        if host_metrics["load"] > 3.0 or host_metrics["free_memory_pct"] < 20.0:
            return "ESCALATED"

        return "SAFE"

    def _extract_pid_from_anomaly(self, anomalies: list) -> int:
        for anomaly in anomalies:
            match = re.search(r"PID\s+(\d+)", anomaly, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return 0

    def _build_forensic_context(self, target_pid: int, anomaly_data: list, hunt_result: dict, mapped_tactics: list) -> str:
        return json.dumps(
            {
                "incident_type": "autonomous_dfir",
                "target_pid": target_pid,
                "anomaly_evidence": anomaly_data,
                "mitre_mapping": mapped_tactics,
                "root_cause_trace": hunt_result,
            },
            indent=2,
        )

    def _zero_prompt_trigger(self, anomaly_data: list):
        print("\n[SENTINEL] [CYBER-PURPLE] Anomaly verified! Engaging Zero-Prompt Engine...")

        target_pid = self._extract_pid_from_anomaly(anomaly_data)
        incident_id = f"INCIDENT_PID_{target_pid}_{int(time.time())}"

        self.telemetry.start_timer(incident_id)

        # ==============================================================================
        # [CRITICAL FIX] "SHOOT FIRST, ASK AI LATER" (Deterministic Containment)
        # Mem-bypass LLM sepenuhnya jika ancaman bersifat CRITICAL.
        # ==============================================================================
        instant_freeze_applied = False
        if self.threat_level == "CRITICAL" and target_pid > 0:
            print(f"[SENTINEL] [BLOOD RED] CRITICAL THREAT DETECTED. Executing immediate SIGSTOP on PID {target_pid}...")
            try:
                import signal
                os.kill(target_pid, signal.SIGSTOP)
                instant_freeze_applied = True
                print(f"[SENTINEL] [PLASMA BLUE] Time-to-Containment (TTC) achieved. Target frozen. Handing over to AI for deep triage.")
                
                self.telemetry.stop_timer(incident_id, "INSTANT_DETERMINISTIC_FREEZE")
            except OSError as e:
                print(f"[SENTINEL] [ERROR] Instant kernel freeze failed: {e}")

        # ==============================================================================
        # FASE 2: DEEP HUNT & AI POST-MORTEM (Non-Time-Critical)
        # ==============================================================================
        hunt_result = {"status": "SKIPPED", "conclusion": "No target PID available."}
        if target_pid > 0:
            hunt_result = self.hunter.hunt_root_cause(target_pid)

        mapper = MitreMapper()
        mapped_tactics = mapper.map_anomalies(anomaly_data)

        if instant_freeze_applied:
            anomaly_data.append("SYSTEM NOTE: The target PID has already been cryogenically frozen (SIGSTOP) by the OS kernel for safety. Focus strictly on forensic profiling.")

        forensic_context = self._build_forensic_context(target_pid, anomaly_data, hunt_result, mapped_tactics)

        print("[SENTINEL] Routing tactical MITRE context to OpenClaw LLM Gateway for Post-Mortem Analysis...")
        triage_result = self.router.execute_autonomous_triage(forensic_context)

        if not instant_freeze_applied:
            executed_action = triage_result.get("status", "UNKNOWN_ACTION")
            self.telemetry.stop_timer(incident_id, executed_action)

    def _collect_host_metrics(self) -> dict:
        return {
            "load": self._load_average(),
            "free_memory_pct": self._free_memory_percent(),
            "timestamp": time.time(),
        }

    def start(self):
        self.is_running = True
        print("\n[SENTINEL] [PLASMA BLUE] Infinite Sentinel Loop initialized. Monitoring system state...")
        print("[SENTINEL] Press Ctrl+C to abort daemon.\n")

        try:
            while self.is_running:
                self._cycle_count += 1
                host_metrics = self._collect_host_metrics()
                print(f"[SENTINEL] Cycle {self._cycle_count}: load={host_metrics['load']:.2f}, free_mem={host_metrics['free_memory_pct']:.1f}%")

                try:
                    swarm_results = self.swarm.deploy_swarm()
                    anomalies = []
                    for report in swarm_results.get("reports", []):
                        findings = report.get("findings", [])
                        if findings:
                            anomalies.extend(findings)

                    new_threat_level = self._score_threat(anomalies, host_metrics)
                    if new_threat_level != self.threat_level:
                        print(f"[SENTINEL] Threat state changed from {self.threat_level} to {new_threat_level}.")
                    self.threat_level = new_threat_level

                    if anomalies:
                        if self.threat_level == "CRITICAL":
                            print("[SENTINEL] [BLOOD RED] Critical threat posture engaged.")
                        self._zero_prompt_trigger(anomalies)
                    elif self.threat_level == "SAFE":
                        print("[SENTINEL] [PLASMA BLUE] No anomalies detected. Maintaining baseline patrol.")

                except Exception as exc:
                    print("\n[SENTINEL] [VOID BLACK] Internal Loop Error Recovered:")
                    traceback.print_exc()

                interval = self._get_polling_interval()
                print(f"[SENTINEL] Sleeping for {interval:.2f} seconds before next scan.\n")
                if self._wake_event.wait(timeout=interval):
                    self._wake_event.clear()

        except KeyboardInterrupt:
            print("\n[SENTINEL] [VOID BLACK] Sentinel Loop manually terminated by Commander.")
            self.is_running = False


if __name__ == "__main__":
    sentinel = SentinelDaemon()
    sentinel.start()
