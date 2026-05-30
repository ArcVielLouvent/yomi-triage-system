import time
import json
import os
import sys
import re

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_engine.swarm import SwarmOrchestrator
from yomi_engine.hunter import OmniVectorHunter
from yomi_core.router import YomiRouter, OpenClawGateway
from yomi_engine.telemetry import TelemetryEngine

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - Infinite Sentinel Loop (v3.0)
# Purpose: Adaptive polling daemon. Operates at extreme efficiency during
#          peacetime, escalates to hyper-scan upon threat detection.
#          Acts as the Event-Driven trigger for the Zero-Prompt AI Engine.
# ==============================================================================


class SentinelDaemon:
    def __init__(self):
        # Initialize the interconnected triage engines
        self.swarm = SwarmOrchestrator()
        self.hunter = OmniVectorHunter()
        self.router = YomiRouter()
        self.telemetry = TelemetryEngine()

        self.threat_level = "SAFE"  # Operational States: SAFE, ESCALATED, CRITICAL
        self.is_running = False

    def _get_polling_interval(self) -> float:
        """
        Calculates the adaptive polling rate based on current threat conditions.
        Ensures <1% CPU utilization during SAFE state.
        """
        if self.threat_level == "SAFE":
            return 5.0  # Standard Patrol: 5 seconds
        elif self.threat_level == "ESCALATED":
            return 1.0  # Heightened Awareness: 1 second
        else:
            return 0.1  # CRITICAL: Hyper-Scan mode (100ms)

    def _extract_pid_from_anomaly(self, anomalies: list) -> int:
        """Dynamically extracts the target PID from Swarm text reports."""
        for anomaly in anomalies:
            match = re.search(r"PID\s+(\d+)", anomaly, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return 0  # Fallback if no PID is explicitly stated

    def _zero_prompt_trigger(self, anomaly_data: list):
        """
        The Zero-Prompt Engine: Assembles forensic context autonomously without
        human keyboard input and cascades it through the OpenClaw AI Gateway.
        """
        print(
            "\n[SENTINEL] [CYBER-PURPLE] Anomaly verified! Engaging Zero-Prompt Engine..."
        )

        # 1. Extract Target PID
        target_pid = self._extract_pid_from_anomaly(anomaly_data)
        incident_id = f"INCIDENT_PID_{target_pid}_{int(time.time())}"
        self.telemetry.start_timer(incident_id)
        # 2. Deploy Root-Cause Hunter if a PID was identified
        hunter_context = "No specific PID identified for root-cause hunting."
        if target_pid > 0:
            hunt_result = self.hunter.hunt_root_cause(target_pid)
            hunter_context = hunt_result.get("conclusion", "Root cause unknown.")

        # 3. Assemble the raw Forensic Context string for the LLM
        forensic_context = f"""
        [AUTONOMOUS DFIR REPORT]
        Anomalies Detected: {json.dumps(anomaly_data)}
        Root-Cause Context: {hunter_context}
        Target PID: {target_pid}
        """

        # 4. Route context through the Circuit Breaker (OpenClaw)
        print("[SENTINEL] Routing forensic context to OpenClaw LLM Gateway...")
        
        triage_result = self.router.execute_autonomous_triage(forensic_context)
        
        executed_action = triage_result.get("status", "UNKNOWN_ACTION")
        self.router.execute_autonomous_triage(forensic_context)

    def start(self):
        """
        Initializes the infinite background loop.
        This is the primary heartbeat of the Yomi Triage System.
        """
        self.is_running = True
        print(
            "\n[SENTINEL] [PLASMA BLUE] Infinite Sentinel Loop initialized. Monitoring system state..."
        )
        print("[SENTINEL] Press Ctrl+C to abort daemon.\n")

        try:
            while self.is_running:
                try:
                    # 1. Deploy the Predator Swarm (Micro-Agents)
                    swarm_results = self.swarm.deploy_swarm()
                    anomalies = []

                    for report in swarm_results.get("reports", []):
                        findings = report.get("findings", [])
                        if findings:
                            anomalies.extend(findings)

                    # 2. Adaptive Polling Logic & Threat Escalation
                    if anomalies:
                        if self.threat_level == "SAFE":
                            print(
                                "\n[SENTINEL] [BLOOD RED] Threat detected by Swarm! Escalating to CRITICAL mode."
                            )
                            self.threat_level = "CRITICAL"

                        # Trigger the full AI analysis pipeline
                        self._zero_prompt_trigger(anomalies)

                        # Reset to escalated mode to monitor for immediate aftershocks
                        self.threat_level = "ESCALATED"
                    else:
                        if self.threat_level != "SAFE":
                            print(
                                "\n[SENTINEL] [PLASMA BLUE] System clear. Returning to SAFE mode baseline."
                            )
                        self.threat_level = "SAFE"

                    # 3. Dynamic Sleep (Resource Management)
                    time.sleep(self._get_polling_interval())

                except Exception as e:
                    print(
                        f"\n[SENTINEL] [VOID BLACK] Internal Loop Error Recovered: {str(e)}"
                    )
                    time.sleep(5)

        except KeyboardInterrupt:
            print(
                "\n[SENTINEL] [VOID BLACK] Sentinel Loop manually terminated by Commander."
            )
            self.is_running = False


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    sentinel = SentinelDaemon()
    sentinel.start()
