import time
import json
import os
import threading
import sys

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Telemetry & Benchmarking (v3.0)
# Purpose: Measures end-to-end latency from threat detection to neutralization.
#          - O(1) Memory Eviction: Zero RAM bloating during massive attacks.
#          - Realistic Math Bounds: Prevents astronomical speed multipliers.
#          - Dedicated I/O Locks: Prevents stdout/ledger corruption in multithreading.
# ==============================================================================


class TelemetryEngine:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.active_incidents = {}

        # Dual-Lock Architecture
        self._dict_lock = threading.Lock()  # Protects RAM state
        self._io_lock = threading.Lock()  # Protects Terminal & Ledger output

        # Max capacity to prevent Memory Leaks from abandoned/hanging timers
        self.MAX_TRACKED_INCIDENTS = 5000

    def start_timer(self, incident_id: str):
        """Marks the exact microsecond an anomaly is detected."""
        with self._dict_lock:
            # O(1) OOM Protection: Safely pop the oldest keys without copying the whole dictionary
            if len(self.active_incidents) >= self.MAX_TRACKED_INCIDENTS:
                for _ in range(100):
                    try:
                        oldest_key = next(iter(self.active_incidents))
                        del self.active_incidents[oldest_key]
                    except StopIteration:
                        break

            # time.perf_counter is immune to OS clock manipulation (NTP changes)
            self.active_incidents[incident_id] = time.perf_counter()

    def stop_timer(self, incident_id: str, action_taken: str):
        """
        Marks neutralization time, calculates latency, and writes a
        cryptographically signed benchmark log to the central ledger.
        """
        with self._dict_lock:
            if incident_id not in self.active_incidents:
                return None
            start_time = self.active_incidents.pop(incident_id)

        end_time = time.perf_counter()
        latency = end_time - start_time

        # SANS Benchmarks for comparison
        human_soc_avg = 1200.0  # 20 minutes to triage
        horizon3_ai = 60.0  # 60 seconds breakout

        # Mathematical Bound for Speed Multiplier
        # Prevents astronomically high multipliers (e.g., 120,000,000x) if latency is sub-millisecond
        math_latency = max(latency, 0.001)
        speed_multiplier = human_soc_avg / math_latency

        report = {
            "incident_id": incident_id,
            "action": action_taken,
            "latency_seconds": round(latency, 4),
            "human_speed_multiplier": f"{round(speed_multiplier, 1)}x",
            "beat_horizon3_ai": latency < horizon3_ai,
        }

        # Thread-Safe I/O Execution
        with self._io_lock:
            self._log_benchmark(report)
            self._print_holographic_report(report)

        return report

    def _log_benchmark(self, report: dict):
        """
        Cryptographically signed metrics integrated into the ImmutableStamp ledger.
        """
        msg = f"Latency Benchmark: {report['latency_seconds']}s | Speed: {report['human_speed_multiplier']} Faster"
        self.audit.record_action(
            "TELEMETRY", "BENCHMARK_RECORDED", msg, metadata=report
        )

    def _print_holographic_report(self, report: dict):
        print("\n" + "=" * 60)
        print("[YOMI TELEMETRY BENCHMARK REPORT]")
        print("=" * 60)
        print(f"Incident ID      : {report['incident_id']}")
        print(f"Action Executed  : {report['action']}")
        print(f"Total Latency    : {report['latency_seconds']} seconds")
        print(
            f"SOC Comparison   : {report['human_speed_multiplier']} Faster than Human Analyst"
        )

        if report["beat_horizon3_ai"]:
            print("[✓] TACTICAL WIN : Defeated Horizon3 AI 60-second breakout time.")
        else:
            print("[!] TACTICAL LOSS: Failed to beat AI adversary breakout time.")
        print("=" * 60 + "\n")


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    tel = TelemetryEngine()
    print("[+] Simulating Threat Detection...")
    incident_id = os.environ.get("YOMI_INCIDENT_ID", "INCIDENT_XZ_1337")

    tel.start_timer(incident_id)

    # Simulate processing time (e.g., eBPF hook, MindReader profiling)
    time.sleep(0.35)

    tel.stop_timer(incident_id, "Cryogenic Freeze & Sandbox Containment")
