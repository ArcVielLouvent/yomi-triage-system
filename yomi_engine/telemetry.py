import time
import json
import os

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Telemetry & Benchmarking
# Purpose: Measures end-to-end latency from threat detection to neutralization.
#          Proves the "10x Faster" SANS Find Evil requirement using hard metrics.
# ==============================================================================


class TelemetryEngine:
    def __init__(self):
        self.active_incidents = {}
        self.benchmark_log = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "yomi_data",
                "telemetry_benchmarks.jsonl",
            )
        )
        os.makedirs(os.path.dirname(self.benchmark_log), exist_ok=True)

    def start_timer(self, incident_id: str):
        """Marks the exact microsecond an anomaly is detected by the Swarm."""
        self.active_incidents[incident_id] = time.perf_counter()

    def stop_timer(self, incident_id: str, action_taken: str):
        """
        Marks the neutralization time and calculates total latency.
        Compares performance against known APT breakout times.
        """
        if incident_id not in self.active_incidents:
            return

        end_time = time.perf_counter()
        start_time = self.active_incidents.pop(incident_id)

        # Calculate response time in seconds
        latency = end_time - start_time

        # SANS Benchmarks for comparison
        human_soc_avg = 1200.0  # 20 minutes to triage
        horizon3_ai = 60.0  # 60 seconds breakout

        speed_multiplier = human_soc_avg / latency if latency > 0 else 0

        report = {
            "incident_id": incident_id,
            "action": action_taken,
            "latency_seconds": round(latency, 4),
            "human_speed_multiplier": f"{round(speed_multiplier, 1)}x Faster",
            "beat_horizon3_ai": latency < horizon3_ai,
        }

        self._log_benchmark(report)
        self._print_holographic_report(report)
        return report

    def _log_benchmark(self, report: dict):
        with open(self.benchmark_log, "a") as f:
            f.write(json.dumps(report) + "\n")

    def _print_holographic_report(self, report: dict):
        print("\n" + "=" * 60)
        print("[YOMI TELEMETRY BENCHMARK REPORT]")
        print("=" * 60)
        print(f"Incident ID      : {report['incident_id']}")
        print(f"Action Executed  : {report['action']}")
        print(f"Total Latency    : {report['latency_seconds']} seconds")
        print(
            f"SOC Comparison   : {report['human_speed_multiplier']} than Human Analyst"
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
    tel.start_timer("INCIDENT_XZ_4092")

    # Simulate processing time (e.g., LLM thinking, OS Bridge freezing)
    time.sleep(0.35)

    tel.stop_timer("INCIDENT_XZ_4092", "Cryogenic Freeze (SIGSTOP)")
