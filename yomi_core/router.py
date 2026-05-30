import sys
import json
import requests # type: ignore
import os
import time

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.harness import YomiHarness

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Ouroboros Router v2.0
# Purpose: Triad Council Gatekeeper, Epistemic Uncertainty Engine, and
#          MCP Vault Routing. Ensures strict JSON intent compliance.
# ==============================================================================

class OpenClawGateway:
    """
    The Circuit Breaker: Implements the Gemini Cascade Strategy.
    Primary: Gemini 2.5 Pro -> Flash -> Local LLM (Ollama/Llama-cpp)
    """
    def __init__(self):
        self.models_cascade = [
            "gemini-2.5-pro",
            "gemini-2.5-flash", 
            "gemini-1.5-pro",
            "local-ollama-llama3"
        ]
        
    def generate_intent(self, forensic_context: str) -> str:
        """
        Attempts to generate JSON intent by cascading through available LLMs.
        """
        print(f"[OPENCLAW] Forensic context: {forensic_context}")
        for model in self.models_cascade:
            print(f"[OPENCLAW] Attempting neural link via {model}...")
            try:
                # [!] PLACEHOLDER: In the API integration phase, the request logic to the Google API will be placed here.
                # For now, we are testing the pipe's resilience (Circuit Breaker)
                if "gemini" in model:
                    # Simulate API Call...
                    # If it fails (e.g., timeout), raise an Exception to trigger a Fallback
                    pass 
                
                elif "local" in model:
                    print(f"[OPENCLAW] [WARNING] Cloud API unreachable. Failing over to offline Local LLM ({model}).")
                    # Simulate calling Ollama localhost
                    pass
                
                # Returns a JSON MOCK for piping tests
                return json.dumps({
                    "red_agent": "Simulated attack identified.",
                    "blue_agent": "Defense breached.",
                    "judge_verdict": f"Analyzed by {model}. Execute freeze.",
                    "epistemic_doubt": 5,
                    "action": "freeze",
                    "target_pid": 4092,
                    "context_summary": forensic_context
                })
                
            except Exception as e:
                print(f"[OPENCLAW] [ERROR] {model} failed: {str(e)}. Triggering Circuit Breaker fallback...")
                time.sleep(1)
                continue
                
        return json.dumps({"action": "unknown", "epistemic_doubt": 100, "context_summary": forensic_context})

class YomiRouter:
    def __init__(self, stance="shogun"):
        self.stance = stance
        self.audit = ImmutableStamp()
        self.harness = YomiHarness()

        self.audit.record_action(
            agent_name="SYSTEM_BOOT",
            action_type="INITIALIZATION",
            description="Yomi Core Router v2.0 armed with Triad Council & Epistemic Engine.",
            raw_command="yomi_core/router.py",
        )

    def evaluate_intent(self, ai_json_payload: str) -> dict:
        """
        The Epistemic Uncertainty Engine & Triad Council Gatekeeper.
        Validates AI epistemic doubt before routing execution to the MCP Harness.
        """
        # 1. Enforce JSON Intent Protocol
        try:
            intent_data = json.loads(ai_json_payload)
        except json.JSONDecodeError:
            error_msg = "FATAL: AI output is not valid JSON. Intent Protocol violated."
            self.audit.record_action("JUDGE", "VETO", error_msg)
            return {"status": "REJECTED", "message": error_msg}

        # 2. Extract Triad Council Deliberation
        red_agent = intent_data.get("red_agent", "No data")
        blue_agent = intent_data.get("blue_agent", "No data")
        judge = intent_data.get("judge_verdict", "No data")

        # 3. Extract Epistemic Doubt Score (0-100)
        doubt_score = intent_data.get("epistemic_doubt", 100)
        action = intent_data.get("action", "unknown")
        target_pid = intent_data.get("target_pid", None)

        print(f"\n[TRIAD COUNCIL] Red (Attack)  : {red_agent}")
        print(f"[TRIAD COUNCIL] Blue (Defense): {blue_agent}")
        print(f"[TRIAD COUNCIL] Judge Verdict : {judge}")
        print(f"[EPISTEMIC ENGINE] Doubt Score: {doubt_score}%")

        # 4. Epistemic Uncertainty Logic (Doubt Threshold Veto)
        if doubt_score > 40:
            msg = f"Doubt threshold exceeded ({doubt_score}%). Action '{action}' REJECTED. Initiating Self-Correction / Shadow Net."
            print(f"[!] {msg}")
            self.audit.record_action("EPISTEMIC_ENGINE", "REJECT", msg)
            return {
                "status": "SELF_CORRECTION_REQUIRED",
                "message": msg,
                "next_step": "Deploy Shadow Net",
            }

        # 5. Tactical Execution (Low Doubt -> Route to Air-Gapped Harness)
        print(
            f"[+] Doubt is within acceptable parameters ({doubt_score}%). Routing to Air-Gapped Harness..."
        )
        self.audit.record_action(
            "TRIAD_COUNCIL",
            "APPROVED",
            f"Action '{action}' on PID {target_pid} approved with {doubt_score}% doubt.",
        )

        harness_result = self.harness.process_intent(ai_json_payload)
        self.audit.record_action(
            "HARNESS", harness_result.get("status", "UNKNOWN"), str(harness_result)
        )

        return harness_result
