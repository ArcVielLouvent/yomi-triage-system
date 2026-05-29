import sys
import json
import os

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.harness import YomiHarness

# Engine modules maintained for subsequent integration phases (Phase 3 & 4)
from yomi_engine.library import OmniLibrary
from yomi_engine.remediator import ReverserEngine
from yomi_engine.swarm import SwarmOrchestrator
from yomi_engine.hunter import OmniVectorHunter
from yomi_engine.sandbox import SandboxEnvironment

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Ouroboros Router v2.0
# Purpose: Triad Council Gatekeeper, Epistemic Uncertainty Engine, and
#          MCP Vault Routing. Ensures strict JSON intent compliance.
# ==============================================================================


class YomiRouter:
    def __init__(self, stance="shogun"):
        self.stance = stance
        self.audit = ImmutableStamp()
        self.harness = YomiHarness()

        # Initialize subsystem instances (Standby Mode)
        self.library = OmniLibrary()
        self.reverser = ReverserEngine()
        self.swarm = SwarmOrchestrator()
        self.hunter = OmniVectorHunter()
        self.sandbox = SandboxEnvironment()

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
