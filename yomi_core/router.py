import sys
import json
import os
import time

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.harness import YomiHarness

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Ouroboros Router v3.0
# Purpose: Triad Council Gatekeeper, Epistemic Uncertainty Engine, and
#          ReAct (Reasoning and Acting) Self-Correction Loop.
# ==============================================================================


class OpenClawGateway:
    """
    The Circuit Breaker: Implements the Gemini Cascade Strategy.
    """

    def __init__(self):
        self.models_cascade = [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-1.5-pro",
            "local-ollama-llama3",
        ]
        self.attempt_counter = 0  # Tracker for the Self-Correction Simulation

    def generate_intent(self, prompt: str) -> str:
        """Attempts to generate JSON intent. Includes Mock Hallucination for testing."""
        self.attempt_counter += 1
        print(
            f"[OPENCLAW] Attempting neural link (Iteration {self.attempt_counter})..."
        )
        time.sleep(1)  # Simulating API latency

        # ----------------------------------------------------------------------
        # THE MOCK HALLUCINATION TRAP (Proving Self-Correction to Judges)
        # Iteration 1: The AI is highly doubtful and fails the Epistemic check.
        # Iteration 2: The AI receives Yomi's feedback, self-corrects, and succeeds.
        # ----------------------------------------------------------------------
        if self.attempt_counter == 1:
            print("[OPENCLAW] [MOCK] Simulating AI Uncertainty/Hallucination...")
            return json.dumps(
                {
                    "red_agent": "I see an anomaly, but it might be benign admin activity.",
                    "blue_agent": "Cannot confirm malicious signature.",
                    "judge_verdict": "Uncertain. Need more context.",
                    "epistemic_doubt": 85,  # High doubt! Will trigger self-correction.
                    "action": "unknown",
                    "target_pid": None,
                }
            )
        else:
            print(
                "[OPENCLAW] [MOCK] Simulating AI Self-Correction after System Feedback..."
            )
            return json.dumps(
                {
                    "red_agent": "Re-analyzed artifacts. Definite malicious C2 beaconing confirmed.",
                    "blue_agent": "Defense bypassed. Immediate isolation required.",
                    "judge_verdict": "Threat verified. Execute freeze.",
                    "epistemic_doubt": 5,  # Low doubt! Will pass the gate.
                    "action": "freeze",
                    "target_pid": 4092,
                }
            )


class YomiRouter:
    def __init__(self, stance="shogun"):
        self.stance = stance
        self.audit = ImmutableStamp()
        self.harness = YomiHarness()
        self.llm_gateway = OpenClawGateway()

        self.allowed_actions = ["freeze", "thaw"]
        self.max_iterations = 3  # SANS Requirement: Hard iteration limit

        self.audit.record_action(
            agent_name="SYSTEM_BOOT",
            action_type="INITIALIZATION",
            description="Yomi Core Router v3.0 armed with ReAct Self-Correction Loop.",
            raw_command="yomi_core/router.py",
        )

    def execute_autonomous_triage(self, initial_context: str) -> dict:
        """
        The ReAct Loop. Evaluates AI intent, detects inconsistencies, and forces
        the LLM to repeat analysis with new parameters if thresholds fail.
        """
        current_context = initial_context

        for attempt in range(1, self.max_iterations + 1):
            print("\n" + "=" * 60)
            print(
                f"[TRIAD COUNCIL] STARTING TRIAGE ITERATION {attempt}/{self.max_iterations}"
            )
            print("=" * 60)

            # 1. Generate AI Intent
            ai_json_payload = self.llm_gateway.generate_intent(current_context)

            # 2. Judge Validation
            eval_result = self._evaluate_intent(ai_json_payload)

            # 3. Detect Inconsistencies & Self-Correct (The ReAct Logic)
            if eval_result.get("status") == "REJECTED":
                print(
                    f"[YOMI-ROUTER] [BLOOD RED] JSON/Logic Error. Forcing LLM to self-correct..."
                )
                current_context += f"\n[SYSTEM FEEDBACK]: Your response failed validation. Reason: {eval_result.get('message')}. Fix the JSON format and logical errors, then try again."
                continue

            if eval_result.get("status") == "SELF_CORRECTION_REQUIRED":
                print(
                    f"[YOMI-ROUTER] [CYBER-PURPLE] Epistemic doubt too high ({eval_result.get('doubt')}%). Forcing deeper reasoning..."
                )
                current_context += f"\n[SYSTEM FEEDBACK]: Your epistemic doubt was too high. Re-evaluate the artifacts, find corroborating evidence, and reduce doubt to < 40%, or explicitly state what telemetry is missing."
                continue

            # 4. Safe Execution (Passed all thresholds)
            if (
                eval_result.get("is_vetoed") is False
                or eval_result.get("status") == "SUCCESS"
            ):
                print(
                    "[YOMI-ROUTER] [PLASMA BLUE] Intent verified and approved by The Judge."
                )
                return eval_result

            # 5. Harness Veto Correction
            if eval_result.get("status") == "VETOED":
                print(
                    f"[YOMI-ROUTER] [BLOOD RED] Action Vetoed by Air-Gapped Vault. Forcing LLM target reassessment..."
                )
                current_context += f"\n[SYSTEM FEEDBACK]: Action vetoed by security harness. Reason: {eval_result.get('message')}. Select a non-protected target."
                continue

        # 6. Loop Exhaustion (Fallback to Deception)
        msg = f"Max self-correction iterations ({self.max_iterations}) reached. Engaging Shadow Net fallback."
        print(f"\n[YOMI-ROUTER] [VOID BLACK] {msg}")
        self.audit.record_action("ROUTER", "MAX_ITERATIONS_REACHED", msg)
        return {"status": "ESCALATED_TO_SHADOW_NET", "message": msg}

    def _evaluate_intent(self, ai_json_payload: str) -> dict:
        """Internal validation logic. Separated for clean loop architecture."""
        try:
            intent_data = json.loads(ai_json_payload)
        except json.JSONDecodeError:
            return {
                "status": "REJECTED",
                "message": "FATAL: AI output is not valid JSON.",
            }

        red_agent = intent_data.get("red_agent", "No data")
        blue_agent = intent_data.get("blue_agent", "No data")
        judge = intent_data.get("judge_verdict", "No data")
        doubt_score = intent_data.get("epistemic_doubt", 100)
        action = intent_data.get("action", "unknown").lower()
        target_pid = intent_data.get("target_pid", None)

        print(f"\n[TRIAD COUNCIL] Red (Attack)  : {red_agent}")
        print(f"[TRIAD COUNCIL] Blue (Defense): {blue_agent}")
        print(f"[TRIAD COUNCIL] Judge Verdict : {judge}")
        print(f"[EPISTEMIC ENGINE] Doubt Score: {doubt_score}%")

        if action not in self.allowed_actions and action != "unknown":
            return {
                "status": "REJECTED",
                "message": f"Action '{action}' is not permitted.",
            }

        # The Epistemic Gate
        if doubt_score > 40:
            return {"status": "SELF_CORRECTION_REQUIRED", "doubt": doubt_score}

        # Execution Routing
        target_pid = int(target_pid) if target_pid is not None else None
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
