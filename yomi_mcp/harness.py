import json
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - The Air-Gapped Harness & Veto Logic
# Purpose: Strict Type-Safe execution boundary. Validates AI JSON intents and
#          vetoes destructive/hallucinated commands.
# ==============================================================================


class YomiHarness:
    def __init__(self):
        self.os_bridge = OSBridge()
        # The Judge's List: Processes that AI is NEVER allowed to touch
        # 0, 1, 2, 3, 4 typically represent core OS kernel/init processes
        self.protected_pids = [0, 1, 2, 3, 4]
        self.banned_actions = ["rm", "kill", "del", "format", "mkfs"]

    def _veto_check(self, intent_data: dict) -> dict:
        """
        THE JUDGE: Evaluates the intent before any execution occurs.
        Returns a dictionary with 'is_vetoed' boolean and 'reason'.
        """
        action = intent_data.get("action", "").lower()
        raw_pid = intent_data.get("target_pid")

        # 1. Type Confusion Protection (Force Integer)
        target_pid = None
        if raw_pid is not None:
            try:
                target_pid = int(raw_pid)
            except (ValueError, TypeError):
                return {
                    "is_vetoed": True,
                    "reason": f"VETO: target_pid '{raw_pid}' is not a valid integer.",
                }

        # 2. Null Pointer Protection (Strict 'is None' check to avoid PID 0 false positives)
        if action in ["freeze", "thaw"] and target_pid is None:
            return {
                "is_vetoed": True,
                "reason": f"VETO: Action '{action}' requires a valid target_pid.",
            }

        # 3. Anti-Spoliation: Block banned raw commands
        if action in self.banned_actions:
            return {
                "is_vetoed": True,
                "reason": f"VETO: Action '{action}' is strictly forbidden by Air-Gapped Vault.",
            }

        # 4. Critical System Protection: Block freezing Core OS PIDs
        # Redundant casting removed. target_pid is guaranteed to be an integer here.
        if target_pid is not None and target_pid in self.protected_pids:
            return {
                "is_vetoed": True,
                "reason": f"VETO: Target PID {target_pid} is a protected core OS process.",
            }

        # 5. Restrict allowed actions to Type-Safe functions only
        allowed_actions = ["freeze", "thaw"]
        if action not in allowed_actions:
            return {
                "is_vetoed": True,
                "reason": f"VETO: Action '{action}' is not a recognized Type-Safe command.",
            }

        return {"is_vetoed": False, "reason": "Intent validated. Execution authorized."}

    def process_intent(self, ai_response: str) -> dict:
        """
        The main entry point for AI communication.
        Accepts JSON string, validates it, runs Veto check, and executes safely.
        """
        try:
            # 1. Parse JSON Protocol
            intent_data = json.loads(ai_response)
        except json.JSONDecodeError:
            return {
                "status": "ERROR",
                "message": "HARNESS REJECTED: AI output is not valid JSON. Intent Protocol violated.",
            }

        # 2. Veto Logic (The Judge)
        print(
            f"\n[YOMI-HARNESS] Received AI Intent: {intent_data.get('action')} on target {intent_data.get('target_pid')}"
        )
        veto_result = self._veto_check(intent_data)

        if veto_result["is_vetoed"]:
            print(f"[YOMI-HARNESS] [BLOCKED] {veto_result['reason']}")
            return {"status": "VETOED", "message": veto_result["reason"]}

        # 3. Safe Execution Routing (Passing to OS Bridge)
        action = intent_data.get("action", "").lower()
        target_pid = intent_data.get("target_pid")

        print(f"[YOMI-HARNESS] [AUTHORIZED] Intent Validated. Routing to OS Bridge...")
        if action == "freeze":
            return self.os_bridge.cryogenic_freeze(target_pid)
        elif action == "thaw":
            return self.os_bridge.thaw_process(target_pid)
        else:
            return {
                "status": "ERROR",
                "message": "Action valid but no execution routing defined.",
            }
