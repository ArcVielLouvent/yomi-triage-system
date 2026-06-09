import json
import psutil
import os
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - The Air-Gapped Harness & Veto Logic (v4.0)
# Purpose: Strict Type-Safe execution boundary. Validates AI JSON intents and
#          vetoes destructive/hallucinated commands via Zero-Trust Whitelisting.
#          - AccessDenied Immunity: Safely handles Linux permission bounds.
#          - Anti-Spoofing: Path-based validation to defeat Process Name Spoofing.
#          - Ghost Executable Support: Immune to Linux " (deleted)" symlink suffix.
# ==============================================================================


class YomiHarness:
    def __init__(self):
        self.os_bridge = OSBridge()
        self.allowed_actions = ["freeze", "thaw"]

    def _is_critical_system_pid(self, pid: int) -> bool:
        """
        Hardened Dynamic OS Protection.
        Catches AccessDenied errors gracefully.
        Validates absolute paths and handles Linux " (deleted)" memory mappings.
        """
        # Always protect absolute core kernel threads and root init
        if pid <= 100:
            return True

        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()

            if not exe_path:
                return False

            # Ghost Executable / Deleted Binary Protection
            # Linux kernel appends " (deleted)" to /proc/[pid]/exe if the binary
            # is updated or removed while running. We must strip this to recognize valid daemons.
            clean_exe_path = exe_path.replace(" (deleted)", "").strip()

            # Valid Linux system bin paths
            safe_bin_dirs = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]

            # O(1) Lookup set for critical daemon names
            critical_binaries = {
                "sshd",
                "bash",
                "systemd",
                "docker",
                "dockerd",
                "containerd",
            }

            basename = os.path.basename(clean_exe_path)
            is_in_safe_dir = any(
                clean_exe_path.startswith(safe_dir) for safe_dir in safe_bin_dirs
            )

            # A process is only protected if it claims a critical name AND resides in a system folder.
            if basename in critical_binaries and is_in_safe_dir:
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # AccessDenied means it's likely a higher-privilege system daemon. Protect it.
            return True

        return False

    def _veto_check(self, intent_data: dict) -> dict:
        """
        THE JUDGE: Evaluates the intent using strict Zero-Trust boundaries.
        Returns a dictionary with 'is_vetoed' boolean and 'reason'.
        """
        raw_action = intent_data.get("action")
        if not isinstance(raw_action, str):
            return {
                "is_vetoed": True,
                "reason": "VETO: 'action' field must be a valid string.",
            }

        action = raw_action.lower().strip()

        if action not in self.allowed_actions:
            return {
                "is_vetoed": True,
                "reason": f"VETO: Action '{action}' denied. Only Type-Safe MCP operations {self.allowed_actions} are authorized.",
            }

        raw_pid = intent_data.get("target_pid")
        if raw_pid is None:
            return {
                "is_vetoed": True,
                "reason": f"VETO: Action '{action}' explicitly requires a 'target_pid'.",
            }

        try:
            target_pid = int(raw_pid)
        except (ValueError, TypeError):
            return {
                "is_vetoed": True,
                "reason": f"VETO: 'target_pid' ('{raw_pid}') must be a strict integer.",
            }

        if self._is_critical_system_pid(target_pid):
            return {
                "is_vetoed": True,
                "reason": f"VETO: Target PID {target_pid} is classified as a protected critical OS process or access was denied.",
            }

        return {"is_vetoed": False, "reason": "Intent validated. Execution authorized."}

    def process_intent(self, ai_response: str) -> dict:
        """
        The main entry point for AI communication.
        Accepts JSON string, validates schema, runs Veto check, and executes safely.
        """
        try:
            intent_data = json.loads(ai_response)
            if not isinstance(intent_data, dict):
                raise ValueError("Parsed JSON is not a key-value object.")
        except (json.JSONDecodeError, ValueError) as e:
            return {
                "status": "ERROR",
                "message": f"HARNESS REJECTED: AI output is not a valid JSON intent object. ({e})",
            }

        print(
            f"\n[YOMI-HARNESS] Received AI Intent: {intent_data.get('action')} on target {intent_data.get('target_pid')}"
        )
        veto_result = self._veto_check(intent_data)

        if veto_result["is_vetoed"]:
            print(f"[YOMI-HARNESS] [BLOCKED] {veto_result['reason']}")
            return {"status": "VETOED", "message": veto_result["reason"]}

        action = intent_data.get("action", "").lower().strip()
        target_pid = int(intent_data.get("target_pid"))

        print(f"[YOMI-HARNESS] [AUTHORIZED] Intent Validated. Routing to OS Bridge...")

        if action == "freeze":
            return self.os_bridge.cryogenic_freeze(target_pid)
        elif action == "thaw":
            return self.os_bridge.thaw_process(target_pid)

        return {
            "status": "ERROR",
            "message": "Action valid but no OS routing defined.",
        }
