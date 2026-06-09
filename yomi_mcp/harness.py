import json
import psutil
import os

# Append root directory to sys.path
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - The Air-Gapped Harness & Veto Logic (v5.0)
# Purpose: Strict Type-Safe execution boundary. Validates AI JSON intents and
#          vetoes destructive/hallucinated commands via Zero-Trust Whitelisting.
#          - Realpath Pinning: Defeats complex Symlink Hijacking / Path Spoofing.
#          - Kernel Thread Immunity: Prevents freezing of intangible OS structures.
#          - AccessDenied Handling: Safely defaults to protecting high-privilege daemons.
# ==============================================================================


class YomiHarness:
    def __init__(self):
        self.os_bridge = OSBridge()
        self.allowed_actions = ["freeze", "thaw"]

    def _is_critical_system_pid(self, pid: int) -> bool:
        """
        Hardened Dynamic OS Protection.
        Catches AccessDenied errors, resolves physical symlinks, and shields
        Kernel Threads from accidental system-crashing interventions.
        """
        # Always protect absolute core kernel threads and root init (PID 0-100)
        if pid <= 100:
            return True

        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()

            # Kernel threads (e.g., kworker, rcu_sched) live entirely in RAM and
            # do not have a binary path on disk. If exe_path is empty, it's a kernel
            # structure. We MUST protect it to prevent Kernel Panic.
            if not exe_path:
                return True

            # Ghost Executable / Deleted Binary Protection
            # Strip the Linux "(deleted)" suffix to recover the original path string
            clean_exe_path = exe_path.replace(" (deleted)", "").strip()

            # Force the OS to resolve the true physical location of the binary on disk.
            # This shatters any illusions if malware is using complex symlinks to masquerade
            # as a trusted system binary.
            true_physical_path = os.path.realpath(clean_exe_path)

            # Valid Linux system bin paths (Physically resolved boundaries)
            safe_bin_dirs = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]

            # O(1) Lookup set for critical daemon names
            critical_binaries = {
                "sshd",
                "bash",
                "sh",
                "systemd",
                "docker",
                "dockerd",
                "containerd",
                "init",
            }

            basename = os.path.basename(true_physical_path)

            # Check if the fully resolved physical path sits inside a trusted system directory
            is_in_safe_dir = any(
                true_physical_path.startswith(safe_dir) for safe_dir in safe_bin_dirs
            )

            # A process is only protected if it claims a critical name AND physically resides in a system folder.
            if basename in critical_binaries and is_in_safe_dir:
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # AccessDenied usually means it's a higher-privilege system daemon or root process.
            # Fail-safe policy: If we can't inspect it, protect it.
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

        # Route the PID through the Hardened OS Protection Shield
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

        # Execute the absolute Veto assessment
        veto_result = self._veto_check(intent_data)

        if veto_result["is_vetoed"]:
            print(f"[YOMI-HARNESS] [BLOCKED] {veto_result['reason']}")
            return {"status": "VETOED", "message": veto_result["reason"]}

        # Unpack verified and safe data
        action = intent_data.get("action", "").lower().strip()
        target_pid = int(intent_data.get("target_pid"))

        print(f"[YOMI-HARNESS] [AUTHORIZED] Intent Validated. Routing to OS Bridge...")

        # Atomically route to the HAL (Hardware Abstraction Layer)
        if action == "freeze":
            return self.os_bridge.cryogenic_freeze(target_pid)
        elif action == "thaw":
            return self.os_bridge.thaw_process(target_pid)

        return {
            "status": "ERROR",
            "message": "Action valid but no OS routing defined in Harness execution map.",
        }


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    harness = YomiHarness()

    # Simulate valid freeze payload
    safe_payload = '{"action": "freeze", "target_pid": 99999}'
    print(harness.process_intent(safe_payload))

    # Simulate malicious hallucination payload aiming at init (PID 1)
    malicious_payload = '{"action": "freeze", "target_pid": 1}'
    print(harness.process_intent(malicious_payload))
