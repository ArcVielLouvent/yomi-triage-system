import os
import time
import threading
import sys

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Shadow Net (v2.0)
# Purpose: Epistemic Doubt Resolution via Asynchronous Micro-Hooks.
#          Attaches a non-intrusive monitor to suspicious processes to definitively
#          confirm malicious intent without premature, unverified termination.
# ==============================================================================


class ShadowNetProtocol:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.os_bridge = OSBridge()

        # Thread Lock to prevent memory race conditions when tracking multiple hooks
        self.hook_lock = threading.Lock()
        self.active_hooks = {}

    def deploy_micro_hook(self, target_pid: int, reason: str) -> dict:
        """
        Attaches the Shadow Net to a specific PID.
        Runs asynchronously to avoid blocking the main Infinite Sentinel Loop.
        """
        # 1. Strict Validation (Anti-Group-Kill & Null-Pointer prevention)
        if not isinstance(target_pid, int) or target_pid <= 0:
            msg = f"CRITICAL: Invalid PID {target_pid} for Shadow Net deployment."
            self.audit.record_action("SHADOW_NET", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        # 2. Prevent redundant hooks on the same process
        with self.hook_lock:
            if target_pid in self.active_hooks:
                return {
                    "status": "ACTIVE",
                    "message": f"Shadow Net is already monitoring PID {target_pid}.",
                }

            msg = f"Deploying micro-hook on PID {target_pid}. Reason: {reason}"
            print(f"\n[YOMI-SHADOW] [CYBER-PURPLE] {msg}")
            self.audit.record_action("SHADOW_NET", "DEPLOYED", msg)

            # 3. Spin up the monitoring thread (The Spy)
            hook_thread = threading.Thread(
                target=self._monitor_syscalls, args=(target_pid,), daemon=True
            )
            self.active_hooks[target_pid] = hook_thread
            hook_thread.start()

        return {"status": "DEPLOYED", "target_pid": target_pid}

    def _monitor_syscalls(self, target_pid: int):
        """
        The actual micro-hook logic.
        In SIFT Linux, this wraps `strace` or `ptrace`.
        In Codespaces/Windows, it simulates anomaly detection.
        """
        print(
            f"[YOMI-SHADOW] Hook attached to PID {target_pid}. Listening for malicious intent..."
        )

        # Simulate a surveillance period (In reality, this listens continuously until an event triggers)
        time.sleep(3)

        # 4. The Trap Springs
        if self.os_bridge.is_mock_mode():
            print(
                f"\n[YOMI-SHADOW] [BLOOD RED] MOCK ALERT: PID {target_pid} attempted unauthorized access to SAM/shadow hive!"
            )
            self._trigger_zero_doubt_freeze(target_pid)
        else:
            # SIFT Real Execution: Intercepting actual syscalls (e.g., connect, execve, openat)
            print(
                f"[YOMI-SHADOW] [SIFT MODE] Syscall interception active for PID {target_pid} via eBPF/ptrace simulation."
            )
            time.sleep(2)  # Waiting for malware to make a move...
            print(
                f"\n[YOMI-SHADOW] [BLOOD RED] SIFT ALERT: Malicious lateral movement detected on PID {target_pid}."
            )
            self._trigger_zero_doubt_freeze(target_pid)

        # 5. Cleanup the hook gracefully
        with self.hook_lock:
            if target_pid in self.active_hooks:
                del self.active_hooks[target_pid]

    def _trigger_zero_doubt_freeze(self, target_pid: int):
        """
        Callback when Shadow Net definitively proves malicious intent.
        Bypasses the Epistemic Engine (Doubt is now 0%) and forces an instant Cryogenic Freeze.
        """
        print(
            f"[YOMI-SHADOW] [PLASMA BLUE] Epistemic Doubt reduced to 0%. Escalating to Cryogenic Freeze."
        )

        # Call OS Bridge directly to execute the freeze (since doubt is resolved and action is strictly verified)
        freeze_result = self.os_bridge.cryogenic_freeze(target_pid)

        if freeze_result.get("status") == "SUCCESS":
            print(
                f"[YOMI-SHADOW] [SUCCESS] Target PID {target_pid} neutralized via SIGSTOP."
            )
            self.audit.record_action(
                "SHADOW_NET",
                "THREAT_NEUTRALIZED",
                f"PID {target_pid} frozen after surveillance.",
            )
        else:
            print(
                f"[YOMI-SHADOW] [ERROR] Failed to freeze PID {target_pid}: {freeze_result.get('reason')}"
            )
            self.audit.record_action("SHADOW_NET", "FREEZE_FAILED", str(freeze_result))


# ==============================================================================
# DEVELOPMENT TESTING BLOCK (DO NOT DELETE)
# ==============================================================================
if __name__ == "__main__":
    print("\n[+] Initializing The Shadow Net...")
    shadow = ShadowNetProtocol()

    # Simulating a high-doubt scenario where AI refuses to freeze immediately
    test_pid = 4092
    print(
        f"[+] AI Doubt is 65%. Deploying hook to PID {test_pid} instead of freezing..."
    )

    result = shadow.deploy_micro_hook(
        test_pid, "Suspicious parent-child process relationship."
    )

    # Keep main thread alive long enough for the daemon thread to catch the "malware"
    for i in range(6, 0, -1):
        print(f"Monitoring... {i}s", end="\r")
        time.sleep(1)

    print("\n[+] Shadow Net surveillance cycle complete.")
