import os
import platform
import signal
import shutil

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - OS Detector Bridge (v2.0)
# Purpose: Hardware Abstraction Layer. Detects OS and specific SIFT toolchains
#          to route execution safely (Real Execution vs Vibe-Coding Mock Mode).
# ==============================================================================


class OSBridge:
    def __init__(self):
        self.os_type = platform.system()
        self.environment = "UNKNOWN"
        self._initialize_bridge()

    def _initialize_bridge(self):
        print(f"\n[YOMI-BRIDGE] Initializing Hardware Abstraction Layer...")
        print(f"[YOMI-BRIDGE] Base OS Detected: {self.os_type}")

        if self.os_type == "Windows":
            self.environment = "WINDOWS_MOCK"
            print(
                "[YOMI-BRIDGE] Windows Development Environment. Loading ETW Simulation Stubs..."
            )

        elif self.os_type == "Linux":
            # Check if this is an actual SIFT workstation by looking for Volatility
            if shutil.which("vol.py") or shutil.which("vol"):
                self.environment = "SIFT_LINUX"
                print(
                    "[YOMI-BRIDGE] SIFT Workstation Confirmed. eBPF & Kernel Hooks ARMED."
                )
            else:
                self.environment = "CODESPACES_LINUX"
                print(
                    "[YOMI-BRIDGE] Standard Linux (Codespaces) Detected. SIFT tools not found."
                )
                print("[YOMI-BRIDGE] Activating Linux Mock Mode...")

        else:
            self.environment = "UNKNOWN_MOCK"
            print(
                f"[YOMI-BRIDGE] Unknown OS ({self.os_type}). Falling back to simulation mode."
            )

    def is_mock_mode(self) -> bool:
        """Returns True if Yomi should simulate tool outputs."""
        return self.environment != "SIFT_LINUX"

    def cryogenic_freeze(self, pid: int) -> dict:
        """
        Freezes a process in memory without terminating it.
        """
        try:
            pid = int(pid)
            if pid <= 0:
                return {
                    "status": "ERROR",
                    "reason": f"CRITICAL: Attempt to freeze illegal PID {pid}. Blocked.",
                }
            if pid <= 4:
                return {
                    "status": "ERROR",
                    "reason": f"CRITICAL: Attempt to freeze protected PID {pid}. Blocked.",
                }
            if pid in (os.getpid(), os.getppid()):
                return {
                    "status": "ERROR",
                    "reason": "CRITICAL: Refusing to freeze the current or parent process.",
                }

            if (
                self.environment == "SIFT_LINUX"
                or self.environment == "CODESPACES_LINUX"
            ):
                # Real Linux execution (SIGSTOP works on both SIFT and Codespaces)
                os.kill(pid, signal.SIGSTOP)
                return {
                    "status": "SUCCESS",
                    "action": "FROZEN",
                    "pid": pid,
                    "os": "Linux",
                    "method": "SIGSTOP",
                }
            else:
                # Windows / Unknown Simulation
                return {
                    "status": "SUCCESS",
                    "action": "FROZEN",
                    "pid": pid,
                    "os": self.os_type,
                    "method": "Simulated NtSuspendProcess",
                }
        except ProcessLookupError:
            return {"status": "ERROR", "reason": f"PID {pid} not found."}
        except PermissionError:
            return {
                "status": "ERROR",
                "reason": f"Permission denied to freeze PID {pid}. Root/Admin required.",
            }
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}

    def thaw_process(self, pid: int) -> dict:
        """
        Resumes a frozen process (SIGCONT).
        """
        try:
            pid = int(pid)
            if pid <= 0:
                return {
                    "status": "ERROR",
                    "reason": f"CRITICAL: Attempt to thaw illegal PID {pid}. Blocked.",
                }
            if pid <= 4:
                return {
                    "status": "ERROR",
                    "reason": f"CRITICAL: Attempt to thaw protected PID {pid}. Blocked.",
                }
            if pid in (os.getpid(), os.getppid()):
                return {
                    "status": "ERROR",
                    "reason": "CRITICAL: Refusing to thaw the current or parent process.",
                }

            if (
                self.environment == "SIFT_LINUX"
                or self.environment == "CODESPACES_LINUX"
            ):
                os.kill(pid, signal.SIGCONT)
                return {
                    "status": "SUCCESS",
                    "action": "THAWED",
                    "pid": pid,
                    "os": "Linux",
                    "method": "SIGCONT",
                }
            else:
                return {
                    "status": "SUCCESS",
                    "action": "THAWED",
                    "pid": pid,
                    "os": self.os_type,
                    "method": "Simulated ResumeThread",
                }
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}
