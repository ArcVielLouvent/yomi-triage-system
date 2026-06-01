import os
import platform
import signal
import shutil

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - OS Detector Bridge (v3.0)
# Purpose: Hardware Abstraction Layer. Detects OS and available forensic
#          binaries, then routes execution safely with real toolchain awareness.
# ==============================================================================


class OSBridge:
    def __init__(self):
        self.os_type = platform.system()
        self.environment = "UNKNOWN"
        self.tool_paths: dict[str, str] = {}
        self.is_sift = False
        self._initialize_bridge()

    def _initialize_bridge(self):
        print(f"\n[YOMI-BRIDGE] Initializing Hardware Abstraction Layer...")
        print(f"[YOMI-BRIDGE] Base OS Detected: {self.os_type}")

        if self.os_type == "Windows":
            self.environment = "WINDOWS"
            print(
                "[YOMI-BRIDGE] Windows host detected. Live SIFT toolchain support is limited."
            )
            self._probe_toolchain()

        elif self.os_type == "Linux":
            self._probe_toolchain()
            if self.is_sift:
                self.environment = "SIFT_LINUX"
                print(
                    "[YOMI-BRIDGE] SIFT Workstation confirmed. Forensic binaries available."
                )
            elif self.can_execute_forensics():
                self.environment = "LINUX_TOOLCHAIN"
                print(
                    "[YOMI-BRIDGE] Linux forensic toolchain detected. Partial SIFT capabilities are available."
                )
            else:
                self.environment = "LINUX_MINIMAL"
                print(
                    "[YOMI-BRIDGE] Linux host detected with no SIFT binaries. Tool wrappers will report availability status."
                )

        else:
            self.environment = "UNKNOWN"
            print(
                f"[YOMI-BRIDGE] Unknown OS ({self.os_type}). Forensic tool detection will be limited."
            )
            self._probe_toolchain()

        self._display_detected_tools()

    def _probe_toolchain(self) -> None:
        known_tools = {
            "volatility": ["vol.py", "vol"],
            "radare2": ["r2"],
            "log2timeline": ["log2timeline.py", "log2timeline"],
            "fls": ["fls"],
            "img_stat": ["img_stat"],
            "icat": ["icat"],
            "tshark": ["tshark"],
            "bulk_extractor": ["bulk_extractor"],
            "yara": ["yara"],
            "ssdeep": ["ssdeep"],
            "strings": ["strings"],
            "grep": ["grep"],
            "reglookup": ["reglookup"],
            "mftparser": ["mftparser"],
            "scalpel": ["scalpel"],
        }

        for tool_name, executable_names in known_tools.items():
            self.tool_paths[tool_name] = next(
                (shutil.which(exe) for exe in executable_names if shutil.which(exe)),
                "",
            )

        self.is_sift = bool(self.tool_paths.get("volatility") and self.tool_paths.get("fls"))

    def _display_detected_tools(self) -> None:
        print("[YOMI-BRIDGE] Forensic tool availability:")
        for name, path in sorted(self.tool_paths.items()):
            print(f"  - {name}: {'available' if path else 'missing'}")

    def is_tool_available(self, tool_name: str) -> bool:
        return bool(self.tool_paths.get(tool_name))

    def get_tool_path(self, tool_name: str) -> str:
        return self.tool_paths.get(tool_name, "")

    def can_execute_forensics(self) -> bool:
        return any(bool(path) for path in self.tool_paths.values())

    def is_reduced_mode(self) -> bool:
        return self.environment not in {"SIFT_LINUX", "LINUX_TOOLCHAIN"}

    def cryogenic_freeze(self, pid: int) -> dict:
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

            if self.os_type == "Linux":
                os.kill(pid, signal.SIGSTOP)
                return {
                    "status": "SUCCESS",
                    "action": "FROZEN",
                    "pid": pid,
                    "os": "Linux",
                    "method": "SIGSTOP",
                }
            return {
                "status": "ERROR",
                "reason": "Cryogenic freeze is only supported on Linux hosts.",
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

            if self.os_type == "Linux":
                os.kill(pid, signal.SIGCONT)
                return {
                    "status": "SUCCESS",
                    "action": "THAWED",
                    "pid": pid,
                    "os": "Linux",
                    "method": "SIGCONT",
                }
            return {
                "status": "ERROR",
                "reason": "Thaw is only supported on Linux hosts.",
            }
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}
