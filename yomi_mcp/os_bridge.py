import ctypes
import os
import platform
import signal
import shutil

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - OS Detector Bridge (v6.0)
# Purpose: Hardware Abstraction Layer. Detects OS and routes execution safely.
#          - Symlink Hijack Defeated: Resolves true disk paths via realpath.
#          - Bitness Immunity: Minimal privilege OpenProcess for Wow64 stability.
#          - Atomic Execution (Zero TOCTOU): Eradicated psutil pre-checks.
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

        trusted_linux_paths = [
            "/bin/",
            "/sbin/",
            "/usr/bin/",
            "/usr/sbin/",
            "/usr/local/bin/",
            "/opt/",
        ]

        for tool_name, executable_names in known_tools.items():
            resolved_path = ""
            for exe in executable_names:
                path = shutil.which(exe)
                if path:
                    # Defeat Symlink Hijacking
                    true_path = (
                        os.path.realpath(path) if self.os_type == "Linux" else path
                    )

                    if self.os_type == "Linux":
                        is_trusted = any(
                            true_path.startswith(tp) for tp in trusted_linux_paths
                        )
                        if not is_trusted:
                            print(
                                f"[YOMI-BRIDGE] [WARNING] Path Hijack Attempt? Ignored untrusted binary location: {true_path}"
                            )
                            continue

                    resolved_path = true_path
                    break
            self.tool_paths[tool_name] = resolved_path

        self.is_sift = bool(
            self.tool_paths.get("volatility") and self.tool_paths.get("fls")
        )

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
            if pid <= 100:
                return {
                    "status": "ERROR",
                    "reason": f"CRITICAL: Attempt to freeze core OS/Kernel PID {pid}. Blocked.",
                }
            if pid in (os.getpid(), os.getppid()):
                return {
                    "status": "ERROR",
                    "reason": "CRITICAL: Refusing to freeze the current or parent process.",
                }

            # Removed psutil.pid_exists() TOCTOU Anti-Pattern.
            # Relying solely on the Atomic execution of os.kill and the subsequent exception handling.

            if self.os_type == "Linux":
                os.kill(pid, signal.SIGSTOP)
                return {
                    "status": "SUCCESS",
                    "action": "FROZEN",
                    "pid": pid,
                    "os": "Linux",
                    "method": "SIGSTOP",
                }

            if self.os_type == "Windows":
                return self._windows_suspend_process(pid)

            return {
                "status": "ERROR",
                "reason": "Cryogenic freeze is only supported on Linux and Windows hosts.",
            }
        except ProcessLookupError:
            return {
                "status": "GHOST_PROCESS",
                "reason": f"PID {pid} not found (died atomically before execution).",
            }
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
            if pid <= 100:
                return {
                    "status": "ERROR",
                    "reason": f"CRITICAL: Attempt to thaw core OS/Kernel PID {pid}. Blocked.",
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

            if self.os_type == "Windows":
                return self._windows_resume_process(pid)

            return {
                "status": "ERROR",
                "reason": "Thaw is only supported on Linux and Windows hosts.",
            }
        except ProcessLookupError:
            # Added atomic Ghost Process handler for thaw_process as well
            return {
                "status": "GHOST_PROCESS",
                "reason": f"PID {pid} not found (died atomically before execution).",
            }
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}

    def _windows_open_process(self, pid: int):
        PROCESS_SUSPEND_RESUME = 0x0800
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle:
            raise OSError(
                f"Failed to open process {pid} with SUSPEND/RESUME rights (Access Denied or Bitness Mismatch)."
            )
        return handle

    def _windows_suspend_process(self, pid: int) -> dict:
        try:
            handle = self._windows_open_process(pid)
            try:
                status = ctypes.windll.ntdll.NtSuspendProcess(handle)
                if status == 0:
                    return {
                        "status": "SUCCESS",
                        "action": "FROZEN",
                        "pid": pid,
                        "os": "Windows",
                        "method": "NTSuspendProcess",
                    }
                return {
                    "status": "ERROR",
                    "reason": f"NtSuspendProcess failed with status {status}.",
                }
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}

    def _windows_resume_process(self, pid: int) -> dict:
        try:
            handle = self._windows_open_process(pid)
            try:
                status = ctypes.windll.ntdll.NtResumeProcess(handle)
                if status == 0:
                    return {
                        "status": "SUCCESS",
                        "action": "THAWED",
                        "pid": pid,
                        "os": "Windows",
                        "method": "NtResumeProcess",
                    }
                return {
                    "status": "ERROR",
                    "reason": f"NtResumeProcess failed with status {status}.",
                }
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as e:
            return {"status": "ERROR", "reason": str(e)}
