import os
import time
import threading
import sys
import argparse
import signal
import stat

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Shadow Net (v6.0)
# Purpose: Epistemic Doubt Resolution via Asynchronous Kernel Hooks (eBPF).
#          - Anti-TOCTOU: "Freeze-First, Verify-Later" architecture.
#          - Secure ELF Necromancy: O_EXCL file creation & Chunked I/O anti-hang.
#          - Process Hollowing Sandbox: Extracts and detonates memfd payloads.
# ==============================================================================


class ShadowNetProtocol:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.os_bridge = OSBridge()

        self.hook_lock = threading.Lock()
        self.active_hooks = {}

        # Secure recovery directory for ELF Necromancy (Not public /tmp)
        self.recovery_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "yomi_data", "recovery")
        )
        os.makedirs(self.recovery_dir, exist_ok=True)
        os.chmod(self.recovery_dir, 0o700)  # Only root can access this vault

        # Singleton Kernel Instantiation
        from yomi_engine.ebpf_sensor import eBPFSentinel

        try:
            self.ebpf = eBPFSentinel()
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                self.ebpf.arm_sensor()
            else:
                print(
                    "[-] Warning: Shadow Net initialized without root. eBPF hooks will fail."
                )
        except Exception as e:
            self.ebpf = None
            self.audit.record_action(
                "SHADOW_NET", "EBPF_INIT_ERROR", f"Failed to arm kernel sensor: {e}"
            )

    def _resolve_binary_path(self, target_pid: int) -> tuple[str, bool, str]:
        """
        Safely reads the binary path, penetrates containers, and identifies fileless traits.
        """
        try:
            raw_path = os.readlink(f"/proc/{target_pid}/exe")
            is_fileless = raw_path.startswith("/memfd:")
            clean_path = raw_path.replace(" (deleted)", "")

            if not os.path.exists(raw_path) and not is_fileless:
                container_path = f"/proc/{target_pid}/root{clean_path}"
                if os.path.exists(container_path):
                    # Prevent hanging on named pipes (FIFO) or sockets created by malware
                    mode = os.stat(container_path).st_mode
                    if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                        return "", False, ""
                    return container_path, is_fileless, raw_path

            return clean_path, is_fileless, raw_path
        except Exception:
            return "", False, ""

    def deploy_micro_hook(self, target_pid: int, reason: str) -> dict:
        if not isinstance(target_pid, int) or target_pid <= 0:
            msg = f"Invalid PID {target_pid} for deployment."
            self.audit.record_action("SHADOW_NET", "ABORTED", msg)
            return {"status": "ERROR", "message": msg}

        if not self.ebpf:
            return {"status": "ERROR", "message": "Kernel sensor not initialized."}

        with self.hook_lock:
            if target_pid in self.active_hooks:
                return {
                    "status": "ACTIVE",
                    "message": f"Shadow Net is already monitoring PID {target_pid}.",
                }
            self.active_hooks[target_pid] = "INITIALIZING"

        initial_bin_path, is_fileless, initial_raw_path = self._resolve_binary_path(
            target_pid
        )

        if not initial_bin_path:
            with self.hook_lock:
                del self.active_hooks[target_pid]
            return {
                "status": "ERROR",
                "message": "Cannot resolve binary path. Process may be dead or inaccessible.",
            }

        fileless_tag = "[FILELESS-MEMFD]" if is_fileless else ""
        msg = f"Deploying hook on PID {target_pid} {fileless_tag}. Reason: {reason}"
        print(f"[*] {msg}")
        self.audit.record_action("SHADOW_NET", "DEPLOYED", msg)

        hook_thread = threading.Thread(
            target=self._monitor_syscalls_safe,
            args=(target_pid, initial_bin_path, initial_raw_path, is_fileless),
            daemon=True,
        )

        with self.hook_lock:
            self.active_hooks[target_pid] = hook_thread

        hook_thread.start()
        return {"status": "DEPLOYED", "target_pid": target_pid, "thread": hook_thread}

    def _monitor_syscalls_safe(
        self,
        target_pid: int,
        initial_bin_path: str,
        initial_raw_path: str,
        is_fileless: bool,
    ):
        try:
            self._monitor_syscalls_logic(
                target_pid, initial_bin_path, initial_raw_path, is_fileless
            )
        except Exception as e:
            self.audit.record_action(
                "SHADOW_NET", "MONITOR_ERROR", f"Thread crash on PID {target_pid}: {e}"
            )
        finally:
            with self.hook_lock:
                if target_pid in self.active_hooks:
                    del self.active_hooks[target_pid]

    def _monitor_syscalls_logic(
        self,
        target_pid: int,
        initial_bin_path: str,
        initial_raw_path: str,
        is_fileless: bool,
    ):
        print(
            f"[*] Kernel surveillance active on PID {target_pid}. Polling Ring-0 telemetry..."
        )
        is_malicious = self.ebpf.monitor_pid(target_pid, duration_sec=3)

        if is_malicious:
            print(
                f"[*] eBPF CONFIRMATION: Malicious activity verified on PID {target_pid}."
            )

            freeze_result = self.os_bridge.cryogenic_freeze(target_pid)
            if freeze_result.get("status") != "SUCCESS":
                print(
                    f"[-] Failed to freeze PID {target_pid}. Malware may have already exited."
                )
                return

            current_bin_path, _, current_raw_path = self._resolve_binary_path(
                target_pid
            )

            # Check if PID was recycled right before the freeze
            if current_raw_path != initial_raw_path:
                print(
                    f"[-] WARNING: PID {target_pid} recycled! Thawing OS process to prevent system damage."
                )

                # Double Safety Belt for OS Stability
                thaw_result = self.os_bridge.thaw_process(target_pid)
                if thaw_result.get("status") != "SUCCESS":
                    print(
                        f"[-] OSBridge Thaw failed. Engaging raw kernel SIGCONT for PID {target_pid}..."
                    )
                    try:
                        os.kill(target_pid, signal.SIGCONT)
                    except Exception as e:
                        self.audit.record_action(
                            "SHADOW_NET",
                            "FATAL_THAW_ERROR",
                            f"Failed to thaw PID {target_pid}: {e}",
                        )

                self.audit.record_action(
                    "SHADOW_NET",
                    "FALSE_POSITIVE_AVOIDED",
                    f"Thawed recycled PID {target_pid}.",
                )
                return

            self._execute_kill_chain(target_pid, current_bin_path, is_fileless)
        else:
            print(
                f"[*] Surveillance ended. No malicious syscalls detected for PID {target_pid}."
            )

    def _execute_kill_chain(self, target_pid: int, binary_path: str, is_fileless: bool):
        print(f"[*] Epistemic Doubt is 0%. Escalating to Full Autonomous Kill Chain.")
        self.audit.record_action(
            "SHADOW_NET", "THREAT_NEUTRALIZED", f"PID {target_pid} frozen."
        )

        from yomi_engine.remediator import ReverserEngine

        reverser = ReverserEngine()
        payload = {
            "pid": target_pid,
            "file_path": binary_path,
            "threat_type": "FILELESS_MEMFD" if is_fileless else "EBPF_VERIFIED_MALWARE",
        }
        rev_result = reverser.generate_rollback_script(payload)
        if rev_result.get("status") == "SUCCESS":
            print(
                f"[*] Remediation playbook generated: {rev_result.get('script_path')}"
            )

        recovery_source = binary_path

        # Secure ELF Necromancy & Process Hollowing Extraction
        if is_fileless or not os.path.exists(binary_path):
            print(
                f"[*] Threat is memory-resident. Initiating Secure ELF RAM Recovery..."
            )

            timestamp = int(time.time())
            recovered_path = os.path.join(
                self.recovery_dir, f"yomi_recovered_{target_pid}_{timestamp}.bin"
            )

            fd = None
            try:
                fd = os.open(
                    recovered_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400
                )

                with os.fdopen(fd, "wb") as dst, open(
                    f"/proc/{target_pid}/exe", "rb"
                ) as src:
                    max_bytes = 50 * 1024 * 1024
                    bytes_read = 0
                    while bytes_read < max_bytes:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
                        bytes_read += len(chunk)

                os.chmod(recovered_path, 0o700)
                recovery_source = recovered_path
                print(f"[*] ELF successfully recovered to safe vault: {recovered_path}")
            except Exception as e:
                print(f"[-] Failed to safely recover ELF from memory: {e}")
                self.audit.record_action(
                    "SHADOW_NET",
                    "RAM_RECOVERY_FAILED",
                    f"PID {target_pid} extraction error: {e}",
                )
                if fd is not None:
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                recovery_source = None

        # Alur Eksekusi Analisis Intelijen
        if recovery_source:
            from yomi_engine.sandbox import SandboxEnvironment

            sandbox = SandboxEnvironment()
            sandbox_result = sandbox.execute_resurrection(target_pid, recovery_source)
            if sandbox_result.get("status") == "SUCCESS":
                print(
                    f"[*] Malware payload sent to Lazarus Chamber for intel extraction."
                )
        else:
            print(
                f"[-] Warning: Critical threat source missing. Escalating to defensive quarantine."
            )
            self.audit.record_action(
                "SHADOW_NET",
                "QUARANTINE_ESCALATION",
                f"PID {target_pid} isolated without sample recovery.",
            )


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Yomi Shadow Net - eBPF Micro-Hook Surveillance."
    )
    parser.add_argument(
        "pid", type=int, help="Target PID to deploy the Shadow Net hook."
    )
    parser.add_argument(
        "--reason", default="Manual CLI Override", help="Justification for hook."
    )
    args = parser.parse_args()

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print(
            "[-] Error: Shadow Net requires root privileges (sudo) to access eBPF/Ring-0."
        )
        sys.exit(1)

    print(f"[*] Initializing The Shadow Net Engine...")
    shadow = ShadowNetProtocol()

    result = shadow.deploy_micro_hook(args.pid, args.reason)

    if result.get("status") == "DEPLOYED":
        hook_thread = result.get("thread")
        if hook_thread:
            hook_thread.join()
        print("[+] Shadow Net surveillance cycle complete.")
        sys.exit(0)
    else:
        print(f"[-] Failed to deploy hook: {result.get('message')}")
        sys.exit(1)
