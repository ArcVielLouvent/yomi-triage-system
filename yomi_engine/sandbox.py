import os
import time
import sys
import shutil
import threading
import subprocess
import signal
import stat

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Lazarus Chamber (v4.0 - PRODUCTION)
# Purpose: Deep Isolation & Forced Execution Sandbox.
#          - Hardened Kernel Namespaces (No -r to prevent UID map escape).
#          - Deterministic Thread Synchronization (Anti-Daemon death).
#          - Pristine Evidence Preservation (0o400 strict locks).
# ==============================================================================


class SandboxEnvironment:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.os_bridge = OSBridge()

        # Define the absolute path for the isolation chamber
        self.chamber_dir = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "yomi_data", "lazarus_chamber"
            )
        )
        os.makedirs(self.chamber_dir, exist_ok=True)
        self.active_sandboxes = {}

    def _validate_binary_path(self, binary_path: str) -> tuple[bool, str]:
        if not isinstance(binary_path, str) or not binary_path:
            return False, "Invalid binary path supplied."
        if not os.path.isabs(binary_path):
            return False, "Binary path must be absolute."
        if not os.path.exists(binary_path):
            return False, f"Binary path does not exist: {binary_path}"
        if not os.path.isfile(binary_path):
            return False, f"Binary path is not a regular file: {binary_path}"
        return True, ""

    def _secure_containment(self, binary_path: str, threat_pid: int) -> str:
        """
        Safely copies the malicious binary.
        Sets the pristine forensic copy to READ-ONLY (0o400)
        so even if a sandbox escape occurs, the malware cannot easily tamper with its own evidence.
        """
        timestamp = int(time.time())
        safe_filename = f"isolated_target_{threat_pid}_{timestamp}.bin"
        destination_path = os.path.join(self.chamber_dir, safe_filename)

        is_valid, error = self._validate_binary_path(binary_path)
        if not is_valid:
            msg = f"Sandbox containment aborted: {error}"
            self.audit.record_action("LAZARUS", "CONTAINMENT_ERROR", msg)
            return "ERROR"

        try:
            shutil.copy2(binary_path, destination_path)
            # Pristine Copy: Read-only for owner, inaccessible to others
            os.chmod(destination_path, 0o400)
            return destination_path
        except Exception as e:
            msg = (
                f"Failed to isolate binary {binary_path} into Lazarus Chamber: {str(e)}"
            )
            self.audit.record_action("LAZARUS", "CONTAINMENT_ERROR", msg)
            return "ERROR"

    def _create_container_overlay(self, source_path: str) -> dict:
        """
        Host-Mirroring Overlay. Gives dynamic malware access to read libc,
        but traps all writes/encryptions in the disposable upper_dir.
        """
        timestamp = int(time.time())
        upper_dir = os.path.join(self.chamber_dir, f"sandbox_upper_{timestamp}")
        work_dir = os.path.join(self.chamber_dir, f"sandbox_work_{timestamp}")
        mount_dir = os.path.join(self.chamber_dir, f"sandbox_root_{timestamp}")

        os.makedirs(upper_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)
        os.makedirs(mount_dir, exist_ok=True)

        # Create an EXECUTABLE copy inside the upperdir for the malware to run from
        sandbox_binary_dir = os.path.join(upper_dir, "opt", "yomi_sandbox")
        os.makedirs(sandbox_binary_dir, exist_ok=True)

        binary_name = os.path.basename(source_path)
        sandbox_binary = os.path.join(sandbox_binary_dir, binary_name)
        shutil.copy2(source_path, sandbox_binary)
        os.chmod(sandbox_binary, 0o700)  # Execution permitted inside sandbox

        overlay_opts = f"lowerdir=/,upperdir={upper_dir},workdir={work_dir}"
        try:
            subprocess.run(
                ["mount", "-t", "overlay", "overlay", "-o", overlay_opts, mount_dir],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            return {
                "status": "ERROR",
                "reason": f"OverlayFS mount failed: {exc.stderr.strip()}",
            }

        return {
            "status": "SUCCESS",
            "upper_dir": upper_dir,
            "work_dir": work_dir,
            "mount_dir": mount_dir,
            "binary_relpath": f"/opt/yomi_sandbox/{binary_name}",
        }

    def _launch_in_minicontainer(self, container_info: dict) -> dict:
        if self.os_bridge.os_type != "Linux":
            return {
                "status": "ERROR",
                "reason": "Mini-container sandboxing is only supported on Linux hosts.",
            }

        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return {
                "status": "ERROR",
                "reason": "Root privileges are required to create Linux namespaces.",
            }

        # Removed -r to prevent container escape via pseudo-root mappings.
        # Relying purely on hard namespaces (-n, -m, -p, -f) while running as true root.
        command = [
            "unshare",
            "-n",
            "-m",
            "-p",
            "-f",
            "--mount-proc",
            "chroot",
            container_info["mount_dir"],
            container_info["binary_relpath"],
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
        except Exception as exc:
            return {"status": "ERROR", "reason": str(exc)}

        return {
            "status": "SUCCESS",
            "pid": process.pid,
            "process": process,
            "mount_dir": container_info["mount_dir"],
            "container_info": container_info,
        }

    def _cleanup_container(self, container_info: dict) -> None:
        mount_dir = container_info.get("mount_dir")
        try:
            subprocess.run(["umount", "-l", mount_dir], check=True, capture_output=True)
        except Exception:
            pass

        for path in (
            container_info.get("upper_dir"),
            container_info.get("work_dir"),
            container_info.get("mount_dir"),
        ):
            if path and os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)

    def execute_resurrection(self, target_pid: int, binary_path: str) -> dict:
        """
        Secures the binary and detonates it safely.
        Returns the monitoring thread object for synchronization.
        """
        print(f"[*] Preparing Lazarus Chamber for PID {target_pid}...")

        contained_path = self._secure_containment(binary_path, target_pid)
        if contained_path == "ERROR":
            return {"status": "ERROR", "message": "Sandbox containment failed."}

        print(f"[*] Target binary secured (Forensic Pristine Copy): {contained_path}")
        self.audit.record_action(
            "LAZARUS", "CONTAINMENT_SUCCESS", f"Secured at {contained_path}"
        )

        print(f"[*] Initiating forced execution (Detonation) in Mini-Container...")

        container_info = self._create_container_overlay(contained_path)
        if container_info.get("status") != "SUCCESS":
            return {
                "status": "ERROR",
                "message": container_info.get("reason", "Overlay failed."),
            }

        launch_result = self._launch_in_minicontainer(container_info)
        if launch_result.get("status") != "SUCCESS":
            self._cleanup_container(container_info)
            return {
                "status": "ERROR",
                "message": launch_result.get("reason", "Launch failed."),
            }

        sandbox_pid = launch_result["pid"]
        self.active_sandboxes[sandbox_pid] = container_info["mount_dir"]
        self.audit.record_action(
            "LAZARUS",
            "RESURRECTION_ACTIVE",
            f"Detonated in isolated PID namespace {sandbox_pid}.",
        )

        # Spawn the monitoring thread
        monitoring_thread = threading.Thread(
            target=self._monitor_awakened_threat,
            args=(
                target_pid,
                sandbox_pid,
                contained_path,
                container_info,
                launch_result["process"],
            ),
            daemon=True,
        )
        monitoring_thread.start()

        return {
            "status": "SUCCESS",
            "sandbox_pid": sandbox_pid,
            "chamber_path": contained_path,
            "thread": monitoring_thread,  # Return thread for precise joining
        }

    def _monitor_awakened_threat(
        self, original_pid, sandbox_pid, contained_path, container_info, process
    ):
        # [FIXED] Found during Fase 6 demo-scenario testing, same bug class
        # as known_issues.md #26: this method used to call MirageProtocol()
        # and MindReaderDecompiler() unconditionally, completely bypassing
        # module_registry -- so disabling MIRAGE or MIND_READER via
        # YOMI_MODULE_MIRAGE=false / YOMI_MODULE_MIND_READER=false had no
        # effect on this post-detonation re-analysis pass (it's a SEPARATE
        # call site from GuardianOrchestrator's own pre-detonation
        # dispatch, which DOES respect the registry). See known_issues.md
        # #29.
        from yomi_core import module_registry

        active = module_registry.resolve_active_modules()
        mirage_enabled = "MIRAGE" in active
        mind_reader_enabled = "MIND_READER" in active

        print(
            f"[*] Commencing Autonomous Interrogation on Sandbox PID {sandbox_pid}..."
        )

        mirage = None
        if mirage_enabled:
            from yomi_engine.mirage import MirageProtocol

            mirage = MirageProtocol()
            mirage.deploy_hallucination(original_pid, os_target="LINUX", force_enable=True)

        try:
            process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            print(
                f"[*] Detonation time window closed. Terminating Sandbox PID {sandbox_pid}."
            )
            try:
                pgid = os.getpgid(process.pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                pass
            process.communicate()
        except Exception:
            pass

        time.sleep(0.5)
        if mirage is not None:
            mirage.teardown_hallucination(original_pid, os_target="LINUX")

        if os.path.exists(contained_path):
            os.chmod(contained_path, 0o500)

        if mind_reader_enabled:
            from yomi_engine.mind_reader import MindReaderDecompiler

            print(f"[*] Executing Mind-Reader Profiling on pristine forensic copy...")
            decompiler = MindReaderDecompiler()
            decompiler.decompile_and_profile(contained_path, original_pid)
        else:
            print(
                "[*] MIND_READER is disabled in the module registry -- "
                "skipping post-detonation profiling."
            )

        self._cleanup_container_forceful(container_info)
        self.audit.record_action(
            "LAZARUS",
            "CONTAINER_DESTROYED",
            f"Chamber for PID {original_pid} obliterated.",
        )
        print(f"[*] Autonomous Interrogation Complete.")

    def _cleanup_container_forceful(self, container_info: dict) -> None:
        """ Forced Unmount to prevent Orphaned Mount Points."""
        mount_dir = container_info.get("mount_dir")
        try:
            # -f (Force) unmounts even if busy
            subprocess.run(
                ["umount", "-f", "-l", mount_dir], check=True, capture_output=True
            )
        except Exception:
            pass

        for path in (
            container_info.get("upper_dir"),
            container_info.get("work_dir"),
            container_info.get("mount_dir"),
        ):
            if path and os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 sandbox.py <TARGET_PID> <BINARY_PATH>")
        sys.exit(1)

    try:
        pid_input = int(sys.argv[1])
    except ValueError:
        print("[-] Invalid PID format.")
        sys.exit(1)

    bin_path = sys.argv[2]

    if os.geteuid() != 0:
        print(
            "[-] Error: Lazarus Chamber requires root privileges (sudo) to create kernel namespaces."
        )
        sys.exit(1)

    sandbox = SandboxEnvironment()
    result = sandbox.execute_resurrection(pid_input, bin_path)

    if result.get("status") == "SUCCESS":
        print(
            "[+] Lazarus Chamber sequence activated successfully. Monitoring in background (15s timeout + Analysis)."
        )

        # Deterministic Thread Synchronization.
        # Wait exactly as long as the background daemon needs to finish (no hardcoded sleep).
        monitoring_thread = result.get("thread")
        if monitoring_thread:
            monitoring_thread.join()

        sys.exit(0)
    else:
        print(f"[-] Lazarus sequence failed: {result.get('message')}")
        sys.exit(1)
