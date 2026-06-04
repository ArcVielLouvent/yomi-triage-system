import os
import time
import sys
import shutil
import threading
import tempfile
import subprocess
import signal

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Lazarus Chamber (v2.0)
# Purpose: Deep Isolation & Forced Execution Sandbox.
#          Extracts dormant or frozen malware, isolates it within a restricted
#          directory, and forcefully awakens it to monitor behavioral signatures.
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
        Safely copies the malicious binary into the isolated Lazarus Chamber.
        Strips unnecessary permissions to prevent sandbox escape.
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
            # Safely copy the artifact instead of moving, to preserve original evidence state
            shutil.copy2(binary_path, destination_path)
            # Restrict execution permissions (Chmod 0700: Owner can read/write/execute only)
            os.chmod(destination_path, 0o700)
            return destination_path
        except Exception as e:
            msg = (
                f"Failed to isolate binary {binary_path} into Lazarus Chamber: {str(e)}"
            )
            self.audit.record_action("LAZARUS", "CONTAINMENT_ERROR", msg)
            return "ERROR"

    def _create_container_overlay(self, source_path: str) -> dict:
        timestamp = int(time.time())
        base_root = os.path.join(self.chamber_dir, f"sandbox_base_{timestamp}")
        upper_dir = os.path.join(self.chamber_dir, f"sandbox_upper_{timestamp}")
        work_dir = os.path.join(self.chamber_dir, f"sandbox_work_{timestamp}")
        mount_dir = os.path.join(self.chamber_dir, f"sandbox_root_{timestamp}")

        os.makedirs(os.path.join(base_root, "bin"), exist_ok=True)
        os.makedirs(upper_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)
        os.makedirs(mount_dir, exist_ok=True)

        binary_name = os.path.basename(source_path)
        sandbox_binary = os.path.join(base_root, "bin", binary_name)
        shutil.copy2(source_path, sandbox_binary)
        os.chmod(sandbox_binary, 0o700)

        overlay_opts = f"lowerdir={base_root},upperdir={upper_dir},workdir={work_dir}"
        try:
            subprocess.run(
                ["mount", "-t", "overlay", "overlay", "-o", overlay_opts, mount_dir],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            return {
                "status": "ERROR",
                "reason": f"OverlayFS mount failed: {exc.stderr.strip() or exc.stdout.strip()}",
            }

        return {
            "status": "SUCCESS",
            "base_root": base_root,
            "upper_dir": upper_dir,
            "work_dir": work_dir,
            "mount_dir": mount_dir,
            "binary_relpath": f"/bin/{binary_name}",
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
                "reason": "Root privileges are required to create Linux namespaces and mounts.",
            }

        command = [
            "unshare",
            "-r",
            "-n",
            "-m",
            "--mount-proc",
            "chroot",
            container_info["mount_dir"],
            container_info["binary_relpath"],
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError as exc:
            return {
                "status": "ERROR",
                "reason": f"Required sandbox command missing: {str(exc)}",
            }
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
            subprocess.run(
                ["umount", mount_dir],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception:
            pass

        for path in (
            container_info.get("base_root"),
            container_info.get("upper_dir"),
            container_info.get("work_dir"),
            container_info.get("mount_dir"),
        ):
            if path:
                shutil.rmtree(path, ignore_errors=True)

    def execute_resurrection(self, target_pid: int, binary_path: str) -> dict:
        """
        The core Lazarus Protocol.
        Secures the binary in the chamber.
        """
        print(
            f"\n[YOMI-LAZARUS] [VOID BLACK] Preparing Lazarus Chamber for PID {target_pid}..."
        )

        # 1. Containment Phase
        contained_path = self._secure_containment(binary_path, target_pid)
        if contained_path == "ERROR":
            return {
                "status": "ERROR",
                "message": "Sandbox containment failed. Aborting resurrection.",
            }

        msg = f"Target binary secured inside isolation chamber: {contained_path}"
        print(f"[YOMI-LAZARUS] [PLASMA BLUE] {msg}")
        self.audit.record_action("LAZARUS", "CONTAINMENT_SUCCESS", msg)

        # 2. The Awakening (Forced Execution / Thaw)
        print(
            f"[YOMI-LAZARUS] [BLOOD RED] Initiating forced resurrection (SIGCONT) on PID {target_pid}..."
        )

        use_minicontainer = os.environ.get("YOMI_USE_MINI_CONTAINER", "true").lower() in (
            "1",
            "true",
            "yes",
        )

        if use_minicontainer:
            container_info = self._create_container_overlay(contained_path)
            if container_info.get("status") != "SUCCESS":
                return {
                    "status": "ERROR",
                    "message": container_info.get("reason", "Failed to create sandbox overlay."),
                }

            launch_result = self._launch_in_minicontainer(container_info)
            if launch_result.get("status") != "SUCCESS":
                return {
                    "status": "ERROR",
                    "message": launch_result.get("reason", "Failed to launch mini-container."),
                }

            sandbox_pid = launch_result["pid"]
            self.active_sandboxes[sandbox_pid] = container_info["mount_dir"]
            self.audit.record_action(
                "LAZARUS",
                "RESURRECTION_ACTIVE",
                f"PID {sandbox_pid} started in mini-container for observation.",
            )

            monitoring_thread = threading.Thread(
                target=self._monitor_awakened_threat,
                args=(sandbox_pid, contained_path, container_info, launch_result["process"]),
                daemon=True,
            )
            monitoring_thread.start()

            return {
                "status": "SUCCESS",
                "sandbox_pid": sandbox_pid,
                "chamber_path": contained_path,
            }
        thaw_result = self.os_bridge.thaw_process(target_pid)
        if thaw_result.get("status") == "SUCCESS":
            print(
                f"[YOMI-LAZARUS] [CYBER-PURPLE] Target PID {target_pid} awakened. Commencing behavioral monitoring..."
            )
            self.active_sandboxes[target_pid] = contained_path
            self.audit.record_action(
                "LAZARUS",
                "RESURRECTION_ACTIVE",
                f"PID {target_pid} successfully thawed for observation.",
            )

            monitoring_thread = threading.Thread(
                target=self._monitor_awakened_threat,
                args=(target_pid, contained_path, None, None),
                daemon=True,
            )
            monitoring_thread.start()

            return {"status": "SUCCESS", "chamber_path": contained_path}

        error_msg = thaw_result.get("reason", "Unknown thawing error")
        print(f"[YOMI-LAZARUS] [ERROR] Resurrection failed: {error_msg}")
        self.audit.record_action("LAZARUS", "RESURRECTION_FAILED", error_msg)
        return {"status": "ERROR", "message": error_msg}

    def _monitor_awakened_threat(self, target_pid: int, contained_path: str, container_info=None, process=None):
        """
        Background daemon observing the awakened sample inside the sandbox.
        AUTONOMOUSLY TRIGGERS The Mirage Protocol and Mind-Reader Decompiler!
        """
        # Dynamic import to prevent circular dependencies
        from yomi_engine.mirage import MirageProtocol
        from yomi_engine.mind_reader import MindReaderDecompiler

        print(
            f"\n[YOMI-LAZARUS] [PLASMA BLUE] Commencing Autonomous Interrogation on PID {target_pid}..."
        )
        time.sleep(2)  # Let the sample initialize inside the container

        if process is not None:
            try:
                while process.poll() is None:
                    time.sleep(1)
            except Exception:
                pass

        # 1. Optionally deploy Mirage Protocol (Honeytokens) only if explicitly enabled
        if os.environ.get("YOMI_ENABLE_MIRAGE_MODE", "false").lower() in (
            "1",
            "true",
            "yes",
        ):
            mirage = MirageProtocol()
            mirage.deploy_hallucination(target_pid, os_target="LINUX")
            time.sleep(2)  # Let the sample interact with the decoy environment
        else:
            print(
                "[YOMI-LAZARUS] [CYBER-PURPLE] Mirage Protocol disabled. Skipping decoy deployment."
            )

        # 2. Trigger Mind-Reader Decompiler (Reverse Engineering)
        print(
            f"[YOMI-LAZARUS] [VOID BLACK] Executing Mind-Reader Profiling..."
        )
        decompiler = MindReaderDecompiler()
        decompiler.decompile_and_profile(contained_path, target_pid)

        if container_info:
            self._cleanup_container(container_info)
            self.audit.record_action(
                "LAZARUS",
                "CONTAINER_CLEANUP",
                f"Cleaned up mini-container for PID {target_pid}.",
            )

        print(f"[YOMI-LAZARUS] [CYBER-PURPLE] Autonomous Interrogation Complete.")



