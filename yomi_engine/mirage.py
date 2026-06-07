import os
import sys
import shutil
import stat

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Mirage Protocol (v4.0 - PRODUCTION)
# Purpose: Deep Deception Technology. Injects synthetic OS artifacts (honeytokens).
#          - OPSEC Hardened: Strict 0o600 file permissions to evade Honeypot detection.
#          - Self-Healing: Autonomous Orphan Sweeper prevents storage bloat.
#          - Path Traversal immunity & Headless execution.
# ==============================================================================


class MirageProtocol:
    def __init__(self):
        self.audit = ImmutableStamp()

        # Define the absolute path for the hallucinatory environment
        self.mirage_dir = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "yomi_data",
                "lazarus_chamber",
                "mirage_env",
            )
        )
        os.makedirs(self.mirage_dir, exist_ok=True)

    def sweep_orphaned_hallucinations(self):
        """
        Self-Healing Cleanup.
        Scans for leftover decoy directories from previously crashed triage sessions.
        If the target PID no longer exists in the OS, the decoy is obliterated.
        """
        try:
            for item in os.listdir(self.mirage_dir):
                item_path = os.path.join(self.mirage_dir, item)
                if os.path.isdir(item_path):
                    # Extract PID from folder name (e.g., linux_target_1234)
                    parts = item.split("_")
                    if len(parts) == 3 and parts[2].isdigit():
                        pid = parts[2]
                        # Check if process is dead (Linux-centric check)
                        if os.name == "posix" and not os.path.exists(f"/proc/{pid}"):
                            shutil.rmtree(item_path, ignore_errors=True)
                            print(f"[*] Swept orphaned hallucination directory: {item}")
        except Exception as e:
            self.audit.record_action(
                "MIRAGE", "SWEEP_ERROR", f"Failed to sweep orphans: {str(e)}"
            )

    def deploy_hallucination(
        self, target_pid: int, os_target: str = "LINUX", force_enable: bool = False
    ) -> dict:
        """
        Deploys a synthetic decoy environment. Safely type-casts to prevent path traversal.
        Uses force_enable to bypass environment variable checks during direct CLI operations.
        """
        if not force_enable and os.environ.get(
            "YOMI_ENABLE_MIRAGE_MODE", "false"
        ).lower() not in ("1", "true", "yes"):
            return {
                "status": "SKIPPED",
                "reason": "Mirage Protocol disabled via YOMI_ENABLE_MIRAGE_MODE.",
            }

        try:
            safe_pid = int(target_pid)
            if safe_pid <= 0:
                raise ValueError("PID must be a positive integer.")
        except ValueError as e:
            msg = f"Invalid PID format for Mirage Deployment: {e}"
            self.audit.record_action("MIRAGE", "ABORTED", msg)
            return {"status": "ERROR", "reason": msg}

        # Auto-clean any ghost directories before deploying a new one
        self.sweep_orphaned_hallucinations()

        print(f"[*] Deploying synthetic OS hallucination for PID {safe_pid}...")

        try:
            if os_target.upper() == "LINUX":
                env_path = self._generate_linux_mirage(safe_pid)
            else:
                env_path = self._generate_windows_mirage(safe_pid)

            msg = f"Synthetic {os_target.upper()} honeytokens deployed at {env_path}"
            print(f"[*] {msg}")
            self.audit.record_action("MIRAGE", "HALLUCINATION_DEPLOYED", msg)

            return {"status": "SUCCESS", "mirage_path": env_path}

        except Exception as e:
            error_msg = f"Failed to deploy Mirage Protocol: {str(e)}"
            self.audit.record_action("MIRAGE", "ERROR", error_msg)
            return {"status": "ERROR", "reason": error_msg}

    def teardown_hallucination(self, target_pid: int, os_target: str = "LINUX") -> bool:
        """
        Ephemeral Cleanup. Destroys the decoy environment after triage is complete.
        """
        try:
            safe_pid = int(target_pid)
            prefix = "linux" if os_target.upper() == "LINUX" else "win"
            target_path = os.path.join(self.mirage_dir, f"{prefix}_target_{safe_pid}")

            # Absolute Security Boundary Check: Ensure we only delete inside mirage_dir
            if os.path.abspath(target_path).startswith(
                self.mirage_dir
            ) and os.path.exists(target_path):
                shutil.rmtree(target_path, ignore_errors=True)
                msg = f"Decoy environment for PID {safe_pid} securely destroyed."
                print(f"[*] {msg}")
                self.audit.record_action("MIRAGE", "HALLUCINATION_TEARDOWN", msg)
                return True
            return False
        except Exception as e:
            self.audit.record_action(
                "MIRAGE", "TEARDOWN_ERROR", f"Cleanup failed: {str(e)}"
            )
            return False

    def _generate_linux_mirage(self, target_pid: int) -> str:
        """Creates fake /etc/shadow and ssh keys with STRICT OPSEC permissions."""
        linux_mirage_path = os.path.join(self.mirage_dir, f"linux_target_{target_pid}")

        os.makedirs(os.path.join(linux_mirage_path, "etc"), exist_ok=True)
        os.makedirs(os.path.join(linux_mirage_path, "root", ".ssh"), exist_ok=True)

        fake_shadow_content = """root:$6$v1kQe$DECOY.HASH.DO.NOT.USE.YOMI:19000:0:99999:7:::
sysadmin:$6$a8B9z$DECOY.HASH.DO.NOT.USE.YOMI:19000:0:99999:7:::"""

        shadow_path = os.path.join(linux_mirage_path, "etc", "shadow")
        with open(shadow_path, "w") as f:
            f.write(fake_shadow_content)
        # Lock down file permissions to root read/write only (0o600)
        os.chmod(shadow_path, stat.S_IRUSR | stat.S_IWUSR)

        fake_ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        fake_ssh_key += "b3BlbnNzaC1rZXktdjEAAAA...[DECOY_KEY]...\n"
        fake_ssh_key += "-----END OPENSSH PRIVATE KEY-----\n"

        key_path = os.path.join(linux_mirage_path, "root", ".ssh", "id_rsa")
        with open(key_path, "w") as f:
            f.write(fake_ssh_key)
        # SSH keys MUST be 0o600 or ssh/malware will reject them
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

        return linux_mirage_path

    def _generate_windows_mirage(self, target_pid: int) -> str:
        """Creates fake SAM registry hives and user documents."""
        win_mirage_path = os.path.join(self.mirage_dir, f"win_target_{target_pid}")

        os.makedirs(
            os.path.join(win_mirage_path, "Windows", "System32", "config"),
            exist_ok=True,
        )
        os.makedirs(
            os.path.join(win_mirage_path, "Users", "Administrator", "Documents"),
            exist_ok=True,
        )

        sam_path = os.path.join(win_mirage_path, "Windows", "System32", "config", "SAM")
        with open(sam_path, "w") as f:
            f.write("YOMI_DECOY_SAM_REGISTRY_HIVE_BINARY_DATA_CORRUPTION_TRAP")
        os.chmod(sam_path, stat.S_IRUSR | stat.S_IWUSR)  # System-level read/write

        doc_path = os.path.join(
            win_mirage_path,
            "Users",
            "Administrator",
            "Documents",
            "Q3_Financials_2026.docx",
        )
        with open(doc_path, "w") as f:
            f.write(
                "YOMI_DECOY_DOCUMENT_TRAP: If malware reads or encrypts this, intent is 100% malicious."
            )

        return win_mirage_path


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 mirage.py <deploy|teardown> <TARGET_PID> [OS_TARGET]")
        sys.exit(1)

    command = sys.argv[1].lower()
    try:
        target_pid = int(sys.argv[2])
    except ValueError:
        print("[-] Error: Invalid PID format.")
        sys.exit(1)

    os_target = sys.argv[3].upper() if len(sys.argv) > 3 else "LINUX"

    mirage = MirageProtocol()

    if command == "deploy":
        # Removed global os.environ mutation. Using force_enable parameter.
        result = mirage.deploy_hallucination(target_pid, os_target, force_enable=True)
        if result.get("status") == "SUCCESS":
            print(f"[+] Mirage deployed successfully: {result['mirage_path']}")
            sys.exit(0)
        else:
            print(f"[-] Mirage deployment failed/skipped: {result.get('reason')}")
            sys.exit(1)

    elif command == "teardown":
        success = mirage.teardown_hallucination(target_pid, os_target)
        if success:
            print(f"[+] Mirage environment for PID {target_pid} dismantled.")
            sys.exit(0)
        else:
            print(f"[-] Failed to dismantle environment for PID {target_pid}.")
            sys.exit(1)

    else:
        print("[-] Unknown command. Use 'deploy' or 'teardown'.")
        sys.exit(1)
