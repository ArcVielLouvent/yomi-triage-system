import os
import sys
import time
import json

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Mirage Protocol (v2.0)
# Purpose: Deep Deception Technology. Injects synthetic OS artifacts (honeytokens)
#          into the Lazarus Chamber. Tricks anti-analysis malware into believing
#          it has successfully compromised a high-value production server,
#          forcing it to unpack its payload.
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

    def deploy_hallucination(self, target_pid: int, os_target: str = "LINUX") -> dict:
        """
        Deploys a synthetic decoy environment only when Mirage mode is explicitly enabled.
        """
        if os.environ.get("YOMI_ENABLE_MIRAGE_MODE", "false").lower() not in (
            "1",
            "true",
            "yes",
        ):
            return {
                "status": "SKIPPED",
                "reason": "Mirage Protocol is disabled. Set YOMI_ENABLE_MIRAGE_MODE=true to enable.",
            }

        print(
            f"\n[YOMI-MIRAGE] [CYBER-PURPLE] Generating synthetic OS hallucination for PID {target_pid}..."
        )

        try:
            if os_target.upper() == "LINUX":
                env_path = self._generate_linux_mirage(target_pid)
            else:
                env_path = self._generate_windows_mirage(target_pid)

            msg = f"Mirage Protocol activated. Synthetic {os_target} honeytokens deployed at {env_path}"
            print(f"[YOMI-MIRAGE] [PLASMA BLUE] {msg}")
            self.audit.record_action("MIRAGE", "HALLUCINATION_DEPLOYED", msg)

            return {"status": "SUCCESS", "mirage_path": env_path}

        except Exception as e:
            error_msg = f"Failed to deploy Mirage Protocol: {str(e)}"
            self.audit.record_action("MIRAGE", "ERROR", error_msg)
            return {"status": "ERROR", "reason": error_msg}

    def _generate_linux_mirage(self, target_pid: int) -> str:
        """Creates fake /etc/shadow, ssh keys, and bash history to bait the malware."""
        linux_mirage_path = os.path.join(self.mirage_dir, f"linux_target_{target_pid}")

        # Create standard Linux folder structures
        os.makedirs(os.path.join(linux_mirage_path, "etc"), exist_ok=True)
        os.makedirs(os.path.join(linux_mirage_path, "root", ".ssh"), exist_ok=True)

        # 1. Deceptive /etc/shadow (Bait for credential dumpers)
        fake_shadow_content = """root:$6$v1kQe$DECOY.HASH.DO.NOT.USE.YOMI:19000:0:99999:7:::
sysadmin:$6$a8B9z$DECOY.HASH.DO.NOT.USE.YOMI:19000:0:99999:7:::"""

        with open(os.path.join(linux_mirage_path, "etc", "shadow"), "w") as f:
            f.write(fake_shadow_content)

        # 2. Deceptive SSH Keys (Bait for lateral movement/worming)
        fake_ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        fake_ssh_key += "b3BlbnNzaC1rZXktdjEAAAA...[DECOY_KEY]...\n"
        fake_ssh_key += "-----END OPENSSH PRIVATE KEY-----\n"
        with open(os.path.join(linux_mirage_path, "root", ".ssh", "id_rsa"), "w") as f:
            f.write(fake_ssh_key)

        return linux_mirage_path

    def _generate_windows_mirage(self, target_pid: int) -> str:
        """Creates fake SAM registry hives and user documents."""
        win_mirage_path = os.path.join(self.mirage_dir, f"win_target_{target_pid}")

        # Create standard Windows folder structures
        os.makedirs(
            os.path.join(win_mirage_path, "Windows", "System32", "config"),
            exist_ok=True,
        )
        os.makedirs(
            os.path.join(win_mirage_path, "Users", "Administrator", "Documents"),
            exist_ok=True,
        )

        # 1. Deceptive SAM Hive (Bait for Mimikatz/hash dumpers)
        with open(
            os.path.join(win_mirage_path, "Windows", "System32", "config", "SAM"), "w"
        ) as f:
            f.write("YOMI_DECOY_SAM_REGISTRY_HIVE_BINARY_DATA_CORRUPTION_TRAP")

        # 2. Deceptive High-Value Data (Bait for Ransomware encryption)
        with open(
            os.path.join(
                win_mirage_path,
                "Users",
                "Administrator",
                "Documents",
                "Q3_Financials_2026.docx",
            ),
            "w",
        ) as f:
            f.write(
                "YOMI_DECOY_DOCUMENT_TRAP: If malware reads or encrypts this, intent is 100% malicious."
            )

        return win_mirage_path


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    print("\n[+] Initializing The Mirage Protocol...")
    mirage = MirageProtocol()

    # Test Linux Deception
    target_pid_linux = int(os.environ.get("YOMI_MIRAGE_TARGET_PID_LINUX", "9999"))
    linux_result = mirage.deploy_hallucination(target_pid_linux, "LINUX")

    # Test Windows Deception
    target_pid_win = int(os.environ.get("YOMI_MIRAGE_TARGET_PID_WINDOWS", "9998"))
    win_result = mirage.deploy_hallucination(target_pid_win, "WINDOWS")

    print("\n[+] Verification:")
    print(f"Linux Trap Deployed : {linux_result['mirage_path']}")
    print(f"Windows Trap Deployed: {win_result['mirage_path']}")
    print(
        "[+] Check your 'yomi_data/lazarus_chamber/mirage_env' folder to see the fake OS files!"
    )
