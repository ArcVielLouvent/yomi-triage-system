import os
import sys
import time
import argparse
import threading
import platform
import subprocess
import json

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_core.sentinel import SentinelDaemon
from yomi_core.dashboard import YomiDashboard
from yomi_core.ghost import GhostProtocol
from rich.live import Live

# ==============================================================================
# YOMI TRIAGE SYSTEM: Phase 6.2 - The Final Wrap (CLI Entry Point)
# Purpose: The absolute command center. Handles Air-Gapped execution,
#          Boot Persistence (Startup), and TUI/Sentinel Threading.
# ==============================================================================


def install_persistence():
    """Installs Yomi into OS Startup sequence (Always Active)"""
    os_name = platform.system()
    print("\n[YOMI-INSTALLER] [VOID BLACK] Initiating OS-Level Boot Persistence...")

    if os_name == "Linux":
        # Systemd installation for SIFT/Linux
        service_path = "/etc/systemd/system/yomi-triage.service"
        script_path = os.path.abspath(sys.argv[0])
        service_content = f"""[Unit]
Description=Yomi Autonomous DFIR Engine
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {script_path} --auto --headless
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
"""
        try:
            with open("yomi-triage.service", "w") as f:
                f.write(service_content)
            print(
                "[YOMI-INSTALLER] [PLASMA BLUE] systemd service generated. (Run as root to mv to /etc/systemd/system/)"
            )
        except Exception as e:
            print(f"[YOMI-INSTALLER] [BLOOD RED] Failed to create Linux service: {e}")

    elif os_name == "Windows":
        # Registry installation for Windows
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            script_path = os.path.abspath(sys.argv[0])
            winreg.SetValueEx(
                key,
                "YomiTriageSystem",
                0,
                winreg.REG_SZ,
                f'"{sys.executable}" "{script_path}" --auto --headless',
            )
            winreg.CloseKey(key)
            print(
                "[YOMI-INSTALLER] [PLASMA BLUE] Windows Registry persistence established."
            )
        except Exception as e:
            print(
                f"[YOMI-INSTALLER] [BLOOD RED] Failed to create Windows registry key: {e}"
            )


def start_sentinel_thread():
    """Runs the infinite Sentinel triage loop in a separate background thread."""
    sentinel = SentinelDaemon()
    # Suppress standard print outputs so it doesn't break the Rich TUI
    sys.stdout = open(os.devnull, "w")
    sentinel.start()


def get_latest_ledger_log() -> dict:
    """Reads the last line of the immutable ledger to update the TUI."""
    log_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "yomi_data",
            "audit_logs",
            "cryptographic_ledger.jsonl",
        )
    )
    if not os.path.exists(log_path):
        return {}
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()
            if lines:
                return json.loads(lines[-1].strip())
    except:
        pass
    return {}


def main():
    parser = argparse.ArgumentParser(description="Yomi Triage System - Autonomous DFIR")
    parser.add_argument(
        "--auto", action="store_true", help="Launch full autonomous triage mode"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install boot persistence (Always Active)",
    )
    parser.add_argument(
        "--headless", action="store_true", help="Run without UI (for background daemon)"
    )
    args = parser.parse_args()

    # 1. INSTALL PERSISTENCE MODE
    if args.install:
        install_persistence()
        sys.exit(0)

    # 2. AUTONOMOUS TRIAGE MODE
    # 2. AUTONOMOUS TRIAGE MODE
    if args.auto:
        # Check Air-Gapped Status (Internet connectivity)
        print("[*] Checking network state for Air-Gapped deployment...")
        # (Yomi's library.py already handles silent failovers if this fails)

        # Fire up the Ghost Protocol (Camouflage & Ouroboros Daemon)
        ghost = GhostProtocol()
        ghost.engage_camouflage()  # [!] REVISI: Mengubah deploy_ menjadi engage_

        # Launch Sentinel Loop in the background
        sentinel_thread = threading.Thread(target=start_sentinel_thread, daemon=True)
        sentinel_thread.start()

        if args.headless:
            # If running as systemd service, just keep the main thread alive silently
            while True:
                time.sleep(10)

        # Re-route stdout back to normal for the UI
        sys.stdout = sys.__stdout__

        # Launch The Obsidian Torii Gateway (Foreground TUI)
        tui = YomiDashboard()
        last_hash = ""

        try:
            with Live(tui.render_layout(), refresh_per_second=4, screen=True) as live:
                while True:
                    # Sync TUI with the background Sentinel via the Cryptographic Ledger
                    latest_log = get_latest_ledger_log()
                    if latest_log and latest_log.get("previous_hash") != last_hash:
                        last_hash = latest_log.get("previous_hash")

                        action = latest_log.get("action", "SYSTEM_UPDATE")
                        desc = latest_log.get("description", "")

                        # Dynamic Color/Status logic for TUI
                        status = "SAFE"
                        if "FREEZE" in action or "CRITICAL" in desc:
                            status = "CRITICAL"
                        elif "SHADOW" in action or "MIRAGE" in desc:
                            status = "DECEPTION"
                        elif "DOUBT" in action or "ANOMALY" in action:
                            status = "WARNING"

                        tui.update_state(status, "AUTO", f"[{action}] {desc}")
                        live.update(tui.render_layout())

                    time.sleep(0.5)
        except KeyboardInterrupt:
            print(
                "\n[+] Obsidian Torii Gateway closed. Sentinel continues in the background if Ouroboros is active."
            )
            sys.exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
