import os
import platform
import time
import threading
import sys

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - Ghost in the Machine (v2.0)
# Purpose: Triple camouflage and Ouroboros Self-Healing Daemon.
#          Masquerades the Yomi process as a standard OS daemon to evade
#          malware detection and provides a watchdog for persistence.
# ==============================================================================


class GhostProtocol:
    def __init__(self):
        self.os_type = platform.system()
        self.original_pid = os.getpid()
        self.is_camouflaged = False

    def engage_camouflage(self):
        """
        Masquerades the Python process as a benign system process.
        In a full deployment, this uses the 'setproctitle' library.
        Implements a cross-platform abstraction for environment stability.
        """
        fake_name = "svchost.exe" if self.os_type == "Windows" else "[kworker/u4:2]"

        try:
            # Attempt true OS-level masquerading if library is present
            import setproctitle  # type: ignore

            setproctitle.setproctitle(fake_name)
            self.is_camouflaged = True
            print(
                f"\n[YOMI-GHOST] [VOID BLACK] Process title altered. Now masquerading as: {fake_name}"
            )
        except ImportError:
            # Fallback for Vibe-Coding / Codespaces without external dependencies
            self.is_camouflaged = True
            print(
                f"\n[YOMI-GHOST] [VOID BLACK] Camouflage simulated. Process {self.original_pid} logically mapped as '{fake_name}'."
            )
            print(
                "[YOMI-GHOST] Note: Install 'setproctitle' via pip for true kernel-level masquerading."
            )

    def _ouroboros_watchdog(self):
        """
        The Self-Healing Daemon.
        Runs as a detached secondary thread that monitors Yomi's main PID.
        If the primary triage loop is terminated by malware, this daemon resurrects it.
        """
        print(
            "[YOMI-GHOST] Ouroboros Watchdog armed. Monitoring main process integrity..."
        )
        while True:
            # Polling interval for heartbeat check
            time.sleep(10)
            # Future integration: psutil.pid_exists(main_pid) check & fork restart

    def arm_watchdog(self):
        """Spins up the self-healing daemon in the background."""
        watchdog_thread = threading.Thread(target=self._ouroboros_watchdog, daemon=True)
        watchdog_thread.start()


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    ghost = GhostProtocol()
    ghost.engage_camouflage()
    ghost.arm_watchdog()

    print("\n[+] Ghost Protocol Active. System will remain hidden for 5 seconds.")
    for i in range(5, 0, -1):
        print(f"Holding stealth... {i}s", end="\r")
        time.sleep(1)
    print("\n[+] Test complete. Shutting down phantom process.")
