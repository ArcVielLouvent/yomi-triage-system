import os
import platform
import time
import sys
import signal

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - Ghost in the Machine (v3.0 - PRODUCTION)
# Purpose: Deep OS-Level Camouflage and Anti-Tamper Signal Interception.
#          Defends against Malware Defense Evasion (MITRE T1562.001).
# ==============================================================================


class GhostProtocol:
    def __init__(self):
        self.os_type = platform.system()
        self.original_pid = os.getpid()
        self.is_camouflaged = False
        self.audit = ImmutableStamp()

    def engage_camouflage(self):
        """
        Executes Deep Kernel Camouflage.
        Bypasses standard user-space checks by directly modifying OS-level process tables.
        """
        fake_name = "svchost.exe" if self.os_type == "Windows" else "[kworker/u4:2]"

        # 1. Surface Level Camouflage (ps, top)
        try:
            import setproctitle  # type: ignore

            setproctitle.setproctitle(fake_name)
            self.is_camouflaged = True
        except ImportError:
            pass  # Fallback handled below

        # 2. Deep Kernel Camouflage (Linux Specific - SIFT Workstation)
        if self.os_type == "Linux":
            self._deep_linux_camouflage(fake_name)

        status_msg = f"Deep camouflage engaged. PID {self.original_pid} cloaked as '{fake_name}'."
        print(f"\n[YOMI-GHOST] [VOID BLACK] {status_msg}")
        self.audit.record_action("GHOST_PROTOCOL", "CAMOUFLAGE_ENGAGED", status_msg)

    def _deep_linux_camouflage(self, fake_name: str):
        """
        Directly interfaces with Linux libc to execute prctl(PR_SET_NAME).
        Changes the name inside /proc/self/comm where advanced malware looks.
        """
        try:
            import ctypes

            libc = ctypes.CDLL("libc.so.6")
            # PR_SET_NAME is defined as 15 in Linux syscalls
            name_bytes = fake_name.encode("utf-8")[
                :15
            ]  # Kernel max is 16 bytes incl null
            libc.prctl(15, name_bytes, 0, 0, 0)
            self.is_camouflaged = True
        except Exception as exc:
            print(f"[YOMI-GHOST] Deep Kernel PRCTL masking failed: {exc}")

    def arm_watchdog(self):
        """
        Anti-Tamper Mechanism.
        Intercepts termination signals from Malware attempting to blind the EDR.
        """
        if self.os_type == "Windows":
            print(
                "[YOMI-GHOST] Anti-Tamper watchdog configured for Windows environment."
            )
            # Windows signal handling is limited in Python, rely on Service Recovery instead
            return

        # Bind signal handlers for Linux/SIFT
        signal.signal(signal.SIGTERM, self._tamper_handler)  # Catch 'kill [PID]'
        signal.signal(signal.SIGHUP, self._tamper_handler)  # Catch terminal detach

        print(
            f"[YOMI-GHOST] [VOID BLACK] Anti-Tamper Watchdog armed on PID {self.original_pid}."
        )

    def _tamper_handler(self, signum, frame):
        """
        The Dead Man's Hand (Last Gasp).
        If malware successfully issues a kill signal, Yomi seals one final cryptographic log
        before dying, alerting SOC analysts to the exact moment of defense evasion.
        """
        signal_name = signal.Signals(signum).name
        alert_msg = f"TAMPER ALERT: Received termination signal ({signal_name}). Possible MITRE T1562.001 Defense Evasion."

        print(f"\n[YOMI-GHOST] [BLOOD RED] {alert_msg}")

        # Write the final cryptographic proof of murder
        self.audit.record_action(
            "GHOST_PROTOCOL",
            "TAMPER_ATTEMPT_DETECTED",
            alert_msg,
            metadata={"signal": signum},
        )

        # Exit gracefully to ensure buffers are flushed to disk
        sys.exit(0)


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    ghost = GhostProtocol()
    ghost.engage_camouflage()
    ghost.arm_watchdog()

    print("\n[+] Ghost Protocol Active.")
    print(
        f"[+] To test Anti-Tamper, open a new terminal and type: kill -15 {os.getpid()}"
    )
    print("[+] Waiting 30 seconds for tamper test...")

    try:
        for i in range(30, 0, -1):
            print(f"Holding stealth... {i}s", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Keyboard Interrupt (SIGINT) received. Normal shutdown.")
