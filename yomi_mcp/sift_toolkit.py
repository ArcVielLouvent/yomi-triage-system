import subprocess
import os
import sys

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - SIFT Toolkit (Elite 5 Arsenal)
# Purpose: Type-Safe Python wrappers for executing SIFT forensics tools.
#          Enforces Anti-Spoliation by strictly defining allowed commands.
# ==============================================================================


class SiftArsenal:
    def __init__(self):
        self.os_bridge = OSBridge()
        # Dependency injection complete. Mock status is natively handled by OSBridge.

    def _run_subprocess(self, command_list: list, tool_name: str) -> dict:
        """
        Executes a command safely without shell=True to prevent injection.
        """
        try:
            print(f"\n[YOMI-ARSENAL] Executing {tool_name} constraint protocol...")
            result = subprocess.run(
                command_list,
                capture_output=True,
                text=True,
                timeout=30,  # Prevent hanging processes
            )

            if result.returncode == 0:
                # Limit output to 1000 chars for LLM context window stability
                return {
                    "status": "SUCCESS",
                    "tool": tool_name,
                    "output": result.stdout[:1000],
                }
            else:
                return {"status": "ERROR", "tool": tool_name, "error": result.stderr}

        except FileNotFoundError:
            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": f"{tool_name} binary not found in system PATH.",
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": f"{tool_name} execution timed out.",
            }
        except Exception as e:
            return {"status": "ERROR", "tool": tool_name, "error": str(e)}

    # -------------------------------------------------------------------------
    # 1. VOLATILITY 3 WRAPPER (Memory Forensics)
    # -------------------------------------------------------------------------
    def run_volatility_netscan(self, memory_dump_path: str) -> dict:
        """
        Type-Safe execution of Volatility netscan to find rogue C2 connections.
        """
        if self.os_bridge.is_mock_mode():
            print(
                "[YOMI-ARSENAL] [MOCK MODE] Simulating Volatility netscan for development..."
            )
            return {
                "status": "MOCK_SUCCESS",
                "tool": "volatility_netscan",
                "output": "Offset(V)  Local Address  Foreign Address  State  PID  Owner\n0x9812  10.0.0.5:4444  103.45.0.0:80  ESTABLISHED  4092  sshd",
            }

        cmd = ["vol.py", "-f", memory_dump_path, "windows.netscan.NetScan"]
        return self._run_subprocess(cmd, "volatility")

    # -------------------------------------------------------------------------
    # 2. RADARE2 WRAPPER (Binary Decompilation / Mind-Reader)
    # -------------------------------------------------------------------------
    def run_radare2_analysis(self, binary_path: str) -> dict:
        """
        Type-Safe execution of Radare2 to extract strings and assembly intel.
        """
        if self.os_bridge.is_mock_mode():
            print(
                "[YOMI-ARSENAL] [MOCK MODE] Simulating Radare2 Decompilation for development..."
            )
            return {
                "status": "MOCK_SUCCESS",
                "tool": "radare2",
                "output": "0x00401000  call sym.imp.socket\n0x00401005  push str.103.45.0.0\n0x0040100a  call sym.imp.connect",
            }

        cmd = ["r2", "-q", "-c", "iz", binary_path]
        return self._run_subprocess(cmd, "radare2")

    # -------------------------------------------------------------------------
    # 3. PLASO WRAPPER (Timeline Forensics)
    # -------------------------------------------------------------------------
    def run_plaso_timeline(self, target_drive_path: str) -> dict:
        """Type-Safe execution of Log2Timeline to build temporal super-timelines."""
        if self.os_bridge.is_mock_mode():
            print(
                "[YOMI-ARSENAL] [MOCK MODE] Simulating Plaso Log2Timeline generation..."
            )
            return {
                "status": "MOCK_SUCCESS",
                "tool": "plaso",
                "output": "2026-05-30T12:00:01Z,EVTX,Security,4624,Logon Success,User: Hacker",
            }

        # Safe array command, prevents shell injection
        cmd = [
            "log2timeline.py",
            "--parsers",
            "win7",
            "/tmp/timeline.plaso",
            target_drive_path,
        ]
        return self._run_subprocess(cmd, "plaso")

    # -------------------------------------------------------------------------
    # 4. THE SLEUTH KIT WRAPPER (Disk & Hidden Artifacts)
    # -------------------------------------------------------------------------
    def run_tsk_fls(self, image_path: str) -> dict:
        """Type-Safe execution of TSK 'fls' to recover deleted files/MFT entries."""
        if self.os_bridge.is_mock_mode():
            print("[YOMI-ARSENAL] [MOCK MODE] Simulating TSK deleted file recovery...")
            return {
                "status": "MOCK_SUCCESS",
                "tool": "tsk",
                "output": "d/d * 1234: /Windows/System32/config/SAM\nr/r * 9999: /Temp/mimikatz.exe",
            }

        cmd = ["fls", "-r", "-p", image_path]
        return self._run_subprocess(cmd, "tsk")

    # -------------------------------------------------------------------------
    # 5. TSHARK WRAPPER (Network PCAP Analysis)
    # -------------------------------------------------------------------------
    def run_tshark_pcap(self, pcap_path: str) -> dict:
        """Type-Safe execution of TShark to detect C2 Beaconing in network captures."""
        if self.os_bridge.is_mock_mode():
            print("[YOMI-ARSENAL] [MOCK MODE] Simulating TShark PCAP Analysis...")
            return {
                "status": "MOCK_SUCCESS",
                "tool": "tshark",
                "output": "10.0.0.5 -> 103.45.0.0 HTTP GET /payload.bin\n10.0.0.5 -> 8.8.8.8 DNS Standard query A c2-server.evil.com",
            }

        cmd = [
            "tshark",
            "-r",
            pcap_path,
            "-Y",
            "http or dns",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
        ]
        return self._run_subprocess(cmd, "tshark")
