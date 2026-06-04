import os
import select
import subprocess
import sys
import tempfile
import time
from typing import Tuple

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - SIFT Toolkit (Expanded Arsenal)
# Purpose: Type-safe forensic wrappers around SIFT / incident response tools.
#          Explicit command lists, path validation, and real toolchain detection.
# ==============================================================================


class SiftArsenal:
    def __init__(self):
        self.os_bridge = OSBridge()

    def _validate_target_path(
        self, path: str, allow_block_device: bool = False
    ) -> Tuple[bool, str]:
        if not isinstance(path, str) or not path:
            return False, "Invalid path supplied for forensic tool."
        if not os.path.isabs(path):
            return False, "Path must be absolute to prevent relative path abuse."
        if not os.path.exists(path):
            return False, f"Target path does not exist: {path}"
        if allow_block_device:
            return True, ""
        if not os.path.isfile(path):
            return False, f"Target path is not a regular file: {path}"
        return True, ""

    def _validate_tool(self, tool_name: str) -> Tuple[bool, str]:
        path = self.os_bridge.get_tool_path(tool_name)
        if not path:
            return (
                False,
                f"{tool_name} is unavailable on this host. Install the SIFT Workstation toolchain or add {tool_name} to PATH.",
            )
        return True, path

    def _stream_process_output(
        self, process: subprocess.Popen, timeout: int = 60
    ) -> tuple[str, str]:
        deadline = time.time() + timeout
        stdout_chunks = []
        stderr_chunks = []
        stdout_len = 0
        stderr_len = 0
        max_chars = 2000

        while True:
            if process.poll() is not None:
                break

            streams = []
            if process.stdout is not None:
                streams.append(process.stdout)
            if process.stderr is not None:
                streams.append(process.stderr)

            if not streams:
                break

            ready, _, _ = select.select(streams, [], [], 0.1)
            if not ready:
                if time.time() > deadline:
                    process.kill()
                    break
                continue

            for pipe in ready:
                chunk = pipe.read(4096)
                if not chunk:
                    continue
                if pipe is process.stdout and stdout_len < max_chars:
                    remaining = max_chars - stdout_len
                    stdout_chunks.append(chunk[:remaining])
                    stdout_len += len(chunk[:remaining])
                if pipe is process.stderr and stderr_len < max_chars:
                    remaining = max_chars - stderr_len
                    stderr_chunks.append(chunk[:remaining])
                    stderr_len += len(chunk[:remaining])

        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()

        return "".join(stdout_chunks).strip(), "".join(stderr_chunks).strip()

    def _run_subprocess(
        self, command_list: list[str], tool_name: str, timeout: int = 60
    ) -> dict:
        try:
            print(f"\n[YOMI-ARSENAL] Executing {tool_name}: {' '.join(command_list)}")
            process = subprocess.Popen(
                command_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            stdout, stderr = self._stream_process_output(process, timeout)

            if process.returncode is None:
                process.kill()
                return {
                    "status": "ERROR",
                    "tool": tool_name,
                    "error": f"{tool_name} execution timed out after {timeout}s.",
                }

            if process.returncode == 0:
                return {
                    "status": "SUCCESS",
                    "tool": tool_name,
                    "output": stdout[:2000],
                }

            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": stderr or stdout or f"{tool_name} returned {process.returncode}",
            }
        except FileNotFoundError:
            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": f"{tool_name} binary not found in system PATH.",
            }
        except Exception as exc:
            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": str(exc),
            }

    def _run_pipe(
        self,
        left_cmd: list[str],
        right_cmd: list[str],
        tool_name: str,
        timeout: int = 60,
    ) -> dict:
        try:
            left = subprocess.Popen(
                left_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            right = subprocess.Popen(
                right_cmd,
                stdin=left.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if left.stdout is not None:
                left.stdout.close()

            stdout, stderr = self._stream_process_output(right, timeout)

            try:
                left.wait(timeout=1)
            except subprocess.TimeoutExpired:
                left.kill()

            if right.returncode == 0:
                return {
                    "status": "SUCCESS",
                    "tool": tool_name,
                    "output": stdout[:2000],
                }
            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": stderr or stdout or f"{tool_name} returned {right.returncode}",
            }
        except Exception as exc:
            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": str(exc),
            }

    # -------------------------------------------------------------------------
    # VOLATILITY 3 WRAPPERS (Memory Forensics)
    # -------------------------------------------------------------------------
    def run_volatility_pslist(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_pslist", "error": error}

        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility_pslist", "error": vol_path}

        cmd = [vol_path, "-f", memory_dump_path, "windows.pslist.PsList"]
        return self._run_subprocess(cmd, "volatility_pslist")

    def run_volatility_netscan(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_netscan", "error": error}

        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility_netscan", "error": vol_path}

        cmd = [vol_path, "-f", memory_dump_path, "windows.netscan.NetScan"]
        return self._run_subprocess(cmd, "volatility_netscan")

    def run_volatility_cmdline(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_cmdline", "error": error}

        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility_cmdline", "error": vol_path}

        cmd = [vol_path, "-f", memory_dump_path, "windows.cmdline.CmdLine"]
        return self._run_subprocess(cmd, "volatility_cmdline")

    def run_volatility_yarascan(
        self, memory_dump_path: str, yara_rules_path: str
    ) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_yarascan", "error": error}

        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility_yarascan", "error": vol_path}

        if not os.path.isfile(yara_rules_path):
            return {
                "status": "ERROR",
                "tool": "volatility_yarascan",
                "error": f"YARA rules file not found: {yara_rules_path}",
            }

        cmd = [
            vol_path,
            "-f",
            memory_dump_path,
            "windows.yarascan.YaraScan",
            "--yara-file",
            yara_rules_path,
        ]
        return self._run_subprocess(cmd, "volatility_yarascan")

    # -------------------------------------------------------------------------
    # VOLATILITY 3 ADVANCED EXTENSIONS (Process Injection Hunting)
    # -------------------------------------------------------------------------
    def run_volatility_windows_malfind(self, memory_dump_path: str) -> dict:
        """Scan Windows memory VAD structures for injected shellcode or hidden PEs."""
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_win_malfind", "error": error}

        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {
                "status": "ERROR",
                "tool": "volatility_win_malfind",
                "error": vol_path,
            }

        cmd = [vol_path, "-f", memory_dump_path, "windows.malfind.Malfind"]
        return self._run_subprocess(cmd, "volatility_win_malfind")

    def run_volatility_linux_malfind(self, memory_dump_path: str) -> dict:
        """Scan Linux process memory maps for anonymous executable pages or code injection."""
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_lin_malfind", "error": error}

        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {
                "status": "ERROR",
                "tool": "volatility_lin_malfind",
                "error": vol_path,
            }

        cmd = [vol_path, "-f", memory_dump_path, "linux.malfind.Malfind"]
        return self._run_subprocess(cmd, "volatility_lin_malfind")

    # -------------------------------------------------------------------------
    # RADARE2 WRAPPER (Static/Binary Analysis)
    # -------------------------------------------------------------------------
    def run_radare2_analysis(self, binary_path: str) -> dict:
        is_valid, error = self._validate_target_path(binary_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "radare2", "error": error}

        enabled, r2_path = self._validate_tool("radare2")
        if not enabled:
            return {"status": "ERROR", "tool": "radare2", "error": r2_path}

        # aaa: Analyze all; pdf @ main: Disassemble main; || fallback to entry0; izq: Quick strings
        cmd = [
            r2_path,
            "-q",
            "-c",
            "aaa; pdf @ main || pdf @ entry0; izq; q",
            binary_path,
        ]
        return self._run_subprocess(cmd, "radare2")

    # -------------------------------------------------------------------------
    # PLASO / LOG2TIMELINE WRAPPER (Timeline Forensics)
    # -------------------------------------------------------------------------
    def run_plaso_timeline(
        self, target_drive_path: str, output_path: str = "/tmp/timeline.plaso"
    ) -> dict:
        is_valid, error = self._validate_target_path(
            target_drive_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "plaso_timeline", "error": error}

        enabled, plaso_path = self._validate_tool("log2timeline")
        if not enabled:
            return {"status": "ERROR", "tool": "plaso_timeline", "error": plaso_path}

        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # Removed rigid Windows 7 parser lock to achieve full compatibility with Linux/macOS images
        cmd = [plaso_path, output_path, target_drive_path]
        return self._run_subprocess(cmd, "plaso_timeline", timeout=300)

    # -------------------------------------------------------------------------
    # THE SLEUTH KIT WRAPPERS
    # -------------------------------------------------------------------------
    def run_tsk_fls(self, image_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "tsk_fls", "error": error}

        enabled, fls_path = self._validate_tool("fls")
        if not enabled:
            return {"status": "ERROR", "tool": "tsk_fls", "error": fls_path}

        cmd = [fls_path, "-r", "-p", image_path]
        return self._run_subprocess(cmd, "tsk_fls")

    def run_tsk_img_stat(self, image_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "tsk_img_stat", "error": error}

        enabled, img_stat_path = self._validate_tool("img_stat")
        if not enabled:
            return {"status": "ERROR", "tool": "tsk_img_stat", "error": img_stat_path}

        cmd = [img_stat_path, image_path]
        return self._run_subprocess(cmd, "tsk_img_stat")

    def run_tsk_icat(
        self, image_path: str, inode_id: str, output_path: str = None
    ) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "tsk_icat", "error": error}

        enabled, icat_path = self._validate_tool("icat")
        if not enabled:
            return {"status": "ERROR", "tool": "tsk_icat", "error": icat_path}

        if not inode_id:
            return {
                "status": "ERROR",
                "tool": "tsk_icat",
                "error": "inode_id is required for icat output.",
            }

        if output_path:
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8", errors="ignore") as outfile:
                result = subprocess.run(
                    [icat_path, image_path, inode_id],
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    return {
                        "status": "SUCCESS",
                        "tool": "tsk_icat",
                        "output": f"Extracted inode {inode_id} to {output_path}",
                    }
                return {
                    "status": "ERROR",
                    "tool": "tsk_icat",
                    "error": result.stderr.strip(),
                }

        cmd = [icat_path, image_path, inode_id]
        return self._run_subprocess(cmd, "tsk_icat", timeout=120)

    # -------------------------------------------------------------------------
    # NETWORK & PCAP ANALYSIS WRAPPERS
    # -------------------------------------------------------------------------
    def run_tshark_pcap(self, pcap_path: str) -> dict:
        is_valid, error = self._validate_target_path(pcap_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "tshark", "error": error}

        enabled, tshark_path = self._validate_tool("tshark")
        if not enabled:
            return {"status": "ERROR", "tool": "tshark", "error": tshark_path}

        cmd = [
            tshark_path,
            "-r",
            pcap_path,
            "-Y",
            "http or dns or ssl or tcp.port == 443 or tcp.port == 80",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "http.host",
            "-e",
            "dns.qry.name",
        ]
        return self._run_subprocess(cmd, "tshark", timeout=120)

    def run_bulk_extractor(self, target_path: str, output_dir: str = None) -> dict:
        is_valid, error = self._validate_target_path(
            target_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "bulk_extractor", "error": error}

        enabled, bulk_path = self._validate_tool("bulk_extractor")
        if not enabled:
            return {"status": "ERROR", "tool": "bulk_extractor", "error": bulk_path}

        output_dir = output_dir or os.path.join(tempfile.gettempdir(), "bulk_extractor")
        os.makedirs(output_dir, exist_ok=True)
        cmd = [bulk_path, "-o", output_dir, target_path]
        return self._run_subprocess(cmd, "bulk_extractor", timeout=180)

    def run_strings_grep(self, target_path: str, pattern: str) -> dict:
        is_valid, error = self._validate_target_path(target_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "strings_grep", "error": error}

        enabled_strings, strings_path = self._validate_tool("strings")
        enabled_grep, grep_path = self._validate_tool("grep")
        if not enabled_strings:
            return {"status": "ERROR", "tool": "strings_grep", "error": strings_path}
        if not enabled_grep:
            return {"status": "ERROR", "tool": "strings_grep", "error": grep_path}

        return self._run_pipe(
            [strings_path, target_path],
            [grep_path, "-i", "-F", pattern],
            "strings_grep",
        )

    # -------------------------------------------------------------------------
    # YARA & SIGNATURE SCANNING WRAPPERS
    # -------------------------------------------------------------------------
    def run_yara_scan(self, target_path: str, rule_path: str) -> dict:
        is_valid, error = self._validate_target_path(target_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "yara_scan", "error": error}

        enabled, yara_path = self._validate_tool("yara")
        if not enabled:
            return {"status": "ERROR", "tool": "yara_scan", "error": yara_path}

        if not os.path.isfile(rule_path):
            return {
                "status": "ERROR",
                "tool": "yara_scan",
                "error": f"YARA rule file not found: {rule_path}",
            }

        cmd = [yara_path, "-s", rule_path, target_path]
        return self._run_subprocess(cmd, "yara_scan")

    def run_ssdeep(self, target_path: str) -> dict:
        is_valid, error = self._validate_target_path(target_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "ssdeep", "error": error}

        enabled, ssdeep_path = self._validate_tool("ssdeep")
        if not enabled:
            return {"status": "ERROR", "tool": "ssdeep", "error": ssdeep_path}

        cmd = [ssdeep_path, target_path]
        return self._run_subprocess(cmd, "ssdeep")

    # -------------------------------------------------------------------------
    # WINDOWS REGISTRY AND FILESYSTEM PARSERS
    # -------------------------------------------------------------------------
    def run_reglookup(self, registry_path: str) -> dict:
        is_valid, error = self._validate_target_path(registry_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "reglookup", "error": error}

        enabled, reglookup_path = self._validate_tool("reglookup")
        if not enabled:
            return {"status": "ERROR", "tool": "reglookup", "error": reglookup_path}

        cmd = [reglookup_path, registry_path]
        return self._run_subprocess(cmd, "reglookup")

    def run_mftparser(self, mft_path: str) -> dict:
        is_valid, error = self._validate_target_path(mft_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "mftparser", "error": error}

        enabled, mftparser_path = self._validate_tool("mftparser")
        if not enabled:
            return {"status": "ERROR", "tool": "mftparser", "error": mftparser_path}

        cmd = [mftparser_path, mft_path]
        return self._run_subprocess(cmd, "mftparser")

    def run_scalpel(
        self, image_path: str, config_path: str = None, output_dir: str = None
    ) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "scalpel", "error": error}

        enabled, scalpel_path = self._validate_tool("scalpel")
        if not enabled:
            return {"status": "ERROR", "tool": "scalpel", "error": scalpel_path}

        if config_path:
            if not os.path.isfile(config_path):
                return {
                    "status": "ERROR",
                    "tool": "scalpel",
                    "error": f"Scalpel config not found: {config_path}",
                }

        output_dir = output_dir or os.path.join(tempfile.gettempdir(), "scalpel")
        os.makedirs(output_dir, exist_ok=True)

        cmd = [scalpel_path, image_path, "-o", output_dir]
        if config_path:
            cmd.insert(1, config_path)
        return self._run_subprocess(cmd, "scalpel", timeout=180)
