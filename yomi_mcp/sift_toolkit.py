import os
import select
import subprocess
import sys
import tempfile
import time
import signal
from typing import Tuple

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - SIFT Toolkit (v2.0)
# Purpose: Type-safe forensic wrappers around SIFT / incident response tools.
#          - Anti-Deadlock I/O: Non-blocking FD reads prevent pipe hanging.
#          - Binary Integrity: Write-Binary ("wb") preserves raw file hashes in icat.
#          - Global Flag Evasion Immunity: "--" injected into Yara and Grep paths.
#          - Scalpel Syntax Fixed: Correct C-level parameter flags for configs.
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

    def _kill_process_group(self, process: subprocess.Popen):
        """Kills the entire process group, annihilating zombie workers."""
        try:
            pgid = os.getpgid(process.pid)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def _set_non_blocking(self, fd):
        """
        Makes a file descriptor non-blocking at the OS level.
        Prevents .read() from deadlocking the server if the binary sends partial bytes.
        """
        import fcntl

        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def _stream_process_output(
        self, process: subprocess.Popen, timeout: int = 60
    ) -> tuple[str, str]:
        deadline = time.time() + timeout
        stdout_chunks = []
        stderr_chunks = []
        stdout_len = 0
        stderr_len = 0

        max_chars = 100000

        # Make pipes Non-Blocking to prevent OS I/O Deadlocks
        if process.stdout:
            self._set_non_blocking(process.stdout.fileno())
        if process.stderr:
            self._set_non_blocking(process.stderr.fileno())

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
                    self._kill_process_group(process)
                    break
                continue

            for pipe in ready:
                try:
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
                except IOError:
                    # Ignore harmless EAGAIN errors when the pipe is temporarily empty
                    continue

        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._kill_process_group(process)

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
                start_new_session=True,
            )

            stdout, stderr = self._stream_process_output(process, timeout)

            if process.returncode is None:
                self._kill_process_group(process)
                return {
                    "status": "ERROR",
                    "tool": tool_name,
                    "error": f"{tool_name} execution timed out after {timeout}s.",
                }

            if process.returncode == 0:
                return {
                    "status": "SUCCESS",
                    "tool": tool_name,
                    "output": stdout[:100000],
                }

            return {
                "status": "ERROR",
                "tool": tool_name,
                "error": stderr
                or stdout
                or f"{tool_name} returned {process.returncode}",
            }
        except FileNotFoundError:
            return {"status": "ERROR", "tool": tool_name, "error": f"Binary not found."}
        except Exception as exc:
            return {"status": "ERROR", "tool": tool_name, "error": str(exc)}

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
                start_new_session=True,
            )
            right = subprocess.Popen(
                right_cmd,
                stdin=left.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            if left.stdout is not None:
                left.stdout.close()

            stdout, stderr = self._stream_process_output(right, timeout)

            try:
                left.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._kill_process_group(left)

            if right.returncode == 0:
                return {
                    "status": "SUCCESS",
                    "tool": tool_name,
                    "output": stdout[:100000],
                }
            return {"status": "ERROR", "tool": tool_name, "error": stderr or stdout}
        except Exception as exc:
            return {"status": "ERROR", "tool": tool_name, "error": str(exc)}

    # -------------------------------------------------------------------------
    # VOLATILITY 3 WRAPPERS
    # -------------------------------------------------------------------------
    def run_volatility_pslist(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_pslist", "error": error}
        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility", "error": vol_path}
        return self._run_subprocess(
            [vol_path, "-f", memory_dump_path, "windows.pslist.PsList"],
            "volatility_pslist",
            timeout=300,
        )

    def run_volatility_netscan(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_netscan", "error": error}
        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility", "error": vol_path}
        return self._run_subprocess(
            [vol_path, "-f", memory_dump_path, "windows.netscan.NetScan"],
            "volatility_netscan",
            timeout=300,
        )

    def run_volatility_cmdline(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_cmdline", "error": error}
        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "tool": "volatility", "error": vol_path}
        return self._run_subprocess(
            [vol_path, "-f", memory_dump_path, "windows.cmdline.CmdLine"],
            "volatility_cmdline",
            timeout=300,
        )

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
            return {"status": "ERROR", "tool": "volatility", "error": vol_path}
        if not os.path.isfile(yara_rules_path):
            return {"status": "ERROR", "error": "YARA file not found."}

        # Added "--" literal barrier to prevent YARA flag evasion.
        cmd = [
            vol_path,
            "-f",
            memory_dump_path,
            "windows.yarascan.YaraScan",
            "--yara-file",
            "--",
            yara_rules_path,
        ]
        return self._run_subprocess(cmd, "volatility_yarascan", timeout=300)

    def run_volatility_windows_malfind(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_win_malfind", "error": error}
        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "error": vol_path}
        return self._run_subprocess(
            [vol_path, "-f", memory_dump_path, "windows.malfind.Malfind"],
            "volatility_win_malfind",
            timeout=300,
        )

    def run_volatility_linux_malfind(self, memory_dump_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            memory_dump_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "volatility_lin_malfind", "error": error}
        enabled, vol_path = self._validate_tool("volatility")
        if not enabled:
            return {"status": "ERROR", "error": vol_path}
        return self._run_subprocess(
            [vol_path, "-f", memory_dump_path, "linux.malfind.Malfind"],
            "volatility_lin_malfind",
            timeout=300,
        )

    # -------------------------------------------------------------------------
    # RADARE2 WRAPPER
    # -------------------------------------------------------------------------
    def run_radare2_analysis(self, binary_path: str) -> dict:
        is_valid, error = self._validate_target_path(binary_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "radare2", "error": error}
        enabled, r2_path = self._validate_tool("radare2")
        if not enabled:
            return {"status": "ERROR", "tool": "radare2", "error": r2_path}

        # Added "--" barrier to Radare2
        cmd = [
            r2_path,
            "-q",
            "-c",
            "aaa; pdf @ main || pdf @ entry0; izq; q",
            "--",
            binary_path,
        ]
        return self._run_subprocess(cmd, "radare2", timeout=120)

    # -------------------------------------------------------------------------
    # PLASO / LOG2TIMELINE WRAPPER
    # -------------------------------------------------------------------------
    def run_plaso_timeline(
        self, target_drive_path: str, output_path: str = "/tmp/timeline.plaso"
    ) -> dict:
        is_valid, error = self._validate_target_path(
            target_drive_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "plaso", "error": error}
        enabled, plaso_path = self._validate_tool("log2timeline")
        if not enabled:
            return {"status": "ERROR", "error": plaso_path}

        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        cmd = [plaso_path, output_path, target_drive_path]
        return self._run_subprocess(cmd, "plaso_timeline", timeout=280)

    # -------------------------------------------------------------------------
    # THE SLEUTH KIT WRAPPERS
    # -------------------------------------------------------------------------
    def run_tsk_fls(self, image_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "fls", "error": error}
        enabled, fls_path = self._validate_tool("fls")
        if not enabled:
            return {"status": "ERROR", "error": fls_path}
        cmd = [fls_path, "-r", "-p", image_path]
        return self._run_subprocess(cmd, "tsk_fls", timeout=120)

    def run_tsk_img_stat(self, image_path: str) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "img_stat", "error": error}
        enabled, img_stat_path = self._validate_tool("img_stat")
        if not enabled:
            return {"status": "ERROR", "error": img_stat_path}
        cmd = [img_stat_path, image_path]
        return self._run_subprocess(cmd, "tsk_img_stat", timeout=60)

    def run_tsk_icat(
        self, image_path: str, inode_id: str, output_path: str = None
    ) -> dict:
        is_valid, error = self._validate_target_path(
            image_path, allow_block_device=True
        )
        if not is_valid:
            return {"status": "ERROR", "tool": "icat", "error": error}
        enabled, icat_path = self._validate_tool("icat")
        if not enabled:
            return {"status": "ERROR", "error": icat_path}

        if output_path:
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # Binary Data Integrity.
            # Force "wb" mode to perfectly preserve binary malware samples or images.
            with open(output_path, "wb") as outfile:
                result = subprocess.run(
                    [icat_path, image_path, inode_id],
                    stdout=outfile,
                    stderr=subprocess.PIPE,
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
                    "error": result.stderr.decode("utf-8", errors="ignore").strip(),
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
            return {"status": "ERROR", "error": tshark_path}

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
            return {"status": "ERROR", "tool": "bulk", "error": error}
        enabled, bulk_path = self._validate_tool("bulk_extractor")
        if not enabled:
            return {"status": "ERROR", "error": bulk_path}

        output_dir = output_dir or os.path.join(
            tempfile.gettempdir(), f"bulk_extractor_{int(time.time())}"
        )
        os.makedirs(output_dir, exist_ok=True)
        cmd = [bulk_path, "-o", output_dir, target_path]
        return self._run_subprocess(cmd, "bulk_extractor", timeout=280)

    def run_strings_grep(self, target_path: str, pattern: str) -> dict:
        is_valid, error = self._validate_target_path(target_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "strings_grep", "error": error}
        enabled_s, strings_path = self._validate_tool("strings")
        enabled_g, grep_path = self._validate_tool("grep")
        if not enabled_s or not enabled_g:
            return {"status": "ERROR", "error": "strings/grep missing."}

        # The "--" barrier preserves integrity against flag injection evasion.
        return self._run_pipe(
            [strings_path, target_path],
            [grep_path, "-i", "-F", "--", pattern],
            "strings_grep",
            timeout=120,
        )

    # -------------------------------------------------------------------------
    # YARA & SIGNATURE SCANNING WRAPPERS
    # -------------------------------------------------------------------------
    def run_yara_scan(self, target_path: str, rule_path: str) -> dict:
        is_valid, error = self._validate_target_path(target_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "yara", "error": error}
        enabled, yara_path = self._validate_tool("yara")
        if not enabled:
            return {"status": "ERROR", "error": yara_path}

        # "--" barrier prevents flag injection evasion for Yara
        cmd = [yara_path, "-s", rule_path, "--", target_path]
        return self._run_subprocess(cmd, "yara_scan", timeout=120)

    def run_ssdeep(self, target_path: str) -> dict:
        is_valid, error = self._validate_target_path(target_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "ssdeep", "error": error}
        enabled, ssdeep_path = self._validate_tool("ssdeep")
        if not enabled:
            return {"status": "ERROR", "error": ssdeep_path}

        cmd = [ssdeep_path, "--", target_path]
        return self._run_subprocess(cmd, "ssdeep", timeout=60)

    # -------------------------------------------------------------------------
    # WINDOWS REGISTRY AND FILESYSTEM PARSERS
    # -------------------------------------------------------------------------
    def run_reglookup(self, registry_path: str) -> dict:
        is_valid, error = self._validate_target_path(registry_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "reglookup", "error": error}
        enabled, reglookup_path = self._validate_tool("reglookup")
        if not enabled:
            return {"status": "ERROR", "error": reglookup_path}
        cmd = [reglookup_path, registry_path]
        return self._run_subprocess(cmd, "reglookup", timeout=60)

    def run_mftparser(self, mft_path: str) -> dict:
        is_valid, error = self._validate_target_path(mft_path)
        if not is_valid:
            return {"status": "ERROR", "tool": "mftparser", "error": error}
        enabled, mftparser_path = self._validate_tool("mftparser")
        if not enabled:
            return {"status": "ERROR", "error": mftparser_path}
        cmd = [mftparser_path, mft_path]
        return self._run_subprocess(cmd, "mftparser", timeout=120)

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
            return {"status": "ERROR", "error": scalpel_path}

        output_dir = output_dir or os.path.join(
            tempfile.gettempdir(), f"scalpel_{int(time.time())}"
        )

        # Scalpel parameter positioning and directory crash fix
        cmd = [scalpel_path, image_path, "-o", output_dir]
        if config_path:
            cmd.insert(1, config_path)
            cmd.insert(1, "-c")

        return self._run_subprocess(cmd, "scalpel", timeout=180)
