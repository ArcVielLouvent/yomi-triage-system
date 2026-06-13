import os
import sys
import json
import threading
import re
import psutil
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.align import Align
from rich import box

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_engine.library import OmniLibrary

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Obsidian Torii Gateway (v10.0)
# Purpose: Responsive, real-time, non-blocking Enterprise TUI center.
#          - Anti-Desynchronization: Visual overflow alert shield for logs.
#          - Strict Anti-Stale Size: -1 signature break for dynamic file re-creation.
#          - Control Char Immunity: Full block against \r, \b, \u202E spoofing.
#          - Total UI Decoupling: Zero /proc or disk I/O in the render loop.
# ==============================================================================


class YomiDashboard:
    def __init__(self):
        self.console = Console(file=sys.__stdout__)
        self.colors = {
            "void_black": "black",
            "ghost_white": "#F8F8FF",
            "obsidian": "#4A4A4A",
            "plasma_blue": "#00FFFF",
            "cyber_purple": "#BF00FF",
            "blood_red": "#FF0000",
            "warning": "#FFD700",
            "green_matrix": "#00FF00",
        }

        # Enhanced ANSI & Control Character Shield
        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self.control_chars = re.compile(
            r"[\x00-\x09\x0B-\x1F\x7F-\x9F\u200B-\u200F\u202A-\u202E]"
        )

        # Lock Splitting Configuration
        self._telemetry_lock = threading.Lock()
        self._log_lock = threading.Lock()

        # Telemetry State
        self.current_status = "SYSTEM BOOT"
        self.active_pid = "SCANNING..."
        self.epistemic_doubt = "0%"
        self.ebpf_status = "STANDBY"

        self.latest_ttc = "AWAITING INCIDENT"
        self.speed_multiplier = "N/A"
        self._last_tel_size = 0

        self.cpu_usage = "0%"
        self.memory_usage = "0%"
        self.memory_status = "NORMAL"
        self.yomi_ram_mb = 0.0

        # Log State
        self.action_log = []

        # Library State
        self.library = OmniLibrary()
        self.cve_count = 0
        self.last_cve_sync = "N/A"
        self.cve_source = "UNKNOWN"
        self.library_status = "UNKNOWN"

        # Background Worker Thread
        self.is_running = True
        self._stop_event = threading.Event()
        self.worker_thread = threading.Thread(
            target=self._background_metrics_worker, daemon=True
        )
        self.worker_thread.start()

    def stop(self):
        """Signals the daemon thread to terminate instantly without sleeping."""
        self._stop_event.set()
        self.is_running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)

    def _background_metrics_worker(self):
        """Background Daemon: Executes gracefully with interruptible wait."""
        while not self._stop_event.is_set() and self.is_running:
            self._refresh_system_metrics()
            self._refresh_library_metrics()
            self._refresh_telemetry_metrics()
            self._stop_event.wait(1.0)

    def generate_torii_logo(self) -> Align:
        torii_ascii = (
            "   ▄▄██████████████████████████████▄▄     \n"
            "     ▀▀▀▀████▀▀▀▀▀▀▀▀▀▀▀▀▀▀████▀▀▀▀       \n"
            "  ▄██████████████████████████████████▄    \n"
            "         ████              ████           \n"
            "         ████   KUROTECH   ████           \n"
            "         ████              ████           \n"
            "         ████              ████           \n"
            "         ----------------------           \n"
            "         | Yomi Triage System |           \n"
            "         ----------------------           "
        )
        return Align.center(
            Text(torii_ascii, style=self.colors["obsidian"], justify="left")
        )

    def make_header(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_row(self.generate_torii_logo())
        grid.add_row(
            Text(
                "AUTONOMOUS DFIR TRIAGE ENGINE v1.0",
                style=f"bold {self.colors['blood_red']}",
                justify="center",
            )
        )
        return Panel(grid, box=box.HEAVY, border_style=self.colors["obsidian"])

    def make_telemetry_panel(self) -> Panel:
        with self._telemetry_lock:
            table = Table(box=box.SIMPLE, expand=True, show_header=False)
            table.add_column("Metric", style=self.colors["ghost_white"])
            table.add_column("Value", justify="right")

            status_color = self.colors["plasma_blue"]
            if "CRITICAL" in self.current_status or "OVERLOAD" in self.current_status:
                status_color = self.colors["blood_red"]
            elif "DECEPTION" in self.current_status:
                status_color = self.colors["cyber_purple"]
            elif "WARNING" in self.current_status:
                status_color = self.colors["warning"]

            table.add_row(
                "System Status", Text(self.current_status, style=f"bold {status_color}")
            )
            table.add_row("Target PID", Text(str(self.active_pid), style="bold yellow"))
            table.add_row(
                "Epistemic Doubt",
                Text(self.epistemic_doubt, style=self.colors["plasma_blue"]),
            )

            ttc_color = (
                self.colors["blood_red"]
                if "TAMPERED" in self.latest_ttc
                else self.colors["green_matrix"]
            )
            table.add_row(
                "Containment Latency", Text(self.latest_ttc, style=f"bold {ttc_color}")
            )
            table.add_row(
                "Tactical Speed",
                Text(
                    self.speed_multiplier, style=f"bold {self.colors['green_matrix']}"
                ),
            )
            table.add_row(
                "eBPF Sentinel",
                Text(self.ebpf_status, style=self.colors["green_matrix"]),
            )

            table.add_row(
                "Yomi RAM Footprint", Text(f"{self.yomi_ram_mb:.1f} MB", style="green")
            )
            table.add_row(
                "Host CPU Usage", Text(self.cpu_usage, style=self.colors["plasma_blue"])
            )
            table.add_row(
                "Memory Threat", Text(self.memory_status, style=self.colors["warning"])
            )

            table.add_row(
                "CVE Records (O(1))",
                Text(str(self.cve_count), style=self.colors["plasma_blue"]),
            )
            table.add_row(
                "Library Status",
                Text(self.library_status, style=self.colors["plasma_blue"]),
            )

            return Panel(
                table,
                title="[b]TACTICAL TELEMETRY",
                border_style=self.colors["plasma_blue"],
            )

    def make_log_panel(self) -> Panel:
        log_text = Text()
        current_term_height = self.console.size.height
        dynamic_max_logs = max(5, current_term_height - 18)

        with self._log_lock:
            for log in self.action_log[-dynamic_max_logs:]:
                log_text.append(f"{log}\n")

        return Panel(
            log_text,
            title="[b]LIVE OPERATION STREAM",
            border_style=self.colors["obsidian"],
        )

    def update_telemetry(
        self, status: str = None, pid: str = None, doubt: str = None, ebpf: str = None
    ):
        with self._telemetry_lock:
            if status is not None:
                self.current_status = status
            if pid is not None:
                self.active_pid = pid
            if doubt is not None:
                self.epistemic_doubt = doubt
            if ebpf is not None:
                self.ebpf_status = ebpf

    def update_state(self, status: str, pid: str, recent_log: str = None):
        self.update_telemetry(status=status, pid=pid)
        if recent_log:
            self.append_log(recent_log)

    def _refresh_telemetry_metrics(self):
        tel_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "yomi_data",
                "telemetry_benchmarks.jsonl",
            )
        )

        if not os.path.exists(tel_path):
            with self._telemetry_lock:
                self.latest_ttc = "[TAMPERED] FILE MISSING"
                self.speed_multiplier = "AUDIT LOG COMPROMISED"
                # Set last size to -1 instead of 0 to prevent 0==0 stale lock upon re-creation
                self._last_tel_size = -1
            return

        try:
            current_size = os.stat(tel_path).st_size
            if current_size == self._last_tel_size:
                return

            with open(tel_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                filesize = f.tell()
                read_size = min(8192, filesize)
                f.seek(filesize - read_size, os.SEEK_SET)

                lines = f.read().splitlines()

                for line in reversed(lines):
                    if not line.strip():
                        continue
                    try:
                        latest = json.loads(line)
                        with self._telemetry_lock:
                            self.latest_ttc = f"{latest.get('latency_seconds', 0)}s"
                            speed = latest.get("human_speed_multiplier", "")
                            self.speed_multiplier = f"{speed} (Beat Horizon3: {latest.get('beat_horizon3_ai')})"
                            self._last_tel_size = current_size
                        return
                    except json.JSONDecodeError:
                        continue
        except (OSError, ValueError):
            pass

    def _refresh_library_metrics(self):
        try:
            meta = self.library.get_metadata()
            with self._telemetry_lock:
                self.cve_count = meta.get("count", 0)
                self.last_cve_sync = meta.get("last_updated", "N/A")
                self.cve_source = meta.get("source", "UNKNOWN")
                self.library_status = "ONLINE" if meta.get("online") else "AIR-GAPPED"
        except Exception:
            with self._telemetry_lock:
                self.library_status = "ERROR"

    def _refresh_system_metrics(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_percent = mem.percent

            yomi_process = psutil.Process(os.getpid())
            ram_mb = yomi_process.memory_info().rss / (1024 * 1024)

            with self._telemetry_lock:
                self.cpu_usage = f"{cpu_percent:.1f}%"
                self.memory_usage = f"{mem_percent:.1f}%"
                self.yomi_ram_mb = ram_mb

                if mem_percent > 90:
                    self.memory_status = "CRITICAL"
                elif mem_percent > 75:
                    self.memory_status = "WARNING"
                else:
                    self.memory_status = "NORMAL"
        except Exception:
            pass

    def append_log(self, raw_text: str):
        # Pre-evaluate threat keywords BEFORE truncation for 100% color fidelity
        threat_detected = any(
            k in raw_text for k in ["ERROR", "CRITICAL", "FREEZE", "OVERLOAD"]
        )
        purple_detected = any(k in raw_text for k in ["SHADOW NET", "MIRAGE"])
        warning_detected = any(k in raw_text for k in ["DETECTED", "WARNING", "DOUBT"])
        success_detected = any(k in raw_text for k in ["SUCCESS", "BENCHMARK"])

        # Anti-ReDoS Pre-Truncation Barrier
        is_truncated = len(raw_text) > 2000
        safe_raw_text = raw_text[:2000] if is_truncated else raw_text

        # Terminal Spoofing Shield (Sanitizing \r, \b, \u202E, and ANSI parameters)
        no_ansi = self.ansi_escape.sub("", safe_raw_text)
        clean_text = self.control_chars.sub(" ", no_ansi).replace("\n", " [LF] ")

        # Append visual truncation shield flag if string overflowed
        if is_truncated:
            clean_text += " ... [TRUNCATED BY YOMI VAULT SHIELD]"

        timestamp = datetime.now().strftime("%H:%M:%S")

        log_style = self.colors["ghost_white"]
        if threat_detected:
            log_style = self.colors["blood_red"]
        elif purple_detected:
            log_style = self.colors["cyber_purple"]
        elif warning_detected:
            log_style = self.colors["warning"]
        elif success_detected:
            log_style = self.colors["green_matrix"]

        styled_log = Text(f"[{timestamp}] {clean_text}", style=log_style)

        with self._log_lock:
            self.action_log.append(styled_log)
            if len(self.action_log) > 100:
                self.action_log = self.action_log[-100:]

    def render_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=14),
            Layout(name="body", ratio=1),
        )
        layout["body"].split_row(
            Layout(name="telemetry", ratio=1, minimum_size=35),
            Layout(name="logs", ratio=2),
        )

        layout["header"].update(self.make_header())
        layout["telemetry"].update(self.make_telemetry_panel())
        layout["logs"].update(self.make_log_panel())

        return layout
