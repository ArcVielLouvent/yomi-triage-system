import os
import sys
import time
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.align import Align
from rich import box

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_engine.library import OmniLibrary

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Obsidian Torii Gateway (v5.0 LIVE)
# Purpose: Responsive, real-time, non-blocking Enterprise TUI.
# ==============================================================================


class YomiDashboard:
    def __init__(self):
        self.console = Console()
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

        self.current_status = "SYSTEM BOOT"
        self.active_pid = "SCANNING..."
        self.epistemic_doubt = "0%"
        self.ebpf_status = "STANDBY"
        self.cpu_usage = "0%"
        self.memory_usage = "0%"
        self.memory_status = "NORMAL"
        self.action_log = []
        self.library = OmniLibrary()
        self.cve_count = len(self.library.database)
        self.last_cve_sync = self.library.last_updated or "N/A"
        self.cve_source = self.library.source
        self.library_status = "ONLINE" if self.library.online else "OFFLINE"

        # Determine terminal height dynamically to limit logs and prevent overflow
        term_height = self.console.size.height
        self.max_logs = max(
            5, term_height - 18
        )  # Reserve 18 lines for header & borders

    def generate_torii_logo(self) -> Align:
        """Fixed static header logo."""
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
        """Real-time updating left panel."""
        self.refresh_system_metrics()
        self.refresh_library_metrics()

        table = Table(box=box.SIMPLE, expand=True, show_header=False)
        table.add_column("Metric", style=self.colors["ghost_white"])
        table.add_column("Value", justify="right")

        status_color = self.colors["plasma_blue"]
        if "CRITICAL" in self.current_status:
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
        table.add_row(
            "Host CPU Usage", Text(self.cpu_usage, style=self.colors["plasma_blue"])
        )
        table.add_row(
            "Host Memory Usage", Text(self.memory_usage, style=self.colors["plasma_blue"])
        )
        table.add_row(
            "Memory Threat", Text(self.memory_status, style=self.colors["warning"])
        )
        table.add_row(
            "CVE Records", Text(str(self.cve_count), style=self.colors["plasma_blue"])
        )
        table.add_row(
            "CVE Source", Text(self.cve_source, style=self.colors["plasma_blue"])
        )
        table.add_row(
            "Last CVE Sync", Text(self.last_cve_sync, style=self.colors["plasma_blue"])
        )
        table.add_row(
            "Library Status", Text(self.library_status, style=self.colors["plasma_blue"])
        )
        table.add_row(
            "Scope", Text("Host-wide system metrics, not Yomi-only", style=self.colors["plasma_blue"])
        )
        table.add_row(
            "eBPF Sentinel", Text(self.ebpf_status, style=self.colors["green_matrix"])
        )
        table.add_row(
            "Network (Air-Gap)", Text("ONLINE", style=self.colors["plasma_blue"])
        )

        return Panel(
            table,
            title="[b]TACTICAL TELEMETRY",
            border_style=self.colors["plasma_blue"],
        )

    def make_log_panel(self) -> Panel:
        """Scrolling terminal logs on the right panel."""
        log_text = Text()

        # Ensure it fits the terminal dynamically
        current_term_height = self.console.size.height
        dynamic_max_logs = max(5, current_term_height - 18)

        for log in self.action_log[-dynamic_max_logs:]:
            log_text.append(f"{log}\n")

        return Panel(
            log_text,
            title="[b]LIVE OPERATION STREAM",
            border_style=self.colors["obsidian"],
        )

    def update_telemetry(self, status: str, pid: str, doubt: str, ebpf: str):
        """Updates the real-time variables for the left panel."""
        if status:
            self.current_status = status
        if pid:
            self.active_pid = pid
        if doubt:
            self.epistemic_doubt = doubt
        if ebpf:
            self.ebpf_status = ebpf

    def update_state(self, status: str, pid: str, recent_log: str = None):
        """Update current status and append a new operational log entry."""
        self.update_telemetry(status, pid, self.epistemic_doubt, self.ebpf_status)
        if recent_log:
            self.append_log(recent_log)

    def refresh_library_metrics(self):
        """Refreshes the dashboard CVE library metrics from the OmniLibrary."""
        try:
            with self.library.database_lock:
                self.cve_count = len(self.library.database)
            self.last_cve_sync = self.library.last_updated or "N/A"
            self.cve_source = self.library.source
            self.library_status = "ONLINE" if self.library.online else "OFFLINE"
        except Exception:
            self.cve_count = -1
            self.last_cve_sync = "UNKNOWN"
            self.cve_source = "UNKNOWN"
            self.library_status = "UNKNOWN"

    def refresh_system_metrics(self):
        """Refreshes CPU and memory metrics from the host environment.

        This is host-level telemetry and reflects total system usage,
        not CPU/RAM usage of only the Yomi process.
        """
        cpu_percent = None
        mem_percent = None

        try:
            import psutil  # type: ignore

            cpu_percent = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
        except Exception:
            try:
                if hasattr(os, "getloadavg"):
                    load1, _, _ = os.getloadavg()
                    cpus = os.cpu_count() or 1
                    cpu_percent = min(100.0, (load1 / cpus) * 100)
                meminfo = {}
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        key, value = line.split(":")
                        meminfo[key.strip()] = int(value.strip().split()[0])
                if "MemTotal" in meminfo and "MemAvailable" in meminfo:
                    mem_percent = round(
                        100.0
                        * (meminfo["MemTotal"] - meminfo["MemAvailable"])
                        / meminfo["MemTotal"],
                        1,
                    )
            except Exception:
                pass

        self.cpu_usage = f"{cpu_percent:.1f}%" if cpu_percent is not None else "N/A"
        self.memory_usage = f"{mem_percent:.1f}%" if mem_percent is not None else "N/A"

        if mem_percent is not None:
            if mem_percent > 90:
                self.memory_status = "CRITICAL"
            elif mem_percent > 75:
                self.memory_status = "WARNING"
            else:
                self.memory_status = "NORMAL"
        else:
            self.memory_status = "UNKNOWN"

    def append_log(self, raw_text: str):
        """Appends a new scrolling log to the right panel with automatic coloration."""
        timestamp = datetime.now().strftime("%H:%M:%S")

        log_style = self.colors["ghost_white"]
        if "ERROR" in raw_text or "CRITICAL" in raw_text or "FREEZE" in raw_text:
            log_style = self.colors["blood_red"]
        elif "SHADOW NET" in raw_text or "MIRAGE" in raw_text:
            log_style = self.colors["cyber_purple"]
        elif "DETECTED" in raw_text or "WARNING" in raw_text:
            log_style = self.colors["warning"]
        elif "SUCCESS" in raw_text:
            log_style = self.colors["green_matrix"]

        styled_log = Text(f"[{timestamp}] {raw_text}", style=log_style)
        self.action_log.append(styled_log)

        # Prevent memory leak by truncating the list
        if len(self.action_log) > 100:
            self.action_log = self.action_log[-100:]

    def render_layout(self) -> Layout:
        """Builds the responsive grid."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=14),  # Fixed size for the Torii Gate
            Layout(name="body", ratio=1),  # Flexible size for the rest of the terminal
        )
        layout["body"].split_row(
            Layout(
                name="telemetry", ratio=1, minimum_size=35
            ),  # Telemetry takes 1/3 of screen
            Layout(name="logs", ratio=2),  # Logs take 2/3 of screen
        )

        layout["header"].update(self.make_header())
        layout["telemetry"].update(self.make_telemetry_panel())
        layout["logs"].update(self.make_log_panel())

        return layout


# ==============================================================================
# UI TEST DRIVER (Execute this to see the responsive magic)
# ==============================================================================
if __name__ == "__main__":
    tui = YomiDashboard()
    tui.append_log("SYSTEM BOOT: Initializing real-time core systems.")
    tui.append_log(
        "SYSTEM NOTICE: Predator Swarm armed. Awaiting SOC approval for planned remediation execution."
    )

    try:
        # screen=True enables the "alternate screen" (like htop/nano)
        with Live(tui.render_layout(), refresh_per_second=10, screen=True) as live:
            # Simulate real-time updates without noisy tick spam
            tui.update_telemetry("SCANNING", "NONE", "0%", "ARMED")
            live.update(tui.render_layout())
            time.sleep(1.5)

            tui.update_telemetry("WARNING", "4092", "65%", "INTERCEPTING")
            tui.append_log(
                "REQUEST: OpenClaw plan ready. SOC approval required before executing remediation playbook."
            )
            live.update(tui.render_layout())
            time.sleep(2)

            tui.update_telemetry("ENGAGED", "4092", "18%", "ACTIVE")
            tui.append_log(
                "APPROVAL RECEIVED: Remediation playbook execution authorized by SOC. Proceeding with isolation and analysis."
            )
            live.update(tui.render_layout())
            time.sleep(2)

            tui.append_log(
                "FINALIZE: Threat neutralization complete. Audit trail sealed and incident handed to SOC for review."
            )
            live.update(tui.render_layout())

            # Keep the dashboard open for observation without noisy background spam
            while True:
                time.sleep(0.5)
                live.update(tui.render_layout())

    except KeyboardInterrupt:
        print("\n[+] Dashboard Terminated Safely.")
        sys.exit(0)
