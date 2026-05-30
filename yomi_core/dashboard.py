import time
import os
import sys
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.align import Align
from rich import box

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Obsidian Torii Gateway (TUI)
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
        }

        self.current_status = "SAFE"
        self.active_pid = "NONE"
        self.action_log = []

    def generate_torii_logo(self) -> Align:
        """
        Generates the KuroTech Obsidian Torii Gateway in ASCII.
        Using Align.center ensures the block is centered without destroying
        the internal relative spacing of the ASCII art.
        """
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
        # Left-justify the text to preserve the shape, then center the whole block
        ascii_text = Text(torii_ascii, style=self.colors["obsidian"], justify="left")
        return Align.center(ascii_text)

    def make_header(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_row(self.generate_torii_logo())
        grid.add_row(
            Text(
                "AUTONOMOUS DFIR TRIAGE ENGINE v4.0",
                style=f"bold {self.colors['ghost_white']}",
                justify="center",
            )
        )
        return Panel(grid, box=box.ROUNDED, border_style=self.colors["plasma_blue"])

    def make_telemetry_panel(self) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_header=False)
        table.add_column("Metric", style=self.colors["ghost_white"])
        table.add_column("Value", justify="right")

        status_color = self.colors["plasma_blue"]
        if self.current_status == "CRITICAL":
            status_color = self.colors["blood_red"]
        elif self.current_status == "DECEPTION":
            status_color = self.colors["cyber_purple"]
        elif self.current_status == "WARNING":
            status_color = self.colors["warning"]

        table.add_row(
            "System Status", Text(self.current_status, style=f"bold {status_color}")
        )
        table.add_row(
            "Target PID",
            Text(
                str(self.active_pid),
                style="bold yellow" if self.active_pid != "NONE" else "dim",
            ),
        )
        table.add_row("Epistemic Doubt", Text("0%", style=self.colors["plasma_blue"]))
        table.add_row(
            "eBPF Sentinel", Text("ARMED (Ring-0)", style=self.colors["ghost_white"])
        )

        return Panel(
            table, title="[b]TACTICAL TELEMETRY", border_style=self.colors["obsidian"]
        )

    def make_log_panel(self) -> Panel:
        log_text = Text()
        # Ensure we only show the last 7 logs so it doesn't overflow the UI
        for log in self.action_log[-7:]:
            log_text.append(f"{log}\n")

        return Panel(
            log_text,
            title="[b]IMMUTABLE LEDGER STREAM",
            border_style=self.colors["obsidian"],
        )

    def update_state(self, status: str, pid: str, new_log: str):
        self.current_status = status
        self.active_pid = pid
        timestamp = time.strftime("%H:%M:%S")

        log_style = self.colors["ghost_white"]
        if "FREEZE" in new_log or "CRITICAL" in new_log:
            log_style = self.colors["blood_red"]
        elif "SHADOW NET" in new_log or "MIRAGE" in new_log:
            log_style = self.colors["cyber_purple"]
        elif "WARNING" in status:
            log_style = self.colors["warning"]

        styled_log = Text(f"[{timestamp}] {new_log}", style=log_style)
        self.action_log.append(styled_log)

    def render_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(
                name="header", size=14
            ),  # Increased height to fit the logo perfectly
            Layout(name="body", ratio=1),
        )
        layout["body"].split_row(
            Layout(name="telemetry", ratio=1), Layout(name="logs", ratio=2)
        )

        layout["header"].update(self.make_header())
        layout["telemetry"].update(self.make_telemetry_panel())
        layout["logs"].update(self.make_log_panel())

        return layout


# ==============================================================================
# DEVELOPMENT TESTING BLOCK (Live UI Simulation)
# ==============================================================================
if __name__ == "__main__":
    tui = YomiDashboard()

    tui.update_state("SAFE", "NONE", "System Boot Sequence Initiated...")
    tui.update_state("SAFE", "NONE", "Ouroboros Watchdog Online.")
    tui.update_state("SAFE", "NONE", "Omni-Library RAG synced.")

    # We use a try-except block with an INFINITE loop so it doesn't close
    try:
        with Live(tui.render_layout(), refresh_per_second=4, screen=True) as live:
            time.sleep(1)
            tui.update_state("SAFE", "NONE", "Predator Swarm scanning Volatility...")
            live.update(tui.render_layout())
            time.sleep(1.5)

            tui.update_state(
                "WARNING", "4092", "Anomaly detected in VAD. Epistemic Doubt: 65%"
            )
            live.update(tui.render_layout())
            time.sleep(1.5)

            tui.update_state(
                "DECEPTION", "4092", "SHADOW NET & eBPF Interception Deployed."
            )
            live.update(tui.render_layout())
            time.sleep(1.5)

            tui.update_state("CRITICAL", "4092", "CRYOGENIC FREEZE EXECUTED (SIGSTOP).")
            live.update(tui.render_layout())
            time.sleep(1.5)

            tui.update_state(
                "DECEPTION",
                "4092",
                "MIRAGE OS Honeytokens injected into Lazarus Chamber.",
            )
            live.update(tui.render_layout())

            # THE INFINITE LOOP: Keeps the dashboard open until you press Ctrl+C
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        # Graceful exit without printing garbage characters
        print("\n[+] Dashboard terminated by User (Ctrl+C).")
        sys.exit(0)
