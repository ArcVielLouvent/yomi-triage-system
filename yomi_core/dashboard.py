import time
import json
import os
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Dark Map
# Purpose: Tactical TUI Dashboard reading from the Immutable Stamp in real-time.
# ==============================================================================

LOG_FILE = "/workspaces/yomi-triage-system/yomi_data/yomi_chain_of_custody.jsonl"

def generate_layout():
    """Creates the grid layout for the dashboard."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=10)
    )
    layout["main"].split_row(
        Layout(name="intel_panel"),
        Layout(name="action_panel")
    )
    return layout

def get_latest_logs(max_lines=8):
    """Reads the tail of the immutable stamp log."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()
        logs = []
        for line in lines[-max_lines:]:
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return logs

def build_dashboard():
    """Updates the dashboard panels based on log data."""
    logs = get_latest_logs()
    
    # 1. HEADER
    header = Panel(Align.center(Text("YOMI AUTONOMOUS DFIR COMMAND CENTER", style="bold red")), style="red")

    # 2. FOOTER (Live Audit Trail)
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Timestamp", style="dim", width=25)
    table.add_column("Agent", style="cyan", width=15)
    table.add_column("Action", style="green", width=20)
    table.add_column("Description", style="white")

    for log in logs:
        # Extracting data safely
        ts = log.get("timestamp", "")[:19] # Cut microseconds
        agent = log.get("agent", "Unknown")
        action = log.get("action_type", "")
        desc = log.get("description", "")
        table.add_row(ts, agent, action, desc)

    footer = Panel(table, title="[bold green]Live Immutable Audit Trail", style="green")

    # 3. INTEL PANEL (Left) & ACTION PANEL (Right)
    # We scan the logs to see what the current status is
    latest_action = logs[-1].get("action_type", "") if logs else "IDLE"
    
    intel_content = Text("\nWaiting for Swarm Telemetry...", style="dim")
    action_content = Text("\nNo Active Threats.", style="dim")

    if "SWARM" in latest_action:
        intel_content = Text("\n[!] SWARM DEPLOYED: Scanning Processes, Network, and Files...", style="bold yellow")
    elif "ROOT_CAUSE" in latest_action:
        intel_content = Text("\n[+] REVERSE TRACKING: Analyzing temporal logs for Patient Zero...", style="bold cyan")
    elif "THREAT_INTEL" in latest_action:
        intel_content = Text("\n[!] CVE MATCH FOUND: Retrieving tactical data from Omni-Library...", style="bold red")

    if "PLAYBOOK" in latest_action:
        action_content = Text("\n[!] PLAYBOOK DRAFTED: Remediation script is ready for Commander approval.", style="bold red blink")
    elif "HONEYPOT" in latest_action or "DETONATE" in latest_action:
        action_content = Text("\n[+] ACTIVE DEFENSE: Sandbox and Decoys are currently LIVE.", style="bold magenta")

    intel_panel = Panel(Align.center(intel_content, vertical="middle"), title="[bold yellow]Swarm & Intel Radar", style="yellow")
    action_panel = Panel(Align.center(action_content, vertical="middle"), title="[bold red]Action & Remediation", style="red")

    # Assemble
    layout = generate_layout()
    layout["header"].update(header)
    layout["footer"].update(footer)
    layout["main"]["intel_panel"].update(intel_panel)
    layout["main"]["action_panel"].update(action_panel)
    
    return layout

# ==============================================================================
# MAIN LOOP
# ==============================================================================
if __name__ == "__main__":
    os.system('clear')
    with Live(build_dashboard(), refresh_per_second=2, screen=True) as live:
        try:
            while True:
                live.update(build_dashboard())
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass