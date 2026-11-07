import math
import os
import sys
import json
import threading
import time
import re
import psutil
from datetime import datetime
from rich.align import Align
from rich.cells import cell_len
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_data import resolve_data_dir
from yomi_engine.library import OmniLibrary

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Obsidian Torii Gateway (v11.0)
# Purpose: Responsive, real-time, non-blocking Enterprise TUI center.
#          - Anti-Desynchronization: Visual overflow alert shield for logs.
#          - Strict Anti-Stale Size: -1 signature break for dynamic file re-creation.
#          - Control Char Immunity: Full block against \r, \b, \u202E spoofing.
#          - Total UI Decoupling: Zero /proc or disk I/O in the render loop.
#          - Adaptive layout: compact header and a dedicated 80x24 view; the
#            large logo only appears on tall terminals.
#          - Honest telemetry: benchmark figures come from the audit ledger
#            (where TelemetryEngine actually writes them), and "TAMPERED" is
#            shown only for a telemetry file that existed and then vanished.
# ==============================================================================

_PID_RE = re.compile(r"\bPID[\s:=_]*(\d{1,10})\b", re.IGNORECASE)
_SPEED_RE = re.compile(r"^(?P<base>.*?)\s*\(Sub-60s:\s*(?P<flag>\w+)\)\s*$")

# Higher number = more urgent. Used to stop a routine event from instantly
# overwriting the status of a recent, more serious one.
_STATUS_SEVERITY = {"SAFE": 0, "WARNING": 1, "DECEPTION": 2, "CRITICAL": 3}
_TAG_RE = re.compile(r"^\[([A-Za-z0-9_.\-]{1,40})\]\s*(.*)$", re.DOTALL)

# Ledger events that fire on every observation cycle and would drown the
# stream. Keyed by action; a non-empty agent set narrows the rule so that, for
# example, SWARM's per-cycle DEPLOYED is hidden while SHADOW_NET's is not.
_NOISY_EVENTS = {
    "TRIAGE_ITERATION": None,
    "MAX_ITERATIONS_REACHED": None,
    "BENCHMARK_RECORDED": None,
    "MAPPED": None,
    "STARTUP": None,
    "INITIALIZATION": None,
    "UI_START": None,
    "SENTINEL_INIT": None,
    "LEDGER_VERIFICATION": None,
    "DEPLOYED": {"SWARM"},
}


def extract_pid(text: str | None) -> str | None:
    """First ``PID <n>`` mentioned in free text, or None."""
    if not text:
        return None
    match = _PID_RE.search(text)
    return match.group(1) if match else None


def should_display_event(agent: str, action: str) -> bool:
    """False for routine per-cycle ledger events that only add noise."""
    if action not in _NOISY_EVENTS:
        return True
    only_agents = _NOISY_EVENTS[action]
    return only_agents is not None and str(agent).upper() not in only_agents


def classify_event(action: str, description: str, agent: str = "") -> str:
    """Maps a ledger event to the dashboard status it should raise."""
    action = str(action)
    description = str(description)
    agent = str(agent)
    if any(k in action for k in ("FREEZE", "THREAT", "CONTAINMENT", "FAILED")):
        return "CRITICAL"
    if "CRITICAL" in description.upper():
        return "CRITICAL"
    if "SHADOW" in action or "SHADOW" in agent.upper() or "MIRAGE" in description:
        return "DECEPTION"
    if "MIRAGE" in agent.upper():
        return "DECEPTION"
    if "DOUBT" in action or "ANOMALY" in action:
        return "WARNING"
    return "SAFE"


class YomiDashboard:
    VERSION = "1.0"
    HEADER_COMPACT_ROWS = 3
    HEADER_LOGO_ROWS = 13
    HEADER_LOGO_MIN_HEIGHT = 44
    FOOTER_ROWS = 1
    TELEMETRY_WIDTH = 40
    NARROW_WIDTH = 90
    SUMMARY_ROWS = 4
    MAX_LOG_RECORDS = 100
    # A more serious status is kept for this long before a calmer event may
    # replace it, so "SAFE" does not flash up seconds after a containment.
    STATUS_HOLD_SECONDS = 30
    CPU_SAMPLE_SECONDS = 0.5

    def __init__(self, lazy_library: bool = False):
        self.console = Console(file=sys.__stdout__)
        self.colors = {
            "void_black": "black",
            # "default" = the terminal's own foreground, so routine text stays
            # readable on both dark and light terminal themes.
            "ghost_white": "default",
            "obsidian": "#6E7681",
            "plasma_blue": "#58A6FF",
            "cyber_purple": "#BC8CFF",
            "blood_red": "#F85149",
            "warning": "#D29922",
            "green_matrix": "#3FB950",
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

        self._status_moment = None
        self.latest_ttc = "AWAITING INCIDENT"
        self.speed_multiplier = "N/A"
        self._last_tel_size = 0
        self._telemetry_seen = False
        self._last_ledger_size = -1

        self.cpu_usage = "0%"
        self.memory_usage = "0%"
        self.memory_status = "NORMAL"
        self.yomi_ram_mb = 0.0

        # Log State: action_log keeps the sanitized Text lines; _log_records
        # keeps the same events split into columns for rendering.
        self.action_log = []
        self._log_records = []
        self.started_at = time.monotonic()
        self.last_event_at = None

        # Library State. lazy_library=True builds OmniLibrary on the
        # background thread: its constructor probes the network with retries,
        # which would otherwise leave an air-gapped operator staring at a
        # blank screen before the first frame.
        self._lazy_library = lazy_library
        self.library = None if lazy_library else OmniLibrary()
        self.cve_count = 0
        self.last_cve_sync = "N/A"
        self.cve_source = "UNKNOWN"
        self.library_status = "STARTING" if lazy_library else "UNKNOWN"

        # psutil's first cpu_percent() call has nothing to compare against and
        # returns a meaningless number, so prime it now and only publish CPU
        # readings taken at least CPU_SAMPLE_SECONDS apart.
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass
        self._last_cpu_sample = time.monotonic()
        self._refresh_system_metrics()

        # Background Worker Thread
        self.is_running = True
        self._stop_event = threading.Event()
        self.worker_thread = threading.Thread(
            target=self._background_metrics_worker, daemon=True
        )
        self.worker_thread.start()

        # The library gets a thread of its own: its constructor can block for
        # several seconds on a network probe, and the CPU/RAM/telemetry
        # refresh above must keep running meanwhile.
        if lazy_library:
            threading.Thread(target=self._init_library, daemon=True).start()

    def stop(self):
        """Signals the daemon thread to terminate instantly without sleeping."""
        self._stop_event.set()
        self.is_running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)
        library = self.library
        if library is not None:
            try:
                library.shutdown()
            except Exception:
                pass

    def _init_library(self):
        try:
            self.library = OmniLibrary()
        except Exception:
            with self._telemetry_lock:
                self.library_status = "ERROR"

    def _background_metrics_worker(self):
        """Background Daemon: Executes gracefully with interruptible wait."""
        while not self._stop_event.is_set() and self.is_running:
            self._refresh_system_metrics()
            self._refresh_library_metrics()
            self._refresh_telemetry_metrics()
            self._stop_event.wait(1.0)

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _style(self, key: str, bold: bool = False) -> str:
        color = self.colors[key]
        if color == "default":
            return "bold" if bold else ""
        return f"bold {color}" if bold else color

    def _status_key(self, status: str) -> str:
        status = str(status)
        if "CRITICAL" in status or "OVERLOAD" in status:
            return "blood_red"
        if "DECEPTION" in status:
            return "cyber_purple"
        if "WARNING" in status:
            return "warning"
        if status == "SAFE":
            return "green_matrix"
        return "plasma_blue"

    def _badge(self, status: str) -> Text:
        color = self.colors[self._status_key(status)]
        return Text(f" {status} ", style=f"bold black on {color}", no_wrap=True)

    def _speed_summary(self) -> str:
        """'401.7x (Sub-60s: True)' -> '401.7x · sub-60s' (short enough to fit)."""
        match = _SPEED_RE.match(self.speed_multiplier)
        if not match:
            return self.speed_multiplier
        base, flag = match.group("base"), match.group("flag")
        if flag == "True":
            return f"{base} · sub-60s"
        if flag == "False":
            return f"{base} · over 60s"
        return base

    def _uptime(self) -> str:
        seconds = int(time.monotonic() - self.started_at)
        hours, rest = divmod(seconds, 3600)
        minutes, secs = divmod(rest, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

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

    # ------------------------------------------------------------------
    # Panels
    # ------------------------------------------------------------------

    def make_header(self, show_logo: bool = False) -> Panel:
        width = self.console.size.width
        with self._telemetry_lock:
            status = self.current_status

        left = Text(no_wrap=True, overflow="ellipsis")
        left.append("◆ ", style=self._style("plasma_blue", bold=True))
        left.append("YOMI TRIAGE SYSTEM", style="bold")
        if width >= 100:
            left.append(
                f"   Autonomous DFIR Triage Engine v{self.VERSION}", style="dim"
            )
        left.append("   KUROTECH", style=self._style("obsidian"))

        right = Text(no_wrap=True)
        right.append_text(self._badge(status))
        right.append(f"  {datetime.now().strftime('%H:%M:%S')}", style="dim")

        row = Table.grid(expand=True)
        row.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        row.add_column(justify="right", no_wrap=True)
        row.add_row(left, right)

        body = Group(self.generate_torii_logo(), row) if show_logo else row
        return Panel(
            body,
            box=box.ROUNDED,
            border_style=self.colors["obsidian"],
            padding=(0, 1),
        )

    def _metric_style(self, key: str) -> str:
        return self._style(key)

    def make_telemetry_panel(self) -> Panel:
        with self._telemetry_lock:
            grid = Table.grid(expand=True, padding=(0, 1))
            grid.add_column(no_wrap=True)
            grid.add_column(justify="right", no_wrap=True, overflow="ellipsis", ratio=1)

            def section(title: str, first: bool = False) -> None:
                if not first:
                    grid.add_row("", "")
                grid.add_row(
                    Text(title, style=self._style("obsidian", bold=True)), Text("")
                )

            def row(label: str, value: str, style: str = "") -> None:
                grid.add_row(Text(label, style="dim"), Text(str(value), style=style))

            section("INCIDENT", first=True)
            row(
                "Status",
                self.current_status,
                self._style(self._status_key(self.current_status), bold=True),
            )
            row("Target PID", self.active_pid, self._style("warning", bold=True))
            row("Epistemic doubt", self.epistemic_doubt)
            tampered = "TAMPERED" in self.latest_ttc
            row(
                "Latency",
                self.latest_ttc,
                self._style("blood_red" if tampered else "green_matrix", bold=True),
            )
            row(
                "Speed",
                self._speed_summary(),
                self._style("blood_red" if tampered else "green_matrix"),
            )

            section("SENSORS")
            row("eBPF sentinel", self.ebpf_status)

            section("HOST")
            memory_key = {"CRITICAL": "blood_red", "WARNING": "warning"}.get(
                self.memory_status, "green_matrix"
            )
            row("Yomi RAM", f"{self.yomi_ram_mb:.1f} MB")
            row("CPU", self.cpu_usage)
            row(
                "Memory",
                f"{self.memory_status} · {self.memory_usage}",
                self._style(memory_key),
            )

            section("INTELLIGENCE")
            row("CVE records", f"{self.cve_count:,}")
            library_key = {
                "ONLINE": "green_matrix",
                "ERROR": "blood_red",
                "STARTING": "warning",
            }.get(self.library_status, "plasma_blue")
            row("Library", self.library_status, self._style(library_key))

        return Panel(
            grid,
            title=Text("TELEMETRY", style="bold"),
            title_align="left",
            box=box.ROUNDED,
            border_style=self.colors["obsidian"],
            padding=(0, 1),
        )

    def make_summary_panel(self) -> Panel:
        """Two-line stand-in for the telemetry panel on narrow terminals."""
        with self._telemetry_lock:
            status = self.current_status
            first = Text(no_wrap=True, overflow="ellipsis")
            first.append_text(self._badge(status))
            first.append(f"  PID {self.active_pid}", style="dim")
            first.append(f"  Doubt {self.epistemic_doubt}", style="dim")
            first.append(f"  Latency {self.latest_ttc}", style="dim")

            second = Text(no_wrap=True, overflow="ellipsis", style="dim")
            second.append(f"CPU {self.cpu_usage}  RAM {self.yomi_ram_mb:.0f} MB")
            second.append(f"  Mem {self.memory_status}  eBPF {self.ebpf_status}")
            second.append(f"  CVE {self.cve_count:,}  {self.library_status}")

        return Panel(
            Group(first, second),
            box=box.ROUNDED,
            border_style=self.colors["obsidian"],
            padding=(0, 1),
        )

    def _visible_records(self, rows: int, message_width: int) -> list:
        """Newest records that fit in `rows` terminal rows once wrapped."""
        with self._log_lock:
            records = list(self._log_records)
        message_width = max(10, message_width)
        chosen = []
        used = 0
        for record in reversed(records):
            lines = max(1, math.ceil(cell_len(record["message"]) / message_width))
            if chosen and used + lines > rows:
                break
            chosen.append(record)
            used += lines
        chosen.reverse()
        return chosen

    def make_log_panel(self, rows: int | None = None, width: int | None = None) -> Panel:
        size = self.console.size
        width = width if width is not None else size.width
        if rows is None:
            rows = max(3, size.height - self.HEADER_COMPACT_ROWS - self.FOOTER_ROWS - 2)
        # Inner width (border + padding = 4) minus the time and level columns
        # and the gaps the grid puts around them (15 in total).
        message_width = width - 4 - 15

        records = self._visible_records(rows, message_width)
        with self._log_lock:
            total = len(self._log_records)

        if not records:
            body = Group(
                Text(""),
                Align.center(
                    Text("Monitoring. No incidents recorded yet.", style="dim italic")
                ),
            )
        else:
            grid = Table.grid(padding=(0, 1), expand=True)
            grid.add_column(width=8, no_wrap=True)
            grid.add_column(width=4, no_wrap=True)
            grid.add_column(ratio=1)
            for record in records:
                message = Text(overflow="fold")
                if record["tag"]:
                    message.append(record["tag"], style=record["level_style"])
                    message.append("  ")
                message.append(record["body"], style=record["style"])
                grid.add_row(
                    Text(record["time"], style="dim"),
                    Text(record["level"], style=record["level_style"]),
                    message,
                )
            body = grid

        return Panel(
            body,
            title=Text("ACTIVITY", style="bold"),
            title_align="left",
            subtitle=Text(f"{total} event{'s' if total != 1 else ''}", style="dim"),
            subtitle_align="right",
            box=box.ROUNDED,
            border_style=self.colors["obsidian"],
            padding=(0, 1),
        )

    def make_footer(self) -> Table:
        left = Text(no_wrap=True, style="dim")
        left.append("Ctrl+C", style="bold")
        left.append(" exit")
        left.append(f"   uptime {self._uptime()}")
        if self.last_event_at is None:
            right = Text("no events yet", style="dim", no_wrap=True)
        else:
            right = Text(
                f"last event {self.last_event_at.strftime('%H:%M:%S')}",
                style="dim",
                no_wrap=True,
            )
        footer = Table.grid(expand=True)
        footer.add_column(ratio=1, no_wrap=True)
        footer.add_column(justify="right", no_wrap=True)
        footer.add_row(left, right)
        return footer

    # ------------------------------------------------------------------
    # State updates
    # ------------------------------------------------------------------

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

    def update_state(
        self,
        status: str,
        pid: str = None,
        recent_log: str = None,
        when: datetime = None,
    ):
        # pid None (or the legacy placeholder "AUTO") means "keep the current
        # target, but pick up a PID named in the event text if there is one".
        if pid in (None, "AUTO"):
            pid = extract_pid(recent_log)

        event_status = status
        moment = when or datetime.now()
        with self._telemetry_lock:
            current = self.current_status
            held_since = self._status_moment
        incoming = _STATUS_SEVERITY.get(status)
        holding = _STATUS_SEVERITY.get(current)
        if (
            incoming is not None
            and holding is not None
            and incoming < holding
            and held_since is not None
            and 0 <= (moment - held_since).total_seconds() < self.STATUS_HOLD_SECONDS
        ):
            status = current  # keep the more serious recent status
        else:
            with self._telemetry_lock:
                self._status_moment = moment

        self.update_telemetry(status=status, pid=pid)
        if recent_log:
            # The line's own severity, even when the headline status is held.
            self.append_log(recent_log, when=when, status=event_status)

    # ------------------------------------------------------------------
    # Data refresh (background thread)
    # ------------------------------------------------------------------

    def _data_root(self) -> str:
        return resolve_data_dir(
            os.path.join(os.path.dirname(__file__), "..", "yomi_data")
        )

    def _refresh_telemetry_metrics(self):
        root = self._data_root()
        tel_path = os.path.join(root, "telemetry_benchmarks.jsonl")

        if os.path.exists(tel_path):
            self._telemetry_seen = True
            self._refresh_from_telemetry_file(tel_path)
            return

        if self._telemetry_seen:
            # The file existed earlier in this session and is now gone: that
            # one is worth a loud alert.
            with self._telemetry_lock:
                self.latest_ttc = "[TAMPERED] FILE MISSING"
                self.speed_multiplier = "TELEMETRY FILE REMOVED"
                # Set last size to -1 instead of 0 to prevent 0==0 stale lock upon re-creation
                self._last_tel_size = -1
            return

        with self._telemetry_lock:
            self._last_tel_size = -1
        # TelemetryEngine records benchmarks in the audit ledger, not in a
        # separate file, so that is the real data source on a normal install.
        self._refresh_from_ledger(os.path.join(root, ImmutableStamp.LEDGER_FILENAME))

    def _refresh_from_telemetry_file(self, tel_path: str):
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
                            self.speed_multiplier = f"{speed} (Sub-60s: {latest.get('sub_60s_containment')})"
                            self._last_tel_size = current_size
                        return
                    except json.JSONDecodeError:
                        continue
        except (OSError, ValueError):
            pass

    def _refresh_from_ledger(self, ledger_path: str):
        try:
            size = os.stat(ledger_path).st_size
            if size == self._last_ledger_size:
                return
            with open(ledger_path, "rb") as f:
                f.seek(max(0, size - 65536))
                tail = f.read().decode("utf-8", errors="replace")
        except OSError:
            return

        for line in reversed(tail.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue  # e.g. the partial first line of the tail window
            if not isinstance(entry, dict) or entry.get("action_type") != "BENCHMARK_RECORDED":
                continue
            metadata = entry.get("metadata")
            if not isinstance(metadata, dict):
                continue
            with self._telemetry_lock:
                self.latest_ttc = f"{metadata.get('latency_seconds', 0)}s"
                speed = metadata.get("human_speed_multiplier", "")
                self.speed_multiplier = f"{speed} (Sub-60s: {metadata.get('sub_60s_containment')})"
            break
        self._last_ledger_size = size

    def _refresh_library_metrics(self):
        library = self.library
        if library is None:
            return
        try:
            meta = library.get_metadata()
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
            now = time.monotonic()
            cpu_percent = None
            if now - self._last_cpu_sample >= self.CPU_SAMPLE_SECONDS:
                cpu_percent = psutil.cpu_percent(interval=None)
                self._last_cpu_sample = now
            mem = psutil.virtual_memory()
            mem_percent = mem.percent

            yomi_process = psutil.Process(os.getpid())
            ram_mb = yomi_process.memory_info().rss / (1024 * 1024)

            with self._telemetry_lock:
                if cpu_percent is not None:
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

    # ------------------------------------------------------------------
    # Log intake
    # ------------------------------------------------------------------

    def append_log(self, raw_text: str, when: datetime = None, status: str = None):
        # Pre-evaluate threat keywords BEFORE truncation for 100% color fidelity
        threat_detected = any(
            k in raw_text for k in ["ERROR", "CRITICAL", "FREEZE", "OVERLOAD"]
        )
        purple_detected = any(
            k in raw_text for k in ["SHADOW NET", "SHADOW_NET", "MIRAGE"]
        )
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

        moment = when or datetime.now()
        timestamp = moment.strftime("%H:%M:%S")

        log_key = "ghost_white"
        level = "INFO"
        if threat_detected:
            log_key, level = "blood_red", "CRIT"
        elif purple_detected:
            log_key, level = "cyber_purple", "DECP"
        elif warning_detected:
            log_key, level = "warning", "WARN"
        elif success_detected:
            log_key, level = "green_matrix", "OK"
        if log_key == "ghost_white":
            # No keyword matched: fall back to the status the caller assigned.
            hint = {
                "CRITICAL": ("blood_red", "CRIT"),
                "DECEPTION": ("cyber_purple", "DECP"),
                "WARNING": ("warning", "WARN"),
            }.get(status)
            if hint:
                log_key, level = hint
        log_style = self.colors[log_key]

        styled_log = Text(f"[{timestamp}] {clean_text}", style=log_style)

        tag_match = _TAG_RE.match(clean_text)
        tag, body = (tag_match.group(1), tag_match.group(2)) if tag_match else ("", clean_text)
        record = {
            "time": timestamp,
            "level": level,
            "level_style": self._style(log_key, bold=True),
            "style": "" if log_style == "default" else log_style,
            "tag": tag,
            "body": body,
            "message": f"{tag}  {body}" if tag else body,
        }

        with self._log_lock:
            self.action_log.append(styled_log)
            self._log_records.append(record)
            if len(self.action_log) > self.MAX_LOG_RECORDS:
                self.action_log = self.action_log[-self.MAX_LOG_RECORDS :]
                self._log_records = self._log_records[-self.MAX_LOG_RECORDS :]
        self.last_event_at = moment

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def render_layout(self) -> Layout:
        size = self.console.size
        width, height = size.width, size.height

        show_logo = height >= self.HEADER_LOGO_MIN_HEIGHT
        header_rows = self.HEADER_LOGO_ROWS if show_logo else self.HEADER_COMPACT_ROWS
        body_rows = max(3, height - header_rows - self.FOOTER_ROWS)

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=header_rows),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=self.FOOTER_ROWS),
        )
        layout["header"].update(self.make_header(show_logo=show_logo))
        layout["footer"].update(self.make_footer())

        if width < self.NARROW_WIDTH:
            summary_rows = min(self.SUMMARY_ROWS, max(0, body_rows - 4))
            if summary_rows:
                layout["body"].split_column(
                    Layout(name="telemetry", size=summary_rows),
                    Layout(name="logs", ratio=1),
                )
                layout["telemetry"].update(self.make_summary_panel())
                layout["logs"].update(
                    self.make_log_panel(rows=body_rows - summary_rows - 2, width=width)
                )
            else:
                layout["body"].update(self.make_log_panel(rows=body_rows - 2, width=width))
        else:
            telemetry_width = self.TELEMETRY_WIDTH
            layout["body"].split_row(
                Layout(name="telemetry", size=telemetry_width),
                Layout(name="logs", ratio=1),
            )
            layout["telemetry"].update(self.make_telemetry_panel())
            layout["logs"].update(
                self.make_log_panel(rows=body_rows - 2, width=width - telemetry_width)
            )

        return layout
