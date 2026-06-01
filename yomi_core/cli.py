import argparse
import contextlib
import logging
import os
import platform
import shlex
import sys
import threading
import time
from pathlib import Path

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_core.sentinel import SentinelDaemon
from yomi_core.ghost import GhostProtocol
from yomi_data import validate_data_store, read_latest_ledger_entry

try:
    from rich.live import Live
except ImportError:  # pragma: no cover
    Live = None

# ==============================================================================
# YOMI TRIAGE SYSTEM: Phase 6.2 - The Final Wrap (CLI Entry Point)
# Purpose: The absolute command center. Handles Air-Gapped execution,
#          Boot Persistence (Startup), and TUI/Sentinel Threading.
# ============================================================================

logger = logging.getLogger("yomi.cli")
if not logger.handlers:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(console_handler)
logger.setLevel(logging.INFO)


class DataSecurityError(Exception):
    pass


def _secure_path(path: Path, mode: int) -> None:
    try:
        if path.exists():
            path.chmod(mode)
    except OSError:
        logger.debug("Unable to set secure permissions for %s", path)


def _assert_path_integrity(path: Path) -> None:
    if path.is_symlink():
        raise DataSecurityError(f"Path integrity violation: {path} is a symlink.")
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise DataSecurityError(
                f"Path integrity violation: ancestor {ancestor} of {path} is a symlink."
            )
    if os.name == "posix" and path.exists():
        owner_uid = path.stat().st_uid
        safe_owner_ids = {0, os.getuid()}
        if owner_uid not in safe_owner_ids:
            raise DataSecurityError(
                f"Ownership violation: {path} is owned by UID {owner_uid}, expected one of {safe_owner_ids}."
            )


def _assert_data_store_integrity(validated: dict) -> None:
    data_dir = Path(validated["data_dir"])
    _assert_path_integrity(data_dir)
    _assert_path_integrity(Path(validated["ledger_file"]))
    _assert_path_integrity(Path(validated["manifest_file"]))
    if validated["migrated_archive"]:
        _assert_path_integrity(Path(validated["migrated_archive"]))
    logger.info("Data store integrity assertions passed for %s", data_dir)


def _record_audit_event(
    audit: ImmutableStamp,
    action_type: str,
    description: str,
    metadata: dict | None = None,
    raw_command: str = "",
    tool_args: dict | None = None,
) -> None:
    try:
        audit.record_action(
            "CLI",
            action_type,
            description,
            raw_command=raw_command,
            tool_args=tool_args or {},
            metadata=metadata,
        )
    except Exception as exc:
        logger.warning("Unable to record CLI audit event %s: %s", action_type, exc)


def install_persistence() -> None:
    """Generates a secure host persistence artifact for the current platform."""
    os_name = platform.system()
    logger.info("Initiating OS-level boot persistence for Yomi.")
    try:
        validated = validate_data_store()
        _assert_data_store_integrity(validated)
        audit = ImmutableStamp()
        _record_audit_event(
            audit,
            "INSTALL_PERSISTENCE",
            "Generated host persistence artifact.",
            metadata={
                "platform": os_name,
                "data_dir": validated["data_dir"],
                "manifest_total_count": validated.get("manifest_total_count"),
                "actual_total_count": validated.get("actual_total_count"),
            },
        )
    except Exception as exc:
        logger.warning("Persistence installation audit path unavailable: %s", exc)
        audit = None

    script_path = Path(sys.argv[0]).resolve()
    if not script_path.exists():
        logger.error("Unable to resolve CLI entrypoint path for persistence installation.")
        return

    if os_name == "Linux":
        service_file = Path.cwd() / "yomi-triage.service"
        service_payload = (
            f"[Unit]\n"
            f"Description=Yomi Autonomous DFIR Engine\n"
            f"After=network.target\n\n"
            f"[Service]\n"
            f"Type=simple\n"
            f"ExecStart={shlex.quote(sys.executable)} {shlex.quote(str(script_path))} --auto --headless\n"
            f"Restart=always\n"
            f"RestartSec=3\n"
            f"User=root\n\n"
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )
        service_file.write_text(service_payload, encoding="utf-8")
        _secure_path(service_file, 0o600)
        logger.info(
            "Persistence artifact created: %s. Move to /etc/systemd/system/ as root.",
            service_file,
        )
    elif os_name == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(
                key,
                "YomiTriageSystem",
                0,
                winreg.REG_SZ,
                f'"{sys.executable}" "{script_path}" --auto --headless',
            )
            winreg.CloseKey(key)
            logger.info("Windows persistence successfully configured in registry.")
            if audit:
                _record_audit_event(
                    audit,
                    "INSTALL_PERSISTENCE",
                    "Installed Windows registry persistence.",
                    metadata={"target": "registry"},
                )
        except Exception as exc:
            logger.error("Failed to create Windows persistence: %s", exc)
            if audit:
                _record_audit_event(
                    audit,
                    "INSTALL_PERSISTENCE_FAILED",
                    "Failed to install Windows persistence.",
                    metadata={"error": str(exc)},
                )
    else:
        logger.warning("Unsupported persistence installation platform: %s", os_name)
        if audit:
            _record_audit_event(
                audit,
                "INSTALL_PERSISTENCE_UNSUPPORTED",
                "Persistence installation unsupported on this platform.",
                metadata={"platform": os_name},
            )


def _prepare_runtime_environment() -> ImmutableStamp:
    validated = validate_data_store()
    _assert_data_store_integrity(validated)
    logger.info("Validated Yomi data store: %s", validated)

    audit = ImmutableStamp()
    if not audit.verify_ledger():
        logger.warning("Immutable ledger verification reported an integrity issue.")
        _record_audit_event(
            audit,
            "LEDGER_VERIFICATION_WARNING",
            "Immutable ledger verification detected an integrity issue.",
        )
    if not audit.verify_soc_checkpoint():
        logger.warning("Notary checkpoint validation failed or is unavailable.")
        _record_audit_event(
            audit,
            "SOC_CHECKPOINT_WARNING",
            "Notary checkpoint validation failed or is unavailable.",
        )

    _record_audit_event(
        audit,
        "STARTUP",
        "Yomi CLI initialized and verified local data store integrity.",
        metadata={
            "data_dir": validated["data_dir"],
            "ledger_file": validated["ledger_file"],
            "manifest_file": validated["manifest_file"],
            "migrated_archive": validated["migrated_archive"],
            "manifest_total_count": validated.get("manifest_total_count"),
            "actual_total_count": validated.get("actual_total_count"),
            "counts_match": validated.get("counts_match"),
            "year_files": validated.get("year_files"),
            "corrupt_year_files": validated.get("corrupt_year_files"),
        },
        raw_command=" ".join(shlex.quote(arg) for arg in sys.argv),
        tool_args={"auto": True},
    )
    return audit


def _run_sentinel_daemon(audit: ImmutableStamp) -> threading.Thread:
    def _daemon_worker() -> None:
        sentinel = SentinelDaemon()
        with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
            sentinel.start()

    thread = threading.Thread(target=_daemon_worker, daemon=True)
    thread.start()
    _record_audit_event(
        audit,
        "SENTINEL_INIT",
        "Spawned Sentinel background daemon.",
        metadata={"daemon": "Sentinel"},
    )
    logger.info("Sentinel daemon started in background.")
    return thread


def _get_latest_ledger_log() -> dict | None:
    latest = read_latest_ledger_entry()
    if latest is None:
        return None
    return latest


def _run_console_loop(audit: ImmutableStamp) -> None:
    _record_audit_event(
        audit,
        "UI_FALLBACK",
        "Falling back to console gateway because dashboard UI is unavailable.",
    )
    last_hash = ""
    try:
        while True:
            latest_entry = _get_latest_ledger_log()
            if latest_entry is not None:
                current_hash = latest_entry.get("hash", "")
                if current_hash and current_hash != last_hash:
                    last_hash = current_hash
                    action_name = latest_entry.get("action_type", "SYSTEM_UPDATE")
                    description = latest_entry.get("description", "")
                    logger.info("Ledger update detected: %s - %s", action_name, description)
            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Console gateway closed by operator. Background Sentinel may continue.")
        _record_audit_event(audit, "SHUTDOWN", "CLI console gateway received keyboard interrupt.")


def _run_tui_loop(audit: ImmutableStamp) -> None:
    if Live is None:
        logger.warning("Rich runtime is unavailable. Using fallback console gateway.")
        _run_console_loop(audit)
        return

    try:
        from yomi_core.dashboard import YomiDashboard
    except ImportError as exc:
        logger.warning(
            "Dashboard UI module unavailable (%s); falling back to console gateway.", exc
        )
        _record_audit_event(
            audit,
            "UI_FALLBACK",
            "Dashboard UI module not available; using console gateway.",
            metadata={"reason": str(exc)},
        )
        _run_console_loop(audit)
        return

    _record_audit_event(audit, "UI_START", "Launching dashboard UI gateway.")
    tui = YomiDashboard()
    last_hash = ""

    try:
        with Live(tui.render_layout(), refresh_per_second=4, screen=True) as live:
            while True:
                latest_entry = _get_latest_ledger_log()
                if latest_entry is not None:
                    current_hash = latest_entry.get("hash", "")
                    if current_hash and current_hash != last_hash:
                        last_hash = current_hash
                        action_name = latest_entry.get("action_type", "SYSTEM_UPDATE")
                        description = latest_entry.get("description", "")

                        status = "SAFE"
                        if "FREEZE" in action_name or "CRITICAL" in description:
                            status = "CRITICAL"
                        elif "SHADOW" in action_name or "MIRAGE" in description:
                            status = "DECEPTION"
                        elif "DOUBT" in action_name or "ANOMALY" in action_name:
                            status = "WARNING"

                        tui.update_state(status, "AUTO", f"[{action_name}] {description}")
                        live.update(tui.render_layout())
                time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Obsidian Torii Gateway closed by operator. Background Sentinel may continue.")
        _record_audit_event(audit, "SHUTDOWN", "CLI dashboard gateway shut down by keyboard interrupt.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Yomi Triage System - Autonomous DFIR")
    parser.add_argument("--auto", action="store_true", help="Launch full autonomous triage mode")
    parser.add_argument(
        "--install",
        action="store_true",
        help="Generate boot persistence artifacts for supported OSes.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without UI (for background daemon).",
    )
    args = parser.parse_args()

    if args.headless and not args.auto:
        parser.error("--headless requires --auto.")

    if args.install and (args.auto or args.headless):
        parser.error("--install cannot be combined with --auto or --headless.")

    if args.install:
        install_persistence()
        sys.exit(0)

    if args.auto:
        audit = _prepare_runtime_environment()
        if os.environ.get("YOMI_ENABLE_GHOST_PROTOCOL", "false").lower() in ("1", "true", "yes"):
            try:
                ghost = GhostProtocol()
                ghost.engage_camouflage()
                _record_audit_event(audit, "GHOST_PROTOCOL", "GhostProtocol engaged camouflage.")
            except Exception as exc:
                logger.warning("GhostProtocol failed: %s", exc)
                _record_audit_event(
                    audit,
                    "GHOST_PROTOCOL_FAILURE",
                    "GhostProtocol camouflage failed.",
                    metadata={"error": str(exc)},
                )
        else:
            logger.info("GhostProtocol is disabled by default. Set YOMI_ENABLE_GHOST_PROTOCOL=true to enable it.")

        _run_sentinel_daemon(audit)
        if args.headless:
            logger.info("Running in headless mode. CLI is now maintaining background services.")
            try:
                while True:
                    time.sleep(10)
            except KeyboardInterrupt:
                logger.info("Headless mode interrupted by user.")
                _record_audit_event(audit, "SHUTDOWN", "Headless mode interrupted by user.")
                sys.exit(0)

        _run_tui_loop(audit)
        _record_audit_event(audit, "SHUTDOWN", "Yomi CLI exited from interactive mode.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
