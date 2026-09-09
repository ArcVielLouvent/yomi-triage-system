"""
YOMI TRIAGE SYSTEM: Core Module - Guardian Orchestrator
Purpose: The single place that decides which of Yomi's deep-dive /
         optional modules fire in response to a triage outcome, gated
         ENTIRELY by yomi_core.module_registry -- never by ad-hoc env
         vars scattered across call sites.

This closes docs/known_issues.md #11: sentinel.py's autonomous loop
used to wire in only 5 of 13 modules (swarm, hunter, router,
mitre_mapper, telemetry); mind_reader, shadow_net, remediator, dossier,
mirage, sandbox, ghost, and ebpf_sensor existed and were independently
tested, but were only reachable via each file's own
`if __name__ == "__main__"` block. GuardianOrchestrator wires all of
them into the autonomous loop, gated by the registry.

DESIGN CONSTRAINTS (read before changing this file):

1. Single investigation at a time, single process. See
   docs/known_issues.md #9: ImmutableStamp's singleton + hardcoded
   __file__-relative data_dir means Yomi is architected for ONE
   concurrent investigation per process today. Multi-tenant/concurrent
   investigation is an explicit, separate, EXPLICITLY DEFERRED
   architectural decision -- this module does not attempt to solve it,
   and assumes the same single-investigation model sentinel.py already
   uses.

2. shadow_net.deploy_micro_hook() is fire-and-forget: it spawns a
   monitoring thread and returns "DEPLOYED" immediately. Its own
   kill_chain() already handles containment + ELF necromancy recovery
   for that path, independently, later, on a background thread. Guardian
   does NOT try to synchronously chain MindReader/Sandbox/Remediator off
   of a Shadow Net deployment -- the outcome isn't known at call time,
   and doing so would be a race condition against that thread. Deep-dive
   modules only fire off SYNCHRONOUS containment successes: the instant
   CRITICAL SIGSTOP path, or a harness result with
   status=="SUCCESS" and action=="FROZEN". At those points target_pid is
   deterministically already stopped.

3. Every dispatch is wrapped in try/except and logged to the ledger on
   failure rather than raised -- one module misbehaving (e.g. Radare2
   missing, sandbox mount failing) must never take down the observation
   loop or block the modules after it in the dispatch order.

4. Two modules (Ghost Protocol, Mirage) had their OWN internal ad-hoc
   env var gates (YOMI_ENABLE_GHOST_PROTOCOL in cli.py,
   YOMI_ENABLE_MIRAGE_MODE inside mirage.py itself) layered on top of
   module_registry's YOMI_MODULE_<KEY> scheme -- two parallel toggle
   mechanisms for the same decision. Guardian resolves this by making
   module_registry the ONLY source of truth it consults: it calls
   Mirage with force_enable=True (bypassing mirage.py's own env check,
   since the enable decision was already made at the registry level),
   and cli.py's Ghost Protocol startup wiring now reads the registry
   instead of YOMI_ENABLE_GHOST_PROTOCOL directly (see
   bootstrap_startup_daemons below). The old env vars are left working
   for direct/manual module invocation (backward compatible), but
   Guardian itself never depends on them. Captured as docs/known_issues.md
   #25/#26.
"""
from __future__ import annotations

import os
import platform
from typing import Optional

from yomi_audit.stamp import ImmutableStamp
from yomi_core import module_registry


def _resolve_exe_path(pid: int) -> str:
    """
    Best-effort /proc/<pid>/exe resolution for a PID that is known to be
    frozen (SIGSTOP'd) at call time. Returns "" if unavailable -- the
    process has already exited, the binary is fileless (self-deleted),
    or this isn't Linux. An empty return is a normal, expected outcome
    that callers must handle gracefully, not an error.
    """
    try:
        raw = os.readlink(f"/proc/{pid}/exe")
        return raw.replace(" (deleted)", "")
    except OSError:
        return ""


class GuardianOrchestrator:
    """
    Wires deep-dive modules into the autonomous triage loop. Modules are
    imported and instantiated LAZILY -- a module disabled in the
    registry is never even imported, matching the "invasive tiers
    default OFF" safety posture module_registry.py already documents.
    """

    def __init__(self):
        self.audit = ImmutableStamp()
        self._active = module_registry.resolve_active_modules()
        self._cycle_count = 0

        self._mind_reader = None
        self._shadow_net = None
        self._remediator = None
        self._dossier = None
        self._mirage = None
        self._sandbox = None

    def is_enabled(self, key: str) -> bool:
        return key in self._active

    # -- lazy accessors: only imported/instantiated if enabled ----------

    def _get_mind_reader(self):
        if self._mind_reader is None:
            from yomi_engine.mind_reader import MindReaderDecompiler
            self._mind_reader = MindReaderDecompiler()
        return self._mind_reader

    def _get_shadow_net(self):
        if self._shadow_net is None:
            from yomi_engine.shadow_net import ShadowNetProtocol
            self._shadow_net = ShadowNetProtocol()
        return self._shadow_net

    def _get_remediator(self):
        if self._remediator is None:
            from yomi_engine.remediator import ReverserEngine
            self._remediator = ReverserEngine()
        return self._remediator

    def _get_dossier(self):
        if self._dossier is None:
            from yomi_engine.dossier import CourtReadyDossier
            self._dossier = CourtReadyDossier()
        return self._dossier

    def _get_mirage(self):
        if self._mirage is None:
            from yomi_engine.mirage import MirageProtocol
            self._mirage = MirageProtocol()
        return self._mirage

    def _get_sandbox(self):
        if self._sandbox is None:
            from yomi_engine.sandbox import SandboxEnvironment
            self._sandbox = SandboxEnvironment()
        return self._sandbox

    # -- dispatch: escalation (async path) -------------------------------

    def handle_escalation(self, target_pid: int, reason: str) -> dict:
        """
        Fires when the router exhausts self-correction and returns
        ESCALATED_TO_SHADOW_NET. Fire-and-forget: deploy_micro_hook()
        spawns its own monitoring thread and Shadow Net's own
        kill_chain() owns containment + ELF recovery from here.
        """
        if not self.is_enabled("SHADOW_NET"):
            msg = (
                f"Router escalated PID {target_pid} to Shadow Net, but "
                "SHADOW_NET is disabled in the module registry "
                "(YOMI_MODULE_SHADOW_NET=true to enable). No further "
                "automated detection action taken for this escalation."
            )
            print(f"[GUARDIAN] {msg}")
            self.audit.record_action("GUARDIAN", "ESCALATION_SKIPPED", msg,
                                      metadata={"target_pid": target_pid})
            return {"status": "SKIPPED", "message": msg}

        try:
            return self._get_shadow_net().deploy_micro_hook(target_pid, reason)
        except Exception as exc:
            msg = f"Shadow Net dispatch failed for PID {target_pid}: {exc}"
            print(f"[GUARDIAN] {msg}")
            self.audit.record_action("GUARDIAN", "SHADOW_NET_DISPATCH_ERROR", msg,
                                      metadata={"target_pid": target_pid, "error": str(exc)})
            return {"status": "ERROR", "message": msg}

    # -- dispatch: post-containment (synchronous path only) ---------------

    def handle_post_containment(self, target_pid: int) -> dict:
        """
        Fires ONLY after a SYNCHRONOUS containment success: the instant
        CRITICAL SIGSTOP path in sentinel.py, or a harness result with
        status=="SUCCESS" and action=="FROZEN". target_pid is
        deterministically stopped at this point, so it's safe to chain
        deep-dive modules off of it (unlike the Shadow Net escalation
        path above, which is async).
        """
        summary: dict = {"mind_reader": None, "remediator": None, "sandbox": None, "mirage": None}
        binary_path = _resolve_exe_path(target_pid)

        if self.is_enabled("MIND_READER") and binary_path:
            try:
                summary["mind_reader"] = self._get_mind_reader().decompile_and_profile(
                    binary_path, target_pid
                )
            except Exception as exc:
                self._log_dispatch_error("MIND_READER", target_pid, exc)

        if self.is_enabled("REMEDIATOR"):
            if binary_path:
                try:
                    summary["remediator"] = self._get_remediator().generate_rollback_script(
                        {"pid": target_pid, "file_path": binary_path}
                    )
                except Exception as exc:
                    self._log_dispatch_error("REMEDIATOR", target_pid, exc)
            else:
                print(
                    f"[GUARDIAN] Skipping rollback script for PID {target_pid}: "
                    "no resolvable binary path (process likely already exited "
                    "or is fileless)."
                )

        if self.is_enabled("SANDBOX") and binary_path:
            try:
                summary["sandbox"] = self._get_sandbox().execute_resurrection(
                    target_pid, binary_path
                )
            except Exception as exc:
                self._log_dispatch_error("SANDBOX", target_pid, exc)

            if self.is_enabled("MIRAGE"):
                try:
                    os_target = "WINDOWS" if platform.system() == "Windows" else "LINUX"
                    # force_enable=True: the enable/disable decision was
                    # already made at the registry level above -- see
                    # constraint #4 in the module docstring. Mirage's own
                    # internal YOMI_ENABLE_MIRAGE_MODE check is bypassed
                    # deliberately, not accidentally.
                    summary["mirage"] = self._get_mirage().deploy_hallucination(
                        target_pid, os_target=os_target, force_enable=True
                    )
                except Exception as exc:
                    self._log_dispatch_error("MIRAGE", target_pid, exc)

        return summary

    def _log_dispatch_error(self, module_key: str, target_pid: int, exc: Exception) -> None:
        msg = f"{module_key} dispatch failed for PID {target_pid}: {exc}"
        print(f"[GUARDIAN] {msg}")
        self.audit.record_action(
            "GUARDIAN", f"{module_key}_DISPATCH_ERROR", msg,
            metadata={"target_pid": target_pid, "error": str(exc)},
        )

    # -- dispatch: end-of-incident reporting -----------------------------

    def generate_incident_dossier(self) -> Optional[dict]:
        if not self.is_enabled("DOSSIER"):
            return None
        try:
            return self._get_dossier().generate_pdf_dossier()
        except Exception as exc:
            print(f"[GUARDIAN] Dossier generation failed: {exc}")
            self.audit.record_action(
                "GUARDIAN", "DOSSIER_DISPATCH_ERROR", f"Dossier generation failed: {exc}",
                metadata={"error": str(exc)},
            )
            return None

    # -- periodic (not per-incident) housekeeping ------------------------

    def periodic_maintenance(self, every_n_cycles: int = 20) -> None:
        """
        Called once per full sentinel observation cycle. Internally only
        actually does anything every `every_n_cycles` calls -- this is
        for housekeeping that doesn't belong tied to a single
        investigation (e.g. sweeping Mirage decoys whose owning process
        has died), not for anything time-critical.
        """
        self._cycle_count += 1
        if self.is_enabled("MIRAGE") and self._cycle_count % every_n_cycles == 0:
            try:
                self._get_mirage().sweep_orphaned_hallucinations()
            except Exception as exc:
                print(f"[GUARDIAN] Periodic Mirage sweep failed: {exc}")

    # -- startup-time (not per-incident) daemons -------------------------

    @staticmethod
    def bootstrap_startup_daemons(audit: ImmutableStamp) -> None:
        """
        Ghost Protocol and the Ring-0 eBPF Sensor are startup-time
        daemons, not per-incident dispatches -- they used to be wired
        directly in cli.py, each with its own gating quirk:
          - Ghost Protocol was gated by YOMI_ENABLE_GHOST_PROTOCOL,
            never by module_registry's YOMI_MODULE_GHOST.
          - The eBPF Sensor was NOT GATED AT ALL: cli.py
            unconditionally subprocess.Popen'd it regardless of
            module_registry's EBPF_SENSOR default_enabled=False.
        Both now go through module_registry exclusively, like every
        other module. Captured as docs/known_issues.md #26.
        """
        active = module_registry.resolve_active_modules()

        if "GHOST" in active:
            from yomi_core.ghost import GhostProtocol
            try:
                ghost = GhostProtocol()
                ghost.engage_camouflage()
                ghost.arm_watchdog()
                audit.record_action(
                    "GUARDIAN", "GHOST_PROTOCOL_ENGAGED",
                    "GhostProtocol engaged camouflage and armed watchdog (via module_registry).",
                )
            except Exception as exc:
                audit.record_action(
                    "GUARDIAN", "GHOST_PROTOCOL_ATOMIC_ABORT",
                    f"GhostProtocol watchdog failed to arm: {exc}. Aborting to "
                    "prevent operating in an unmonitored cloaked state.",
                    metadata={"error": str(exc)},
                )
                raise SystemExit(
                    "Fatal: Ghost Protocol armed state is corrupt. Aborted."
                ) from exc
        else:
            print(
                "[GUARDIAN] GHOST is disabled in the module registry (default). "
                "Set YOMI_MODULE_GHOST=true to enable."
            )

        if "EBPF_SENSOR" in active:
            import subprocess
            import sys as _sys
            try:
                subprocess.Popen(
                    [
                        _sys.executable, "-c",
                        "from yomi_engine.ebpf_sensor import eBPFSentinel; "
                        "s = eBPFSentinel(); s.arm_sensor(); s.monitor_pid(1, 86400)",
                    ],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                audit.record_action(
                    "GUARDIAN", "EBPF_SENSOR_DEPLOYED",
                    "Ring-0 eBPF Sensor deployed as isolated subprocess (via module_registry).",
                )
            except Exception as exc:
                audit.record_action(
                    "GUARDIAN", "EBPF_SENSOR_DISPATCH_ERROR",
                    f"Failed to deploy eBPF Sensor: {exc}",
                    metadata={"error": str(exc)},
                )
        else:
            print(
                "[GUARDIAN] EBPF_SENSOR is disabled in the module registry (default). "
                "Set YOMI_MODULE_EBPF_SENSOR=true to enable."
            )
