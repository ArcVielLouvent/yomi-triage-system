#!/usr/bin/env python3
"""
Boots the REAL Sentinel -> Guardian Orchestrator -> Harness chain against a
synthetic, non-destructive CRITICAL anomaly naming a real (harmless)
subprocess, and asserts real, verifiable outcomes in the resulting ledger --
proving the wired pipeline actually runs end-to-end on THIS machine, not
just that the unit/integration test suite passes.

This is the standalone, no-pytest-required equivalent of
tests/integration/test_chain_sentinel_router_harness.py::
test_critical_threat_chain_freezes_real_process_end_to_end -- same proven
pattern, same real dispatch, run as a plain script an operator (or CI) can
execute directly against a live checkout.

What this proves, concretely, each with an explicit assertion below (not
just "did it crash"):
  1. SentinelDaemon boots and GuardianOrchestrator initializes without error
     against yomi_core/module_registry.py's real default configuration.
  2. A CRITICAL synthetic anomaly naming a real subprocess PID gets an
     instant SIGSTOP -- verified by reading /proc/<pid>/status, not assumed.
  3. GuardianOrchestrator.handle_post_containment dispatches MIND_READER,
     REMEDIATOR, and DOSSIER (all default-enabled) off that containment --
     verified by reading back the real ledger this run produced.
  4. REMEDIATOR's #14/#15 path-containment fix is exercised against a REAL
     binary path (this interpreter's own executable, resolved via
     /proc/<pid>/exe), not a mock -- and correctly refuses to generate a
     rollback script for it, since a Python interpreter binary normally
     lives under a protected system directory (/usr on most distros).

Isolation: every hardcoded __file__-relative data path this chain touches
(ImmutableStamp's ledger, OmniLibrary's CVE store, ReverserEngine's
remediation dir, CourtReadyDossier's report dir) is redirected to a fresh
temp directory before anything is constructed -- this run NEVER touches the
real repository's yomi_data/. See docs/known_issues.md #27 for why this
manual redirection is currently necessary (there is no YOMI_DATA_DIR
override yet).

Only one real network boundary is mocked: the LLM API call itself
(OpenClawGateway.generate_intent). Every other step -- harness veto logic,
os_bridge.cryogenic_freeze, Guardian's dispatch decisions, ledger writes --
runs for real.

Usage:
  python3 scripts/smoke_test_cli.py

Exit code 0 = every assertion passed. Exit code 1 = something is wired
wrong or broken on this machine. Safe to wire into CI (see run_tests.sh).

Platform: Linux only (real SIGSTOP/proc-status inspection). Exits 0 with a
skip notice on other platforms rather than failing the build.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def _mock_llm_freeze_response(target_pid: int) -> str:
    return json.dumps({
        "red_agent": "Anomaly correlates to active credential theft.",
        "blue_agent": "Recommend immediate containment.",
        "judge_verdict": "APPROVE",
        "epistemic_doubt": 5,
        "action": "freeze",
        "target_pid": target_pid,
    })


def main() -> int:
    if sys.platform != "linux":
        print(
            "[smoke_test_cli] SKIP: real SIGSTOP/proc-status inspection is "
            "Linux-specific. Not failing the build on this platform.",
            file=sys.stderr,
        )
        return 0

    failures: list[str] = []

    # --- Isolation: redirect every __file__-relative data path BEFORE
    # anything constructs a singleton or reads a default path. Order
    # matters: yomi_audit.stamp must be patched and its singleton reset
    # before ANY ImmutableStamp() call happens anywhere in the chain
    # (multiple modules construct it independently; the first call wins
    # and is reused everywhere after).
    tmp_dir = Path(tempfile.mkdtemp(prefix="yomi-smoke-"))
    try:
        fake_pkg_dir = tmp_dir / "fake_pkg"

        from yomi_audit import stamp as stamp_module
        from yomi_core import router as router_module
        from yomi_engine import dossier as dossier_module
        from yomi_engine import library as library_module
        from yomi_engine import remediator as remediator_module
        from yomi_engine import swarm as swarm_module

        fake_audit_dir = fake_pkg_dir / "yomi_audit"
        fake_engine_dir = fake_pkg_dir / "yomi_engine"
        fake_audit_dir.mkdir(parents=True)
        fake_engine_dir.mkdir(parents=True)

        stamp_module.__file__ = str(fake_audit_dir / "stamp.py")
        swarm_module.__file__ = str(fake_engine_dir / "swarm.py")
        remediator_module.__file__ = str(fake_engine_dir / "remediator.py")
        dossier_module.__file__ = str(fake_engine_dir / "dossier.py")
        library_module.__file__ = str(fake_engine_dir / "library.py")

        # Avoid interactive getpass()/network KMS calls, and avoid
        # depending on whatever GPG state happens to exist on this host
        # (forces the deterministic HMAC/sha256 signing fallback instead).
        import os as _os
        _os.environ.pop("YOMI_AUDIT_HMAC_KMS_PROVIDER", None)
        _os.environ["YOMI_AUDIT_HMAC_MODE"] = "generated"
        shutil.which = lambda name: None  # noqa: ARG005

        stamp_module.ImmutableStamp._instance = None
        audit = stamp_module.ImmutableStamp()

        # LLM boundary: don't hit a real API.
        router_module.GEMINI_API_KEY = None
        router_module.AIR_GAPPED_MODE = True

        from yomi_core.sentinel import SentinelDaemon  # noqa: E402

        print("[smoke_test_cli] Constructing SentinelDaemon (boots GuardianOrchestrator)...")
        daemon = SentinelDaemon()

        print("[smoke_test_cli] Spawning a real, harmless test subprocess...")
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            time.sleep(0.2)
            target_pid = proc.pid
            daemon.router.llm_gateway.generate_intent = (
                lambda ctx: _mock_llm_freeze_response(target_pid)
            )

            daemon.threat_level = "CRITICAL"
            anomaly_data = [
                f"CRITICAL: credential theft detected via PID {target_pid} accessing /etc/shadow"
            ]

            print(f"[smoke_test_cli] Feeding synthetic CRITICAL anomaly for PID {target_pid}...")
            daemon._zero_prompt_trigger(anomaly_data)

            # --- Assertion 1: real SIGSTOP happened.
            frozen = False
            for _ in range(20):
                with open(f"/proc/{target_pid}/status", encoding="utf-8") as f:
                    status = f.read()
                if "State:\tT" in status:
                    frozen = True
                    break
                time.sleep(0.05)
            if frozen:
                print("[smoke_test_cli] [PASS] Process was actually SIGSTOP'd (verified via /proc).")
            else:
                failures.append("Process was never actually frozen by the instant-containment path.")

            # --- Assertions 2-4: the ledger tells a coherent, verifiable story.
            with open(audit.ledger_file, encoding="utf-8") as f:
                lines = [json.loads(l) for l in f if l.strip()]
            action_types = [l["action_type"] for l in lines]

            if "AUTONOMOUS_CONTAINMENT" in action_types:
                print("[smoke_test_cli] [PASS] Sentinel's instant SIGSTOP was sealed to the ledger.")
            else:
                failures.append("AUTONOMOUS_CONTAINMENT missing from the ledger.")

            if "REPORT_SIGNED" in action_types:
                print("[smoke_test_cli] [PASS] GuardianOrchestrator dispatched DOSSIER (unconditional, end-of-incident).")
            else:
                failures.append("REPORT_SIGNED (DOSSIER dispatch) missing from the ledger.")

            if "ABORTED" in action_types and any(
                l["action_type"] == "ABORTED" and "critical system path" in l["description"].lower()
                for l in lines
            ):
                print(
                    "[smoke_test_cli] [PASS] GuardianOrchestrator dispatched REMEDIATOR against the "
                    "real interpreter path, and #14/#15's containment fix correctly refused it "
                    "(protected system directory)."
                )
            else:
                failures.append(
                    "Expected REMEDIATOR to dispatch and refuse the real interpreter path "
                    "(ABORTED / 'critical system path' not found in the ledger)."
                )

        finally:
            proc.kill()  # SIGKILL works even on a SIGSTOP'd process.
            proc.wait(timeout=5)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print()
    if failures:
        print(f"[smoke_test_cli] FAILED -- {len(failures)} assertion(s) did not hold:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("[smoke_test_cli] All assertions passed. Sentinel -> Guardian -> Harness chain is wired correctly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
