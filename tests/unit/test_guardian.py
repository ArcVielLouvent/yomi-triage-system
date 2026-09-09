"""
Unit tests for yomi_core.guardian.GuardianOrchestrator -- the dispatcher
that closes docs/known_issues.md #11 by wiring mind_reader, shadow_net,
remediator, dossier, mirage, sandbox, ghost, and ebpf_sensor into the
autonomous loop, gated entirely by yomi_core.module_registry.

Every sub-module class is patched at its SOURCE (yomi_engine.mind_reader.
MindReaderDecompiler, etc.) before GuardianOrchestrator's lazy accessors
import it -- this proves the dispatch wiring/gating logic in isolation,
without depending on what any individual sub-module actually does
internally (that's what each module's own test file is for).
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def clean_module_env(monkeypatch):
    """Ensures no leftover YOMI_MODULE_* env vars from another test or
    the real shell environment leak into these tests."""
    for key in (
        "SHADOW_NET", "SANDBOX", "MIRAGE", "GHOST", "EBPF_SENSOR",
        "MIND_READER", "REMEDIATOR", "DOSSIER",
    ):
        monkeypatch.delenv(f"YOMI_MODULE_{key}", raising=False)
    monkeypatch.delenv("YOMI_DEMO_PROFILE", raising=False)


@pytest.fixture
def guardian(isolated_stamp, clean_module_env):
    from yomi_core.guardian import GuardianOrchestrator
    return GuardianOrchestrator()


def _ledger_action_types(isolated_stamp):
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        return [json.loads(l)["action_type"] for l in f if l.strip()]


# --------------------------------------------------------------------------
# is_enabled / lazy import discipline
# --------------------------------------------------------------------------

def test_invasive_modules_disabled_by_default(guardian):
    for key in ("SHADOW_NET", "SANDBOX", "MIRAGE", "GHOST", "EBPF_SENSOR"):
        assert guardian.is_enabled(key) is False


def test_read_only_and_containment_modules_enabled_by_default(guardian):
    for key in ("MIND_READER", "REMEDIATOR", "DOSSIER"):
        assert guardian.is_enabled(key) is True


def test_disabled_module_class_is_never_imported(guardian, monkeypatch):
    """
    SHADOW_NET is disabled by default -- handle_escalation must not even
    import yomi_engine.shadow_net, let alone instantiate it.
    """
    import sys
    monkeypatch.delitem(sys.modules, "yomi_engine.shadow_net", raising=False)

    result = guardian.handle_escalation(5000, "test escalation")

    assert result["status"] == "SKIPPED"
    assert "yomi_engine.shadow_net" not in sys.modules


# --------------------------------------------------------------------------
# handle_escalation (async / fire-and-forget path)
# --------------------------------------------------------------------------

def test_handle_escalation_skipped_and_logged_when_shadow_net_disabled(guardian, isolated_stamp):
    result = guardian.handle_escalation(5000, "router exhausted iterations")
    assert result["status"] == "SKIPPED"
    assert "ESCALATION_SKIPPED" in _ledger_action_types(isolated_stamp)


def test_handle_escalation_dispatches_shadow_net_when_enabled(monkeypatch, isolated_stamp):
    monkeypatch.setenv("YOMI_MODULE_SHADOW_NET", "true")
    from yomi_core.guardian import GuardianOrchestrator
    guardian = GuardianOrchestrator()

    mock_instance = MagicMock()
    mock_instance.deploy_micro_hook.return_value = {"status": "DEPLOYED"}
    monkeypatch.setattr(
        "yomi_engine.shadow_net.ShadowNetProtocol",
        MagicMock(return_value=mock_instance),
    )

    result = guardian.handle_escalation(5000, "router exhausted iterations")

    mock_instance.deploy_micro_hook.assert_called_once_with(5000, "router exhausted iterations")
    assert result == {"status": "DEPLOYED"}


def test_handle_escalation_dispatch_exception_is_caught_and_logged(monkeypatch, isolated_stamp):
    monkeypatch.setenv("YOMI_MODULE_SHADOW_NET", "true")
    from yomi_core.guardian import GuardianOrchestrator
    guardian = GuardianOrchestrator()

    mock_instance = MagicMock()
    mock_instance.deploy_micro_hook.side_effect = RuntimeError("bcc not installed")
    monkeypatch.setattr(
        "yomi_engine.shadow_net.ShadowNetProtocol",
        MagicMock(return_value=mock_instance),
    )

    result = guardian.handle_escalation(5000, "reason")

    assert result["status"] == "ERROR"
    assert "SHADOW_NET_DISPATCH_ERROR" in _ledger_action_types(isolated_stamp)


# --------------------------------------------------------------------------
# handle_post_containment (synchronous path)
# --------------------------------------------------------------------------

def test_post_containment_skips_mind_reader_when_binary_unresolvable(guardian, monkeypatch):
    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "")
    mock_cls = MagicMock()
    monkeypatch.setattr("yomi_engine.mind_reader.MindReaderDecompiler", mock_cls)

    guardian.handle_post_containment(5000)

    mock_cls.assert_not_called()


def test_post_containment_dispatches_mind_reader_when_binary_resolvable(guardian, monkeypatch):
    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "/tmp/malware.bin")

    mock_instance = MagicMock()
    mock_instance.decompile_and_profile.return_value = {"skill_level": "Novice"}
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler",
        MagicMock(return_value=mock_instance),
    )
    # REMEDIATOR is also default-enabled -- stub it out so this test
    # isolates MIND_READER's dispatch specifically.
    monkeypatch.setattr(
        "yomi_engine.remediator.ReverserEngine",
        MagicMock(return_value=MagicMock(generate_rollback_script=MagicMock(return_value={}))),
    )

    summary = guardian.handle_post_containment(5000)

    mock_instance.decompile_and_profile.assert_called_once_with("/tmp/malware.bin", 5000)
    assert summary["mind_reader"] == {"skill_level": "Novice"}


def test_post_containment_dispatches_remediator_with_correct_payload(guardian, monkeypatch):
    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "/tmp/malware.bin")
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler",
        MagicMock(return_value=MagicMock(decompile_and_profile=MagicMock(return_value={}))),
    )

    mock_instance = MagicMock()
    mock_instance.generate_rollback_script.return_value = {"status": "SUCCESS"}
    monkeypatch.setattr(
        "yomi_engine.remediator.ReverserEngine",
        MagicMock(return_value=mock_instance),
    )

    summary = guardian.handle_post_containment(5000)

    mock_instance.generate_rollback_script.assert_called_once_with(
        {"pid": 5000, "file_path": "/tmp/malware.bin"}
    )
    assert summary["remediator"] == {"status": "SUCCESS"}


def test_post_containment_remediator_skips_generation_without_binary_path(guardian, monkeypatch):
    """REMEDIATOR stays enabled but must not be CALLED with an empty/
    invalid file_path -- it should be skipped entirely, not called with
    file_path=""."""
    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "")
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler",
        MagicMock(return_value=MagicMock()),
    )
    mock_remediator_cls = MagicMock()
    monkeypatch.setattr("yomi_engine.remediator.ReverserEngine", mock_remediator_cls)

    guardian.handle_post_containment(5000)

    mock_remediator_cls.assert_not_called()


def test_post_containment_dispatch_exception_is_caught_and_logged(guardian, monkeypatch, isolated_stamp):
    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "/tmp/malware.bin")
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler",
        MagicMock(return_value=MagicMock(
            decompile_and_profile=MagicMock(side_effect=RuntimeError("radare2 crashed"))
        )),
    )
    monkeypatch.setattr(
        "yomi_engine.remediator.ReverserEngine",
        MagicMock(return_value=MagicMock(generate_rollback_script=MagicMock(return_value={}))),
    )

    summary = guardian.handle_post_containment(5000)

    assert summary["mind_reader"] is None
    assert "MIND_READER_DISPATCH_ERROR" in _ledger_action_types(isolated_stamp)


def test_post_containment_sandbox_and_mirage_dispatch_when_both_enabled(monkeypatch, isolated_stamp):
    monkeypatch.setenv("YOMI_MODULE_SANDBOX", "true")
    monkeypatch.setenv("YOMI_MODULE_MIRAGE", "true")
    from yomi_core.guardian import GuardianOrchestrator
    guardian = GuardianOrchestrator()

    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "/tmp/malware.bin")
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler",
        MagicMock(return_value=MagicMock(decompile_and_profile=MagicMock(return_value={}))),
    )
    monkeypatch.setattr(
        "yomi_engine.remediator.ReverserEngine",
        MagicMock(return_value=MagicMock(generate_rollback_script=MagicMock(return_value={}))),
    )

    mock_sandbox = MagicMock()
    mock_sandbox.execute_resurrection.return_value = {"status": "AWAKENED"}
    monkeypatch.setattr("yomi_engine.sandbox.SandboxEnvironment", MagicMock(return_value=mock_sandbox))

    mock_mirage = MagicMock()
    mock_mirage.deploy_hallucination.return_value = {"status": "DEPLOYED"}
    monkeypatch.setattr("yomi_engine.mirage.MirageProtocol", MagicMock(return_value=mock_mirage))

    summary = guardian.handle_post_containment(5000)

    mock_sandbox.execute_resurrection.assert_called_once_with(5000, "/tmp/malware.bin")
    # force_enable=True: Mirage's OWN internal YOMI_ENABLE_MIRAGE_MODE
    # check must be deliberately bypassed, since the registry already
    # made the enable/disable decision.
    mock_mirage.deploy_hallucination.assert_called_once()
    _, kwargs = mock_mirage.deploy_hallucination.call_args
    assert kwargs.get("force_enable") is True
    assert summary["sandbox"] == {"status": "AWAKENED"}
    assert summary["mirage"] == {"status": "DEPLOYED"}


def test_post_containment_sandbox_disabled_never_dispatches_mirage(guardian, monkeypatch):
    """SANDBOX and MIRAGE are both disabled by default -- with no binary
    even resolvable, neither must be touched."""
    monkeypatch.setattr("yomi_core.guardian._resolve_exe_path", lambda pid: "/tmp/malware.bin")
    monkeypatch.setattr(
        "yomi_engine.mind_reader.MindReaderDecompiler",
        MagicMock(return_value=MagicMock(decompile_and_profile=MagicMock(return_value={}))),
    )
    monkeypatch.setattr(
        "yomi_engine.remediator.ReverserEngine",
        MagicMock(return_value=MagicMock(generate_rollback_script=MagicMock(return_value={}))),
    )
    mock_sandbox_cls = MagicMock()
    mock_mirage_cls = MagicMock()
    monkeypatch.setattr("yomi_engine.sandbox.SandboxEnvironment", mock_sandbox_cls)
    monkeypatch.setattr("yomi_engine.mirage.MirageProtocol", mock_mirage_cls)

    guardian.handle_post_containment(5000)

    mock_sandbox_cls.assert_not_called()
    mock_mirage_cls.assert_not_called()


def test_mirage_enabled_without_sandbox_dependency_fails_loud_at_construction(isolated_stamp, monkeypatch):
    """
    module_registry.resolve_active_modules() validates dependencies and
    raises RuntimeError if a module is enabled but its dependency isn't
    -- MIRAGE requires SANDBOX. This must surface as a clear, actionable
    error at GuardianOrchestrator construction time (i.e. at Sentinel
    startup), not as a silent partial-feature state.
    """
    monkeypatch.setenv("YOMI_MODULE_MIRAGE", "true")
    monkeypatch.delenv("YOMI_MODULE_SANDBOX", raising=False)
    from yomi_core.guardian import GuardianOrchestrator

    with pytest.raises(RuntimeError, match="MIRAGE.*SANDBOX"):
        GuardianOrchestrator()


# --------------------------------------------------------------------------
# generate_incident_dossier
# --------------------------------------------------------------------------

def test_generate_incident_dossier_calls_dossier_when_enabled(guardian, monkeypatch):
    mock_instance = MagicMock()
    mock_instance.generate_pdf_dossier.return_value = {"pdf_file": "x.pdf"}
    monkeypatch.setattr(
        "yomi_engine.dossier.CourtReadyDossier",
        MagicMock(return_value=mock_instance),
    )

    result = guardian.generate_incident_dossier()

    mock_instance.generate_pdf_dossier.assert_called_once()
    assert result == {"pdf_file": "x.pdf"}


def test_generate_incident_dossier_returns_none_when_disabled(monkeypatch, isolated_stamp):
    monkeypatch.setenv("YOMI_MODULE_DOSSIER", "false")
    from yomi_core.guardian import GuardianOrchestrator
    guardian = GuardianOrchestrator()

    mock_cls = MagicMock()
    monkeypatch.setattr("yomi_engine.dossier.CourtReadyDossier", mock_cls)

    result = guardian.generate_incident_dossier()

    assert result is None
    mock_cls.assert_not_called()


def test_generate_incident_dossier_exception_caught_and_logged(guardian, monkeypatch, isolated_stamp):
    monkeypatch.setattr(
        "yomi_engine.dossier.CourtReadyDossier",
        MagicMock(return_value=MagicMock(
            generate_pdf_dossier=MagicMock(side_effect=RuntimeError("disk full"))
        )),
    )

    result = guardian.generate_incident_dossier()

    assert result is None
    assert "DOSSIER_DISPATCH_ERROR" in _ledger_action_types(isolated_stamp)


# --------------------------------------------------------------------------
# periodic_maintenance
# --------------------------------------------------------------------------

def test_periodic_maintenance_sweeps_mirage_only_every_n_cycles(isolated_stamp, monkeypatch):
    monkeypatch.setenv("YOMI_MODULE_SANDBOX", "true")
    monkeypatch.setenv("YOMI_MODULE_MIRAGE", "true")
    from yomi_core.guardian import GuardianOrchestrator
    guardian = GuardianOrchestrator()

    mock_mirage = MagicMock()
    monkeypatch.setattr("yomi_engine.mirage.MirageProtocol", MagicMock(return_value=mock_mirage))

    for _ in range(2):
        guardian.periodic_maintenance(every_n_cycles=3)
    mock_mirage.sweep_orphaned_hallucinations.assert_not_called()

    guardian.periodic_maintenance(every_n_cycles=3)
    mock_mirage.sweep_orphaned_hallucinations.assert_called_once()


def test_periodic_maintenance_noop_when_mirage_disabled(guardian, monkeypatch):
    mock_cls = MagicMock()
    monkeypatch.setattr("yomi_engine.mirage.MirageProtocol", mock_cls)

    for _ in range(50):
        guardian.periodic_maintenance(every_n_cycles=1)

    mock_cls.assert_not_called()


# --------------------------------------------------------------------------
# bootstrap_startup_daemons (Ghost Protocol + eBPF Sensor)
# --------------------------------------------------------------------------

def test_bootstrap_ghost_disabled_by_default_skips_entirely(isolated_stamp, clean_module_env, monkeypatch):
    from yomi_core.guardian import GuardianOrchestrator
    mock_cls = MagicMock()
    monkeypatch.setattr("yomi_core.ghost.GhostProtocol", mock_cls)

    GuardianOrchestrator.bootstrap_startup_daemons(isolated_stamp)

    mock_cls.assert_not_called()


def test_bootstrap_ghost_enabled_engages_camouflage_and_arms_watchdog(isolated_stamp, clean_module_env, monkeypatch):
    monkeypatch.setenv("YOMI_MODULE_GHOST", "true")
    mock_instance = MagicMock()
    monkeypatch.setattr("yomi_core.ghost.GhostProtocol", MagicMock(return_value=mock_instance))

    from yomi_core.guardian import GuardianOrchestrator
    GuardianOrchestrator.bootstrap_startup_daemons(isolated_stamp)

    mock_instance.engage_camouflage.assert_called_once()
    mock_instance.arm_watchdog.assert_called_once()
    assert "GHOST_PROTOCOL_ENGAGED" in _ledger_action_types(isolated_stamp)


def test_bootstrap_ghost_watchdog_failure_aborts_with_system_exit(isolated_stamp, clean_module_env, monkeypatch):
    monkeypatch.setenv("YOMI_MODULE_GHOST", "true")
    mock_instance = MagicMock()
    mock_instance.arm_watchdog.side_effect = OSError("prctl blocked by seccomp")
    monkeypatch.setattr("yomi_core.ghost.GhostProtocol", MagicMock(return_value=mock_instance))

    from yomi_core.guardian import GuardianOrchestrator
    with pytest.raises(SystemExit):
        GuardianOrchestrator.bootstrap_startup_daemons(isolated_stamp)

    assert "GHOST_PROTOCOL_ATOMIC_ABORT" in _ledger_action_types(isolated_stamp)


def test_bootstrap_ebpf_sensor_disabled_by_default_never_spawns_subprocess(isolated_stamp, clean_module_env, monkeypatch):
    mock_popen = MagicMock()
    monkeypatch.setattr("subprocess.Popen", mock_popen)

    from yomi_core.guardian import GuardianOrchestrator
    GuardianOrchestrator.bootstrap_startup_daemons(isolated_stamp)

    mock_popen.assert_not_called()


def test_bootstrap_ebpf_sensor_enabled_spawns_isolated_subprocess(isolated_stamp, clean_module_env, monkeypatch):
    monkeypatch.setenv("YOMI_MODULE_EBPF_SENSOR", "true")
    mock_popen = MagicMock()
    monkeypatch.setattr("subprocess.Popen", mock_popen)

    from yomi_core.guardian import GuardianOrchestrator
    GuardianOrchestrator.bootstrap_startup_daemons(isolated_stamp)

    mock_popen.assert_called_once()
    assert "EBPF_SENSOR_DEPLOYED" in _ledger_action_types(isolated_stamp)


def test_bootstrap_ebpf_sensor_spawn_failure_is_caught_and_logged(isolated_stamp, clean_module_env, monkeypatch):
    monkeypatch.setenv("YOMI_MODULE_EBPF_SENSOR", "true")
    monkeypatch.setattr("subprocess.Popen", MagicMock(side_effect=OSError("fork failed")))

    from yomi_core.guardian import GuardianOrchestrator
    GuardianOrchestrator.bootstrap_startup_daemons(isolated_stamp)  # must not raise

    assert "EBPF_SENSOR_DISPATCH_ERROR" in _ledger_action_types(isolated_stamp)
