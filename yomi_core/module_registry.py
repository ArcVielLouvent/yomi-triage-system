"""
Module Registry — single source of truth for which Yomi subsystems are
active in a given run.

Why this exists: as of the hackathon snapshot, ~8 real modules
(mind_reader, shadow_net, remediator, dossier, mirage, sandbox, ghost,
ebpf_sensor) existed in the codebase but were never wired into Sentinel's
autonomous loop — they were only reachable via each file's own
`if __name__ == "__main__"` block. This registry is the mechanism that
fixes that: Guardian (Fase 4-5) reads this registry once at startup and
wires every ENABLED module into the pipeline. Nothing in this codebase is
meant to sit unused again — if a module isn't wanted for a given
deployment, it is explicitly OFF here, not silently orphaned in the source
tree.

Default posture: everything with real OS-level side effects (process
camouflage, deception/honeypot, kernel eBPF hooks, sandbox detonation) is
OFF by default. This is a safety default for unattended/enterprise
deployment, not a statement that the module is unfinished. Operators
(including us, for demos) turn modules on explicitly via env var or
`yomi_config.yaml`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum


class RiskTier(Enum):
    READ_ONLY = "read_only"          # observes/reports only, no state change
    CONTAINMENT = "containment"       # freezes/kills processes (reversible)
    INVASIVE = "invasive"             # deception, camouflage, kernel hooks,
                                       # sandbox detonation (higher blast radius)


@dataclass(frozen=True)
class ModuleSpec:
    key: str                # env var suffix: YOMI_MODULE_<key>
    dotted_path: str        # importable module path
    risk_tier: RiskTier
    default_enabled: bool
    requires: tuple[str, ...] = field(default_factory=tuple)  # other module keys
    platform_notes: str = ""


# --- The full registry. Every module in the codebase must appear here. ----
REGISTRY: dict[str, ModuleSpec] = {
    # Layer 0/1 — always-on plumbing, not user-toggleable (foundation, not
    # a "feature"). Listed here for visibility/documentation only.
    "STAMP": ModuleSpec("STAMP", "yomi_audit.stamp", RiskTier.READ_ONLY, True),
    "OS_BRIDGE": ModuleSpec("OS_BRIDGE", "yomi_mcp.os_bridge", RiskTier.READ_ONLY, True),
    "DATASTORE": ModuleSpec("DATASTORE", "yomi_data", RiskTier.READ_ONLY, True),

    # Detection / analysis — safe to default ON, read-only.
    "SWARM": ModuleSpec("SWARM", "yomi_engine.swarm", RiskTier.READ_ONLY, True),
    "HUNTER": ModuleSpec("HUNTER", "yomi_engine.hunter", RiskTier.READ_ONLY, True, requires=("SWARM",)),
    "TELEMETRY": ModuleSpec("TELEMETRY", "yomi_engine.telemetry", RiskTier.READ_ONLY, True),
    "MITRE_MAPPER": ModuleSpec("MITRE_MAPPER", "yomi_engine.mitre_mapper", RiskTier.READ_ONLY, True),
    "LIBRARY": ModuleSpec("LIBRARY", "yomi_engine.library", RiskTier.READ_ONLY, True),
    "MIND_READER": ModuleSpec("MIND_READER", "yomi_engine.mind_reader", RiskTier.READ_ONLY, True, requires=("HUNTER",)),

    # Reasoning
    "ROUTER": ModuleSpec("ROUTER", "yomi_core.router", RiskTier.READ_ONLY, True),

    # Containment — reversible OS state change. On by default because it's
    # the core value proposition, but distinct tier from read-only.
    "HARNESS": ModuleSpec("HARNESS", "yomi_mcp.harness", RiskTier.CONTAINMENT, True),
    "REMEDIATOR": ModuleSpec("REMEDIATOR", "yomi_engine.remediator", RiskTier.CONTAINMENT, True, requires=("HARNESS",)),

    # Reporting — safe, on by default.
    "WEAVER": ModuleSpec("WEAVER", "yomi_engine.weaver", RiskTier.READ_ONLY, True),
    "DOSSIER": ModuleSpec("DOSSIER", "yomi_engine.dossier", RiskTier.READ_ONLY, True, requires=("WEAVER",)),

    # --- Invasive tier: OFF by default, toggled explicitly (e.g. for demos) ---
    "SHADOW_NET": ModuleSpec(
        "SHADOW_NET", "yomi_engine.shadow_net", RiskTier.INVASIVE, False,
        requires=("OS_BRIDGE",),
        platform_notes="Linux Ring-0 eBPF only; no-op on Windows/macOS.",
    ),
    "SANDBOX": ModuleSpec(
        "SANDBOX", "yomi_engine.sandbox", RiskTier.INVASIVE, False,
        requires=("REMEDIATOR",),
        platform_notes="Requires Linux namespaces (pid/net/mount); root required.",
    ),
    "MIRAGE": ModuleSpec(
        "MIRAGE", "yomi_engine.mirage", RiskTier.INVASIVE, False,
        requires=("SANDBOX",),
    ),
    "GHOST": ModuleSpec(
        "GHOST", "yomi_core.ghost", RiskTier.INVASIVE, False,
        platform_notes="Process camouflage + dead man's switch. Off by default: "
        "changes the daemon's own observable identity, not appropriate as a "
        "silent default for an auditable enterprise deployment.",
    ),
    "EBPF_SENSOR": ModuleSpec(
        "EBPF_SENSOR", "yomi_engine.ebpf_sensor", RiskTier.INVASIVE, False,
        platform_notes="Linux Ring-0 only; requires bcc + root.",
    ),
}


def is_enabled(key: str) -> bool:
    """
    Resolution order: explicit env var override > profile default >
    ModuleSpec.default_enabled. Env var format: YOMI_MODULE_<KEY>=true|false
    """
    spec = REGISTRY[key]
    env_override = os.environ.get(f"YOMI_MODULE_{spec.key}")
    if env_override is not None:
        return env_override.strip().lower() in ("1", "true", "yes", "on")
    return spec.default_enabled


def resolve_active_modules() -> dict[str, ModuleSpec]:
    """
    Returns the modules that are actually enabled for this run, with
    dependency validation (fails loud, not silently, if a module is enabled
    but a required dependency is disabled -- this is what stops us from
    ever again having a module that's 'on' but functionally orphaned).
    """
    active = {k: v for k, v in REGISTRY.items() if is_enabled(k)}
    for key, spec in active.items():
        missing = [r for r in spec.requires if r not in active]
        if missing:
            raise RuntimeError(
                f"Module '{key}' is enabled but its dependencies {missing} are "
                f"not. Enable them too (YOMI_MODULE_<DEP>=true) or disable "
                f"'{key}'."
            )
    return active


DEMO_PROFILE_ENV = {
    # A ready-made env-var set for live demos: everything on, including the
    # invasive tier, so the full "unique vs. top-5" surface area is visible.
    # Not a default -- operators opt into this explicitly.
    "YOMI_MODULE_SHADOW_NET": "true",
    "YOMI_MODULE_SANDBOX": "true",
    "YOMI_MODULE_MIRAGE": "true",
    "YOMI_MODULE_GHOST": "true",
    "YOMI_MODULE_EBPF_SENSOR": "true",
}
