from __future__ import annotations

import os
import sys
import re
import time
from dataclasses import dataclass, field, asdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Cross-Artifact Correlator (Fase 7)
# Purpose: Synthesizes structured results already produced by Hunter,
#          MitreMapper, Swarm, and (optionally) MindReader/Library into a
#          single CorrelatedCaseFile per incident, flagging cross-source
#          corroboration and contradictions instead of silently merging.
#
# DESIGN CONSTRAINT (see docs/phase_log/fase_7.md): this module consumes
# LIVE in-memory return values passed in by its caller. It never reads
# ImmutableStamp's ledger -- record_action() flattens structured results
# into free-text descriptions, and reconstructing structure from that text
# is lossy (see the pre-existing, documented
# test_mitre_mapper_entries_are_NOT_detected_by_weaver_KNOWN_BUG in
# tests/unit/test_weaver.py for what that lossiness looks like in
# practice). Callers (yomi_core/guardian.py) are responsible for gathering
# the source modules' return values and passing them in here.
# ==============================================================================


@dataclass
class CorrelatedCaseFile:
    target_pid: int
    incident_id: str

    timeline_events: list = field(default_factory=list)
    filesystem_artifacts: list = field(default_factory=list)
    network_findings: list = field(default_factory=list)
    memory_findings: list = field(default_factory=list)
    registry_findings: list = field(default_factory=list)
    mitre_tactics: list = field(default_factory=list)
    cve_correlations: list = field(default_factory=list)

    corroborated_tactics: list = field(default_factory=list)
    contradictions: list = field(default_factory=list)
    coverage_gaps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_report_text(self) -> str:
        """
        Rendered as a standalone section, meant to be appended to
        TemporalNarrativeWeaver's narrative before CourtReadyDossier signs
        it -- NOT a replacement for the weaver's ledger-based narrative,
        an additional, differently-sourced section.
        """
        lines = [
            "=" * 80,
            "                 CROSS-ARTIFACT CORRELATION (FASE 7)",
            "=" * 80,
            "",
            f"Incident: {self.incident_id}  |  Target PID: {self.target_pid}",
            "",
        ]

        def _section(title: str, items: list, empty_msg: str) -> list:
            out = [f"[{title}]"]
            if not items:
                out.append(f"- {empty_msg}")
            else:
                for item in items:
                    detail = item.get("detail", item) if isinstance(item, dict) else item
                    source = item.get("source", "") if isinstance(item, dict) else ""
                    prefix = f"({source}) " if source else ""
                    out.append(f"- {prefix}{detail}")
            out.append("")
            return out

        lines += _section("TIMELINE", self.timeline_events, "No temporal artifacts.")
        lines += _section("FILESYSTEM", self.filesystem_artifacts, "No filesystem artifacts.")
        lines += _section("NETWORK", self.network_findings, "No network findings.")
        lines += _section("MEMORY", self.memory_findings, "No memory findings.")
        lines += _section("REGISTRY", self.registry_findings, "No registry findings.")

        lines.append("[MITRE TACTICS CLAIMED]")
        if self.mitre_tactics:
            for t in self.mitre_tactics:
                lines.append(f"- {t.get('mitre_id')}: {t.get('desc')}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("[CORROBORATED ACROSS >=2 INDEPENDENT SOURCES]")
        if self.corroborated_tactics:
            for tid in self.corroborated_tactics:
                lines.append(f"- {tid}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("[CONTRADICTIONS / UNCORROBORATED CLAIMS]")
        if self.contradictions:
            for c in self.contradictions:
                lines.append(f"- CLAIM: {c.get('claim')}")
                lines.append(f"  ISSUE: {c.get('issue')}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("[COVERAGE GAPS]")
        if self.coverage_gaps:
            for g in self.coverage_gaps:
                lines.append(f"- {g}")
        else:
            lines.append("- None.")
        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)


class CrossArtifactCorrelator:
    def __init__(self):
        self.audit = ImmutableStamp()

    def correlate(
        self,
        target_pid: int,
        hunt_result: dict | None = None,
        mapped_tactics: list | None = None,
        swarm_reports: list | None = None,
        registry_result: dict | None = None,
        mind_reader_result: dict | None = None,
    ) -> CorrelatedCaseFile:
        hunt_result = hunt_result or {}
        mapped_tactics = mapped_tactics or []
        swarm_reports = swarm_reports or []
        registry_result = registry_result or {}

        incident_id = f"CORRELATED_PID_{target_pid}_{int(time.time())}"
        case = CorrelatedCaseFile(target_pid=target_pid, incident_id=incident_id)

        # --- ingest per-artifact source --------------------------------
        temporal = hunt_result.get("temporal_vector")
        if temporal:
            case.timeline_events.append({"source": "HUNTER_PLASO", "detail": temporal})
        else:
            case.coverage_gaps.append("timeline (Plaso) unavailable or empty")

        spatial = hunt_result.get("spatial_vector")
        if spatial:
            case.filesystem_artifacts.append({"source": "HUNTER_TSK", "detail": spatial})
        else:
            case.coverage_gaps.append("filesystem (TSK) unavailable or empty")

        registry_vector = registry_result.get("registry_vector")
        if registry_vector:
            case.registry_findings.append({"source": "HUNTER_REGLOOKUP", "detail": registry_vector})
        elif registry_result.get("status") == "SKIPPED":
            case.coverage_gaps.append("registry hunt skipped (no hive path configured)")
        else:
            case.coverage_gaps.append("registry (reglookup) unavailable or empty")

        for report in swarm_reports:
            if not isinstance(report, dict):
                continue
            agent = report.get("agent", "UNKNOWN_AGENT")
            bucket = case.network_findings if "Network" in agent else case.memory_findings
            for finding in report.get("findings", []):
                bucket.append({"source": agent, "detail": finding})

        if not any(isinstance(r, dict) and r.get("agent") == "Network_Agent" for r in swarm_reports):
            case.coverage_gaps.append("network agent did not report")
        if not any(isinstance(r, dict) and r.get("agent") == "Memory_Agent" for r in swarm_reports):
            case.coverage_gaps.append("memory agent did not report")

        for entry in mapped_tactics:
            if not isinstance(entry, dict):
                continue
            for tactic in entry.get("matched_tactics", []):
                case.mitre_tactics.append(
                    {
                        "mitre_id": tactic.get("mitre_id"),
                        "desc": tactic.get("tactical_desc"),
                        "raw_evidence": entry.get("raw_evidence"),
                    }
                )

        if mind_reader_result and mind_reader_result.get("status") == "SUCCESS":
            signature_id = mind_reader_result.get("signature_id")
            if signature_id:
                case.cve_correlations.append(
                    {
                        "cve_id": signature_id,
                        "source": "MINDREADER_SCHEMA_MIMICRY",
                    }
                )

        # --- cross-source corroboration / contradiction -----------------
        self._check_c2_corroboration(case)
        self._check_process_injection_corroboration(case)

        self.audit.record_action(
            "CORRELATOR",
            "CASE_FILE_COMPILED",
            f"Correlated {len(case.mitre_tactics)} MITRE tactic claim(s), "
            f"{len(case.corroborated_tactics)} corroborated, "
            f"{len(case.contradictions)} uncorroborated, for PID {target_pid}.",
            metadata={
                "target_pid": target_pid,
                "incident_id": incident_id,
                "coverage_gaps": case.coverage_gaps,
            },
        )
        return case

    def _check_c2_corroboration(self, case: CorrelatedCaseFile) -> None:
        """
        T1071 (Application Layer Protocol / C2) is a keyword-only match in
        MitreMapper -- it fires on words like "beacon"/"outbound" found
        ANYWHERE in anomaly text, with no verification against actual
        network evidence. Cross-check against Swarm's network findings
        before letting the claim stand as corroborated.
        """
        claims_c2 = any(t.get("mitre_id") == "T1071" for t in case.mitre_tactics)
        if not claims_c2:
            return

        # Deliberately narrow: swarm.py's own "clean" findings also contain
        # the words "external" and "C2" (e.g. "...without obvious external
        # C2 anomalies") -- a loose external|c2 substring match would
        # corroborate off a finding that explicitly says NOTHING was found.
        # Match only the specific positive-signal phrasings swarm.py emits
        # when it actually flags something.
        positive_signal = re.compile(
            r"external connection\(s\) observed|"
            r"detected external connection\(s\)|"
            r"flagged external destination\(s\)|"
            r"confirmed command-and-control",
            re.IGNORECASE,
        )
        network_confirms = any(
            positive_signal.search(f.get("detail", "")) for f in case.network_findings
        )
        if network_confirms:
            if "T1071" not in case.corroborated_tactics:
                case.corroborated_tactics.append("T1071")
        else:
            case.contradictions.append(
                {
                    "claim": "T1071 (C2 beacon) flagged by MitreMapper keyword match",
                    "issue": "No corroborating external connection found in Swarm's "
                    "network agent findings for this incident.",
                }
            )

    def _check_process_injection_corroboration(self, case: CorrelatedCaseFile) -> None:
        """
        T1055 (Process Injection, IoE signature PE_INJECT) fires on
        keywords like "inject"/"unbacked"/"vad"/"shellcode" found ANYWHERE
        in anomaly text -- same single-source-keyword weakness as C2
        above. A real process injection event should also leave a trace
        in the Plaso timeline (e.g. an unbacked/anomalous memory region or
        injection-related process event), not just an anomaly-text hit.
        """
        claims_injection = any(t.get("mitre_id") == "T1055" for t in case.mitre_tactics)
        if not claims_injection:
            return

        timeline_confirms = any(
            re.search(r"inject|unbacked|shellcode|vad", e.get("detail", ""), re.IGNORECASE)
            for e in case.timeline_events
        )
        if timeline_confirms:
            if "T1055" not in case.corroborated_tactics:
                case.corroborated_tactics.append("T1055")
        else:
            case.contradictions.append(
                {
                    "claim": "T1055 (Process Injection) flagged by MitreMapper keyword match",
                    "issue": "No corroborating injection-related event found in "
                    "the Plaso timeline for this incident.",
                }
            )


# ==============================================================================
# CLI EXECUTION BLOCK (manual smoke-check with synthetic inputs)
# ==============================================================================
if __name__ == "__main__":
    correlator = CrossArtifactCorrelator()
    demo_case = correlator.correlate(
        target_pid=1234,
        hunt_result={"temporal_vector": "Shell execution near PID 1234", "spatial_vector": None},
        mapped_tactics=[
            {
                "raw_evidence": "outbound beacon detected",
                "matched_tactics": [{"mitre_id": "T1071", "tactical_desc": "Application Layer Protocol (C2)"}],
            }
        ],
        swarm_reports=[{"agent": "Network_Agent", "findings": ["TShark completed without obvious external C2 anomalies."]}],
        registry_result={"status": "SKIPPED", "registry_vector": None},
    )
    print(demo_case.to_report_text())
