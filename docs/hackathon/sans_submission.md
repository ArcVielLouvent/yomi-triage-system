<div align="center">
  <h1>YOMI TRIAGE SYSTEM</h1>
  <h2>SANS "Find Evil!" Hackathon Submission — Archived</h2>
</div>

> **Archive note:** This document preserves the original hackathon-facing framing and judging-criteria mapping from the SANS Institute *Find Evil!* "Protocol SIFT" Hackathon submission. Yomi did not place in the Top 5 finalists (Camel, FindEvil, Mulder, Protocol SIFT++, TRUDI). It is kept here for reference and provenance, separate from the current project documentation in [`../../README.md`](../../README.md) and the rest of `docs/`.

---

## SANS Hackathon Compliance Checklist

| Requirement | Status | Location / Link |
| :--- | :---: | :--- |
| **1. Code Repository & License** | ✅ | Public GitHub Repository. [MIT License](../../LICENSE) is included in the root directory. |
| **2. Demo Video (Max 5 Min)** | ✅ | Available on YouTube: [YouTube](https://www.youtube.com/watch?v=212GHYCgO8c&feature=youtu.be) |
| **3. Architecture Diagram** | ✅ | See [`docs/architecture.md`](../architecture.md) (Mermaid diagrams & AI-readable captions). |
| **4. Written Project Description** | ✅ | Full narrative available on the [Devpost Submission Page](https://devpost.com/software/yomi-triage-system-autonomous-dfir-engine). |
| **5. Dataset Documentation** | ✅ | Located in [`docs/dataset_documentation.md`](../dataset_documentation.md). Details SANS Egnyte Ground Truth and native OS testing. |
| **6. Accuracy Report** | ✅ | Located in [`docs/accuracy_report.md`](../accuracy_report.md). Details VETO constraints, hallucination defense, and known dossier bias. |
| **7. Try-It-Out Instructions** | ✅ | Step-by-step SIFT deployment guide located in `docs/dataset_documentation.md`. |
| **8. Agent Execution Logs** | ✅ | Cryptographic traces (iteration loops, vetoes, and token usage) preserved in `yomi_data/yomi_chain_of_custody.jsonl`. |

*Note: Datasets (such as the DFRWS 2008 Memory Dump) are not hosted in this repository due to size constraints. Instructions to download and mount them to the SIFT Workstation are detailed in the Dataset Documentation.*

## Executive Summary / Problem Statement

**The 60-Second Gap Problem:** Modern autonomous offensive AI engines (like Horizon3/NodeZero) boast a full network compromise breakout time of under 60 seconds. Anthropic's security team observed state-sponsored actors utilizing LLMs (GTG-1002) at request rates physically impossible for humans. Meanwhile, traditional human-driven SOC analysis and manual CLI incident response remain bottlenecked by human keystroke latency, creating a catastrophic window of opportunity for adversaries.

**The Yomi Triage Response:** Yomi is engineered to operate on a fundamentally faster timeline. By orchestrating SANS SIFT Workstation forensic tools through a strict, type-safe Model Context Protocol (MCP) server and evaluating evidence via a cascading Epistemic Doubt Engine, **Yomi targets a Time-to-Containment (TTC) of < 5 seconds**. While offensive AIs are still deploying initial payloads, Yomi autonomously observes the anomaly, Orients via SIFT tool parsing, Decides via OpenClaw LLM logic, and Acts by freezing the suspect process --- preserving the live VAD memory state and locking the forensic artifacts into a cryptographically sealed ledger.

## SANS Alignment Matrix

Yomi was engineered to directly answer the core challenges and judging criteria established by the SANS *Find Evil!* Hackathon.

| SANS Challenge / Criteria | The Yomi Architectural Solution |
| :--- | :--- |
| **The Speed Problem (Beat 60s AI Breakout)** | `telemetry.py` benchmarks demonstrate a Time-to-Containment of **~3.002 seconds**. The Sentinel daemon leverages the Evidence Swarm for rapid User-Space/Socket anomaly detection. Upon C2 confirmation, it bypasses LLM latency entirely ("Shoot First" logic) and executes containment through **Atomic OS Syscalls (`kill -STOP`)**. If the threat is obfuscated, it escalates to Ring-0 eBPF Tracepoints. |
| **Judging 1: Autonomous Execution & Self-Correction** | **Persistent Learning Loop & Graceful Degradation.** Yomi evaluates tool outputs through structured `TRIAGE_ITERATIONS`. To prevent infinite conversational spirals, a `--max-iterations` cap is architecturally enforced. Once reached, the agent halts the LLM and falls back to a deterministic `Shadow Net` response. |
| **Judging 4: Architectural vs. Prompt-Based Guardrails** | **Architectural enforcement, not prompt trust (Air-Gapped Harness).** Critical boundary checks are hardcoded. If the AI hallucinates an intent to freeze a protected OS process (e.g., target PID 1), the Harness intercepts it and executes a deterministic `VETO_ENGAGED` block. |
| **Context Window Overload (The SIFT Dump Problem)** | **Anti-OOM RAM Limiter & Omni-Sanitizer.** SIFT tools (like Volatility) can dump gigabytes of data. Yomi's Swarm orchestrator physically bounds RAM reads (max 2MB), extracts purely relevant IoCs (IPs, PIDs, MITRE Tactics), and strips ANSI/Newline injections *before* context is sent to the LLM. |
| **Judging 5: Audit Trail Quality** | **Cryptographic Chain of Custody (`stamp.py`).** Every AI decision, tool execution, and state change is HMAC-SHA256 signed in an append-only JSONL ledger. `weaver.py` converts this to a human-readable Temporal Narrative. |
| **Judging 2: IR Accuracy & Hallucination Defense** | **Zero-Hallucination Threat Intel.** `library.py`, a local O(1) in-memory LRU cache database, matches Volatility/TShark findings to local CVE definitions, stripping the LLM of its ability to fabricate threat intel. |
| **Judging 3: Breadth and Depth of Analysis** | **Multi-Layered Hunting.** Scans RAM (`Memory_Agent`), Network (`Network_Agent`), Kernel Ring-0 (`Shadow_Net`), and Disk Timelines (`Hunter`). If malware is fileless, *Secure ELF Necromancy* recovers the payload directly from RAM into an isolated vault for the `Sandbox` to analyze. |

## Original Development Roadmap (as submitted)

-   **Phase 1 (Hackathon submission):** Full autonomous incident triage utilizing SIFT tools via MCP. Ring-0 monitoring via eBPF.
-   **Phase 2 (The Ephemeral Docker Bridge):** OS-Agnostic Execution. Yomi would run natively on Windows/macOS endpoints, autonomously spinning up an ephemeral SIFT Docker container per memory-dump request, executing the Volatility command, extracting parsed results, and instantly destroying the container.

This roadmap has since been superseded by the post-hackathon evolution plan; see [`docs/roadmap/dfir-depth.md`](../roadmap/dfir-depth.md) for the current direction (cross-artifact correlation and DFIR-depth work) and [`docs/phase_log/`](../phase_log/) for phase-by-phase progress.

---

### License & Attribution

This project is licensed under the **MIT License**. See the [`LICENSE`](../../LICENSE) file for details.

Built under the **KuroTech** banner for the SANS Institute: Protocol SIFT Find Evil! Hackathon. Mentions and gratitude to the maintainers of the SIFT Workstation, Volatility Foundation, and the open-source DFIR community.
