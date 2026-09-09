<div align="center">
  <h1>YOMI TRIAGE SYSTEM</h1>
  <h2>System Architecture & Module Reference</h2>
</div>

## Table of Contents
1. [System Architecture & Data Flow](#1-system-architecture--data-flow)
2. [Yomi Lifecycle & Module Interoperability](#2-yomi-lifecycle--module-interoperability)
3. [Yomi Core Engines (The Arsenal)](#3-yomi-core-engines-the-arsenal)

---

## 1. System Architecture & Data Flow

![Yomi System Topology](System_Topology.svg)

Yomi intentionally separates the forensic ingestion layer, AI reasoning layer, and audit containment layer to enforce strict security boundaries. The LLM acts purely as a reasoning engine, while the OSBridge and MCP Vault handle physical execution.

### 1.1 Macro System Architecture

The following diagram maps how components connect (Evidence Swarm -> Aegis OSBridge -> OpenClaw Gateway -> Remediator). It shows where the Air-Gapped Harness executes architectural VETO constraints before commands ever reach the OS layer, distinctly separating LLM prompt logic from hardcoded deterministic logic.

```mermaid
graph TD;
    %% Artifact Sources & Evidence Swarm
    subgraph "Data Ingestion - The Evidence Swarm"
        A1[eBPF Ring-0 Telemetry]
        A2[Disk Images / Memory Dumps]
        V["Inode Pinning Vault (ARCHITECTURAL: Anti-TOCTOU)"]
        A1 & A2 --> V
    end

    %% Yomi Hardware Abstraction (The Guardrails)
    subgraph "Yomi Core Execution Bridge (Strict Boundaries)"
        B["The Aegis Harness (ARCHITECTURAL GUARDRAIL: Veto Engine)"]
        LS["Atomic Load Shedding (ARCHITECTURAL: F-DoS Protection)"]
        C["SiftArsenal: Global Thread Pool"]
        S["Anti-OOM Context Shield (ARCHITECTURAL: 100KB Limit)"]
    end

    %% AI Brain (Prompt Logic)
    subgraph "OpenClaw Gateway (LLM Cascade)"
        E1["Gemini 2.5 Pro (PROMPT-BASED REASONING)"]
        E2["Local Fallback (Air-Gapped)"]
    end

    %% Triage & Action (The Loop)
    subgraph "Tactical Orchestration"
        F["Triad Council / Epistemic Doubt (PERSISTENT LOOP: Max-Iterations Cap)"]
        G["Shadow Net: Ring-0 eBPF (Deterministic Fallback)"]
        I["Aegis Containment (OS-Level SIGSTOP)"]
    end

    %% Forensic Audit
    subgraph "Forensic Audit Center"
        H[("HMAC-SHA256 Cryptographic Ledger (Immutable)")]
    end

    %% Data Flow
    V --> B
    B --> LS
    LS -- "Valid Tasks" --> C
    C -- "Massive Outputs" --> S
    S -- "Truncated Safe Context" --> E1
    E1 & E2 --> F
    F -- "If Doubt < 40%" --> I
    F -- "If Doubt > 40% (Escalate/Loop)" --> G
    G -- "Malicious Syscalls Verified" --> I
    I & G --> H
```

### 1.2 MCP Tool Execution & Anti-Spoliation Data Flow

This sequence demonstrates how the MCP Server acts as an architectural guardrail. It prevents LLM hallucinations from executing arbitrary commands and forces the agent to self-correct if it provides invalid arguments, requests missing tools, or if the underlying forensic tool crashes.

```mermaid
sequenceDiagram;
    participant LLM as OpenClaw LLM (Prompt Logic)
    participant Vault as MCP Vault (Architectural Guardrail)
    participant SIFT as SIFT Toolkit (C-Binaries)

    LLM->>Vault: Request execution (e.g., run_scalpel)
    Note over Vault: ARCHITECTURAL BOUNDARY CHECK

    alt Command Injection or Target PID 1 Detected
        Vault-->>LLM: VETO_ENGAGED: Action blocked by hardcoded logic gate.
    end

    Vault->>Vault: Check Active Tasks (Load Shedding)
    alt System Saturated
        Vault-->>LLM: VETO: OVERLOAD. Request Dropped.
    else Worker Available
        Vault->>SIFT: Dispatch via Process Group Isolation (shell=False)

        alt Execution Timeout (> 300s)
            SIFT->>SIFT: os.killpg() (Annihilate Zombie Process)
            Vault-->>LLM: Error: Execution Timeout.
        else Execution Success
            SIFT-->>Vault: Massive Raw Output Stream (e.g., 4GB)
            Note over Vault: ARCHITECTURAL GUARDRAIL: Context Shield
            Vault->>Vault: Truncate precisely to 100KB
            Vault-->>LLM: Safe, Truncated IoC Context returned
        end
    end
```

### 1.3 Security Boundary Enforcement Summary

-   **Prompt-Based Guardrails:** Prompt engineering is used *only* for cognitive formatting (e.g., instructing the LLM to output valid JSON or map findings to MITRE ATT&CK). Prompts are **never** relied on for system safety.

-   **Architectural Guardrails (Enforced):** Security boundaries are enforced via Python logic gates outside the LLM's context window. The `Aegis Harness` utilizes deterministic `if/else` evaluations against protected PIDs. The `Context Shield` utilizes strict `buffer.read(100000)` OS-level limits. An LLM hallucination physically cannot bypass these mechanisms.

## 2. Yomi Lifecycle & Module Interoperability

The state diagram below shows how Yomi's Python modules interact dynamically during an active incident, from swarm deployment through containment to audit sealing. This modular design prevents deadlocks and ensures rapid threat response.

```mermaid
stateDiagram-v2
    [*] --> SwarmDeploy : Systemd Boot / CLI Exec

    state "Observation & Telemetry" as Observation {
        state "Pin Inodes / Secure Files" as InodeLock
        state "Network/RAM Sweeps" as Sweep
        state "Start Dual-Lock Timer" as Timer

        SwarmDeploy --> InodeLock
        InodeLock --> Sweep
        Sweep --> Timer
    }

    state "Analysis & Validation Layer" as Analysis {
        state "Omni-Sanitizer (Scrub Secrets)" as Sanitize
        state "Library.py (O(1) CVE Matching)" as IntelIngest
        state "Epistemic Doubt Check (AUTONOMOUS REASONING)" as DoubtCheck

        Timer --> Sanitize
        Sanitize --> IntelIngest
        IntelIngest --> DoubtCheck
    }

    state "Containment & Forensics Layer" as Action {
        state "SIGSTOP / Aegis Harness (ARCHITECTURAL CONTAINMENT)" as Remediate
        state "Shadow Net eBPF (Ring-0 Fallback)" as ShadowNet
        state "Atomic ELF Necromancy" as Necromancy

        DoubtCheck --> Remediate : Doubt < 40%
        DoubtCheck --> ShadowNet : Doubt > 40% (Self-Correct / Loop)
        ShadowNet --> Remediate : Malicious Syscalls Confirmed
        ShadowNet --> Necromancy : Fileless Threat Detected
    }

    state "Audit & Reporting Layer" as Audit {
        state "stamp.py (HMAC-SHA256: IMMUTABLE EVIDENCE LEDGER)" as Stamp
        state "dossier.py (Human-Readable Export - Known Bias)" as Dossier
        state "Stop Timer (TTC Benchmark)" as TimerStop

        Remediate --> Stamp
        Necromancy --> Stamp
        Stamp --> TimerStop
        TimerStop --> Dossier
    }

    state "Graceful Shutdown" as Shutdown {
        state "Systemd SIGTERM Catch" as Sigterm
        state "Atomic Rollback (Ghost Protocol)" as Rollback
    }

    Dossier --> [*] : Terminate Lifecycle / Standby
    Observation --> Sigterm
    Sigterm --> Rollback
    Rollback --> [*]
```

> **Module wiring (Fase 6, Tahap 1):** `sentinel.py`'s autonomous loop wires in all 13 modules via `yomi_core/guardian.py`'s `GuardianOrchestrator`, gated entirely by `yomi_core/module_registry.py`. `swarm`, `hunter`, `router`, `mitre_mapper`, and `telemetry` run every observation cycle; `mind_reader`, `remediator`, `dossier` dispatch after a synchronous containment success; `shadow_net` dispatches (fire-and-forget) on escalation; `sandbox` and `mirage` dispatch after containment if their invasive tier is explicitly enabled; `ghost` and `ebpf_sensor` are wired at CLI startup. See [`docs/known_issues.md`](known_issues.md) #11 for the full dispatch design and #25/#26 for two env-var gating inconsistencies found and fixed while wiring this.

## 3. Yomi Core Engines (The Arsenal)

Beyond standard MCP wrappers, Yomi implements several deeply integrated, advanced DFIR subsystems:

- **The Evidence Swarm (`swarm.py`):** The central orchestrator. Hardened with **Inode Pinning (OS Hardlinks)** to obliterate Time-of-Check to Time-of-Use (TOCTOU) attacks. Uses an **Anti-OOM Context Shield (100KB Dynamic Truncation)** and bounded regex to prevent Catastrophic Backtracking (ReDoS) when ingesting massive datasets.

- **The Aegis Harness (`harness.py`):** The Zero-Trust Policy Gatekeeper. Before any OS-level intervention (freeze/thaw) is routed to the Kernel, the Harness validates it. Built with **Kernel Thread Immunity** (safeguarding intangible OS structures without `exe_path` limits) and **Realpath Pinning** to defeat Process Name Spoofing and Symlink Path Hijacking.

- **Chronos Telemetry Engine (`telemetry.py`):** Uses a **Dual-Lock Architecture** and **O(1) Memory Eviction** to ensure zero RAM bloat during massive, multi-threaded incident tracking, delivering cryptographically signed latency benchmarks.

- **Human-Readable Executive Dossiers (`dossier.py` & `weaver.py`):** Procedurally generates human-readable forensic timelines mapped to MITRE ATT&CK. The court-ready evidence lives in the JSONL ledger; this module compiles rapid PDF/TXT annexes for human analysts.

- **The Omni-Library (`library.py` v4.0):** An O(1) local Threat Intelligence Database. Uses In-Memory LRU Caching and Memory-Safe Streams to query NVD/CVE definitions without causing Out-of-Memory (OOM) spikes during intense triage.

- **OmniVector Root-Cause Hunter (`hunter.py`):** Traces "Patient Zero" by correlating Volatility memory artifacts with Plaso super-timelines and TSK deleted file recoveries, using strict word-boundary regex.

- **Mind-Reader Decompiler (`mind_reader.py`):** Autonomously executes Radare2 against frozen malware to extract Assembly logic. Built with a **Native Python Extraction Fallback**: if Radare2 fails or is unavailable, it gracefully degrades to a native 1MB binary string extraction so the LLM never loses actionable artifacts.

- **The Lazarus Chamber & Mirage Protocol (`mirage.py` & `sandbox.py`):** A deep isolation sandbox. Extracted malware is awakened (`SIGCONT`) within a synthetic hallucinated environment. Built with an Autonomous Orphan Sweeper to prevent storage bloat.

- **The Shadow Net (`ebpf_sensor.py` & `shadow_net.py`):** Injects C code directly into the Linux Ring-0 Kernel via Tracepoints. Features **Secure ELF Necromancy** to physically reconstruct fileless malware from RAM into an **Atomic Vault** (secured with an explicit `os.chmod(0o700)` right after directory creation -- see [`docs/known_issues.md`](known_issues.md) #23 for why relying on `os.umask()` alone was insufficient).

- **Aegis Reverser Engine (`remediator.py`):** Automatically generates and GPG-signs verifiable bash scripts to roll back changes made by malware. Hardened against Bash Comment Injection (newline stripping) and enforces strict military-grade triage ordering (`SIGSTOP -> DUMP -> SIGKILL`).

- **Ghost Protocol (`ghost.py`):** Deep OS Camouflage. Evades malware anti-analysis by masquerading the Yomi daemon as a standard OS process (e.g., `[kworker/u4:2]`). Armed with an autonomous **Dead Man's Switch (Watchdog)** that seals a final cryptographic log if malware successfully issues a kill signal to the EDR.

- **The OMNISCIENT Torii Gateway (`dashboard.py` v10.0):** A responsive, real-time, non-blocking Terminal UI (TUI) built with `rich`. Hardened against Terminal Spoofing, Lock Starvation, and VFS I/O Lag.

---

See also: [`docs/security.md`](security.md) for the threat model and hardening detail behind these modules, and [`docs/known_issues.md`](known_issues.md) for the running log of confirmed gaps and fixes across all of them.
