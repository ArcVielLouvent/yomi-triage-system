<div align="center">
  <h1>YOMI TRIAGE SYSTEM</h1>
  <h2>Dataset & Reproducibility Documentation</h2>
</div>

## 1. Overview & Dataset Strategy

This document outlines the datasets, memory captures, and telemetry logs utilized to evaluate the **KuroTech Yomi** architecture. In alignment with the SANS Find Evil! Hackathon mandate, we utilized a combination of exact official case data and live deterministic OS artifacts.

### A. SANS Official Starter Case Data (Ground Truth)
To rigorously test Yomi's Model Context Protocol (MCP) and Architectural Vault Shields, we utilized the official SANS-provided datasets.
-   **Specific Target:** `win7-32-nromanoff-memory.001` (2GB Memory Dump)
-   **Usage in Yomi:** Used specifically to benchmark `mcp_server.py` via Volatility. We proved that Yomi can ingest a 2GB memory dump, parse it through Volatility `malfind`, and architecturally truncate the output to 100KB *before* it hits the LLM, preventing context window overflow (OOM).
-   **What It Found:** The agent successfully parsed the truncated payload, identifying embedded memory anomalies without suffering from token exhaustion.

### B. Live System Binaries & Syscalls (Native OS Testing)
To test the live-action components of Yomi (eBPF sensors and Autonomous Containment) without introducing live malware that could corrupt the SIFT environment, we utilized standard Linux processes generating intentional, malicious-looking I/O anomalies (e.g., bypassing standard file access to read `/etc/shadow` via file descriptors).
-   **What It Found:** The system successfully detected `openat` syscall anomalies, autonomously issued `SIGSTOP` freezes, mapped the behavior to MITRE ATT&CK Tactics (e.g., T1027), and generated dynamic APT signatures (e.g., `CVE-2026-YOMI4209`) directly into the local Threat Intel database.


## 2. Reproduce Instructions (Replicating the Video Demo)

To ensure perfect deterministic evaluation, SANS Judges can replicate the exact sequence demonstrated in our submission video by running the following commands on a standard SANS SIFT Workstation (v2026).

**Preparation:** Open two terminal windows side-by-side. Log into both as root (`sudo su -`) and navigate to the project directory: `cd /home/sansforensics/yomi-triage-system`. Ensure your Gemini API key is exported: `export GEMINI_API_KEY="YOUR_KEY"`.

### Step 1: Initialize the EDR & eBPF Hooks

*Terminal 1 (Left)* - Clean the previous ledger and boot the Yomi UI gateway. This autonomously invokes LLVM to compile and inject the Ring-0 eBPF sensor.

```bash
rm -f yomi_data/*.jsonl* yomi_data/*.lock yomi_data/reports/*; clear
python3 yomi_core/cli.py --auto

```

*(Leave this terminal running. The TUI will actively monitor kernel syscalls).*

### Step 2: Trigger an Evasive Threat (Autonomous Containment)

*Terminal 2 (Right)* - Simulate an adversary using a file descriptor to bypass traditional monitoring and access a critical file.

Bash

```bash
bash -c 'exec 3< /etc/shadow; sleep 300' &

```

> **Validation:** Terminal 1 will immediately flash RED. The eBPF sensor intercepts the `openat` syscall and autonomously issues a `SIGSTOP` freeze with zero human intervention. Note the Target PID generated.

### Step 3: Test Swarm & Hunter (Honesty Over Perfection)

*Terminal 2 (Right)* - Pass the frozen PID (e.g., `1234`) to the concurrent Swarm and disk artifact Hunter.


```bash
export YOMI_FORENSIC_PATH="/dev/sda1"
python3 yomi_engine/swarm.py
python3 yomi_engine/hunter.py <INSERT_FROZEN_PID>

```

> **Validation:** Observe the Hunter agent gracefully handling a `plaso` spatial error on the unsupported `/dev/sda1` partition. It logs the failure and self-corrects its investigative path instead of crashing.

### Step 4: AI Reasoning & Token Provenance

*Terminal 2 (Right)* - Run the Mind-Reader decompiler to profile the threat using the LLM.

```bash
python3 yomi_engine/mind_reader.py /bin/ls <INSERT_FROZEN_PID>

```

> **Validation:** This proves authentic AI execution. The LLM generates a psychological profile of the threat and strictly injects its exact Token Usage metrics directly into the cryptographic ledger.

### Step 5: Test Architectural Guardrails (Vault Shield & Veto)

*Terminal 2 (Right)* - Test Yomi's hardcoded constraint implementations without relying on LLM prompt-adherence.

*Test the Volatility Vault Shield (Requires the SANS memory dump placed in the path below):*


```bash
python3 -c "from yomi_mcp.mcp_server import YomiMCPServer; print(YomiMCPServer().call_tool('run_volatility_linux_malfind', {'memory_dump_path': '/mnt/cases/sans_hackathon/memory_dumps/win7-32-nromanoff.raw'}))"

```

*Test the Air-Gapped Harness Veto (Attempting to freeze critical PID 1):*


```bash
python3 -c "from yomi_mcp.harness import YomiHarness; print(YomiHarness().process_intent('{\"action\": \"freeze\", \"target_pid\": 1}'))"

```

> **Validation:** The Harness explicitly rejects the action and logs `VETO_ENGAGED`. This proves that security boundaries are enforced architecturally, not via prompts.

### Step 6: Generate the Court-Ready Dossier

*Terminal 2 (Right)* - Parse the ledger and compile the final human-readable report.

```bash
python3 yomi_engine/dossier.py

```

> **Validation:** Open the generated PDF in yomi_data/reports/. Note that while this PDF serves as a quick human-readable summary, the true "Court-Ready" immutable evidence is the cryptographically sealed yomi_chain_of_custody.jsonl file, which securely preserves all AI profiles and VETO records.