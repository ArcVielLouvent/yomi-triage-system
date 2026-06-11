# YOMI TRIAGE SYSTEM: Dataset & Reproducibility Documentation

## 1. Overview
This document outlines the datasets, memory captures, disk images, and telemetry logs utilized to evaluate, benchmark, and validate the **Yomi Triage System** during the SANS "Find Evil!" Hackathon.

All datasets were curated to rigorously test Yomi's autonomous capabilities under hostile conditions:
- **OpenClaw LLM Validation:** Testing the accuracy of the Triad Council and Epistemic Doubt threshold (>40%) using high-noise artifacts.
- **MCP OSBridge Stability:** Ensuring legacy SIFT Toolkit C-binaries execute without causing resource exhaustion (OOM) via the 100KB Context Shield.
- **Ring-0 Telemetry:** Validating the eBPF tracepoints (The Shadow Net) against evasive fileless malware syscalls.

## 2. Primary Data Sources

### A. SANS Official Starter Case Data (Ground Truth)
The baseline foundation for our forensic testing utilizes the exact official case data provided by the SANS Institute. We highly recommend judges utilize this identical dataset to reproduce our Live Triage benchmarks.
- **Source:** [SANS Official Egnyte Repository](https://sansorg.egnyte.com/fl/HhH7crTYT4JK)
- **Data Types:** Memory Dumps (Raw RAM captures), Disk Images (E01/DD), and Network PCAPs.
- **Usage in Yomi:** Used directly to benchmark `mcp_server.py` (Volatility/Plaso tracing) and validate the autonomous capability to prevent LLM hallucination when ingesting multi-gigabyte data streams.

### B. Live System Binaries (Native OS Testing)
To test the live-action components of Yomi (such as `ebpf_sensor.py` and `shadow_net.py`) without introducing live malware into the SIFT environment, we utilized standard, benign Linux processes generating intentional I/O noise.

## 3. Data Structure & OPSEC Compliance

To comply with GitHub's Terms of Service and KuroTech's strict Operational Security (OPSEC) protocols, **no live malware, multi-gigabyte memory dumps, or massive disk images are committed to this repository.**

For SANS Judges reproducing this environment on a standard SIFT Workstation OVA, please structure your local data directory as follows:

```text
/mnt/cases/sans_hackathon/
├── memory_dumps/
│   └── sans_case_01.raw
├── disk_images/
│   └── sans_case_01.E01
└── pcaps/
    └── lateral_movement.pcap

```

> ⚠️ **PATH ENFORCEMENT NOTICE:** Yomi's MCP Vault (`mcp_server.py` & `sift_toolkit.py`) strictly enforces **Absolute Path Declarations**. Relative Path Traversal attempts will be autonomously vetoed.

## 4. Reproducibility & Testing Instructions

To ensure deterministic evaluation, follow these replication steps on your SIFT workstation:

### Test 1: MCP Server Volatility Analysis (Context Shield Validation)

This test validates Yomi's Model Context Protocol (MCP) server capability to safely ingest heavy forensic outputs at the OS level.

1.  Mount or place the SANS memory dump in your local directory.

2.  Configure your AI Agent (e.g., Claude Code, OpenClaw) to connect to Yomi's MCP Server. The server communicates via standard I/O:

    ```bash
    sudo python3 yomi_mcp/mcp_server.py

    ```

3.  Issue the natural language prompt to your Agent: *"Use the MCP tool 'run_volatility_linux_malfind' to scan the absolute path `/mnt/cases/sans_hackathon/memory_dumps/sans_case_01.raw`"*

4.  **Expected Result:** The MCP server autonomously validates the path, invokes Volatility, applies the *100KB Anti-OOM Context Shield*, and returns a safe, truncated JSON payload to the LLM without crashing the memory context.

### Test 2: Autonomous eBPF Ring-0 Hook Execution (Shadow Net)

This test validates the low-level kernel tracking mechanism natively. A dormant `sleep` process generates no telemetry, so we use a safe I/O loop to simulate noisy malware.

1.  Execute a background noisy process and attach the eBPF hook immediately:

    ```bash
    while true; do cat /etc/hostname > /dev/null; sleep 0.2; done & sudo python3 yomi_engine/ebpf_sensor.py $!

    ```

2.  **Expected Result:** Yomi will grab the PID of the spawned loop (`$!`), attach the eBPF kernel hooks (`sys_enter`), and continuously stream real-time syscall telemetries to the terminal.

3.  Press `Ctrl+C` to cleanly detach the eBPF hooks.

## 5. Cryptographic Artifact Ledger & Verification

All execution interactions during our internal testing phase have been securely purged from this repository to ensure a pristine deployment slate.

When Yomi operates, new deterministic cryptographic hashes will be generated autonomously and sealed within `yomi_data/yomi_chain_of_custody.jsonl`.

### Verifying Ledger Integrity (Autonomous Boot Check)

Unlike standard EDRs that require manual log audits, Yomi integrates Autonomous Cryptographic Verification directly into its boot sequence via `validate_data_store()`.

To verify that your audit trail has not been tampered with, initialize the Triage CLI:


```bash
sudo yomi-triage --auto

```

**Expected Behavior:** During the startup sequence, `cli.py` invokes the validation engine. If the HMAC-SHA256 ledger chain is mathematically intact, the CLI boot proceeds to the Sentinel Dashboard. If any data has been modified, the `logger` will instantly throw an anomaly warning indicating the data store is compromised.