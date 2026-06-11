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
- **Usage in Yomi:** Used directly to benchmark `hunter.py` (Volatility/Plaso tracing) and validate the autonomous capability to prevent LLM hallucination when ingesting multi-gigabyte data streams.

### B. Live System Binaries (Native OS Testing)
To test the live-action components of Yomi (such as `ebpf_sensor.py`, `os_bridge.py`, and `harness.py`) without introducing live malware into the SIFT environment, we utilized standard, benign Linux processes:
- **Usage:** Long-running sleep commands or standard networking tools (`curl`) are used as safe, observable targets to validate Ring-0 syscall hooks, PID freezing (SIGSTOP), and process resumption (SIGCONT) autonomously without corrupting the host machine.

## 3. Data Structure & OPSEC Compliance

To comply with GitHub's Terms of Service and KuroTech's strict Operational Security (OPSEC) protocols, **no live malware, multi-gigabyte memory dumps, or massive disk images are committed to this repository.**

For SANS Judges reproducing this environment on a standard SIFT Workstation OVA, please structure your local data directory as follows to mirror the testing environment:

```text
/mnt/cases/sans_hackathon/
├── memory_dumps/
│   └── sans_case_01.raw
├── disk_images/
│   └── sans_case_01.E01
└── pcaps/
    └── lateral_movement.pcap

````

> ⚠️ **PATH ENFORCEMENT NOTICE:** Yomi's MCP Vault (`sift_toolkit.py`) strictly enforces **Absolute Path Declarations** to prevent Relative Path Traversal attacks. Always provide the full absolute path to the LLM during triage tasks.

## 4. Reproducibility & Testing Instructions

To ensure deterministic evaluation, follow these replication steps on your SIFT workstation:

### Test 1: Volatility Memory Analysis (Context Shield & Privilege Validation)

This test validates Yomi's capability to safely ingest heavy forensic outputs at the OS level. Reading raw memory devices requires root privileges.

1.  Mount or place the SANS memory dump in your local directory.

2.  Engage Yomi via the global entry point with root privileges:

    ```bash
    sudo yomi-triage --auto

    ```

3.  Input the natural language prompt: _"Scan the absolute path /mnt/cases/sans_hackathon/memory_dumps/sans_case_01.raw using Volatility and extract injected PIDs."_

4.  **Expected Result:** Yomi's MCP server autonomously validates the path, invokes `volatility -f ... malfind`, applies the _100KB Anti-OOM Context Shield_, and prints a structured payload containing the flagged processes.

### Test 2: Autonomous eBPF Ring-0 Hook Execution (Shadow Net)

This test validates the non-interactive, low-level kernel tracking mechanism. You can run the target process in the background and seamlessly pass its PID to the sensor in a single automated command line.

1.  Execute a background benign process and attach the eBPF hook immediately:

    ```bash
    sleep 300 & sudo python3 yomi_engine/ebpf_sensor.py $!

    ```

2.  **Expected Result:** Yomi will grab the PID of the spawned sleep process (`$!`), attach the eBPF kernel hooks (`sys_enter`), and stream real-time syscall telemetries to the terminal.

3.  Press `Ctrl+C` to cleanly detach the eBPF hooks from the kernel state.

## 5. Cryptographic Artifact Ledger & Verification

All execution interactions during our internal testing phase have been securely purged from this production repository to ensure a pristine deployment slate.

When judges execute triage commands, new deterministic cryptographic hashes will be generated autonomously and sealed within `yomi_data/yomi_chain_of_custody.jsonl`.

### Verifying Ledger Integrity (Autonomous Boot Check)

Unlike standard EDRs that require manual log audits, Yomi integrates Autonomous Cryptographic Verification directly into its boot sequence (`cli.py`).

To verify that your audit trail has not been tampered with, simply start the engine:

```bash
sudo yomi-triage --auto

```

**Expected Behavior:** During the initialization phase, the `_prepare_runtime_environment()` function traverses the entire HMAC-SHA256 ledger chain.

- If the chain is mathematically intact, the CLI will output: `Validated Yomi data store`.

- If any malware has modified a single byte of the log file, the system will instantly throw an integrity warning and record a `LEDGER_VERIFICATION_WARNING` audit event.
