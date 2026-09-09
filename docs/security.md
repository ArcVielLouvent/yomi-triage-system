<div align="center">
  <h1>YOMI TRIAGE SYSTEM</h1>
  <h2>Security & Compliance Framework</h2>
</div>

## Table of Contents
1. [Security & Compliance Framework](#1-security--compliance-framework)
2. [Threat Model & Security Boundaries](#2-threat-model--security-boundaries)
3. [Advanced Security Architecture](#3-advanced-security-architecture)

---

## 1. Security & Compliance Framework

Yomi is built with enterprise audit standards to ensure forensic integrity during automated response operations:

-   **HMAC-SHA256 Cryptographic Ledger (`stamp.py`):** Implements deterministic JSON canonicalization. Every action receives a unique signature keyed with an isolated `audit_hmac.key`, preventing post-incident tampering by threat actors.

-   **Cryptographic Dossier Signatures (`dossier.py`):** The Temporal Narrative is automatically compiled into PDF and raw TXT annexes. Yomi dynamically interfaces with the host's GPG binaries to apply detached cryptographic signatures to these summary reports, ensuring their origin cannot be spoofed.

-   **Optional KMS-backed HMAC key storage:** Yomi can load the ledger key from a remote key management service when configured via `YOMI_AUDIT_HMAC_KMS_PROVIDER` (`vault` or `aws-secrets-manager`).

-   **Air-gapped ephemeral HMAC key mode:** Set `YOMI_AUDIT_HMAC_MODE=ephemeral` to derive the HMAC key in memory only via PBKDF2. The key is never written to disk.

-   **Read-Only Forensic Tooling Execution:** Tools exposed to the LLM (like `fls` or `img_stat`) are executed strictly in read-only mode against evidentiary datasets via type-safe MCP wrappers.

-   **SOC Notary Checkpoints:** Generates mathematical attestations (in `.sig`-style JSON manifests) simulating Hardware Enclave isolation, so analysts can verify the state of the database immediately upon boot.

### MCP Vault Hardening Table

Unlike typical LLM agent wrappers, Yomi's MCP Vault was engineered to survive hostile, adversarial environments.

| Adversarial Tactic / Tool Failure | The Yomi MCP Server Mitigation |
| :--- | :--- |
| **Command Injection (RCE)** | **Absolute Regex Sealing.** Eradicates shell chaining `[;&\|$<>]` while preserving literal quotes for YARA/Regex syntax evaluation. |
| **Flag Injection Evasion** | **Literal Option Barriers.** Injects `--` before dynamic arguments, preventing malware named `-v` or `-p` from being parsed as CLI tool options by `grep`, `yara`, `ssdeep`, and `radare2`. |
| **Thread Exhaustion DoS** | **Atomic Load Shedding.** Global Thread Pool capped at 5 workers. Incoming requests beyond capacity are instantly vetoed (0s latency), preventing server queue freezing. |
| **I/O Blocking Deadlocks** | **Non-Blocking OS Descriptors.** Pipes utilize `fcntl.O_NONBLOCK`. If a C-binary hangs without closing its buffer, Yomi safely reads partial bytes without locking the main execution thread. |
| **Zombie Process CPU Starvation** | **Process Group Annihilation.** Forensic tools are launched with `start_new_session=True`. On timeout, `os.killpg()` atomically destroys the tool and all runaway child processes. |
| **Binary Extraction Corruption** | **Write-Binary Integrity.** Tools like `icat` extract unallocated inodes strictly in `"wb"` mode, preventing Python UTF-8 coercion from corrupting malware MD5/SSDEEP hashes. |
| **Context Window Blowout (OOM)** | **100KB Context Shield.** Massive artifacts (like multi-GB memory strings) are dynamically truncated at 100,000 characters before hitting the LLM context limits. |

## 2. Threat Model & Security Boundaries

- **LLM Hallucination & Command Injection (RCE):** Yomi treats the LLM purely as an untrusted inference engine. The custom MCP Server implements a regex shield `(\$\(|`|\||;|&&|\|\||>)` to eradicate shell chaining/subshell attacks, while safely preserving quoting for YARA/Regex execution.

- **Flag Injection Evasion (Anti-Forensic Defense):** Malware authors often name malicious files with leading hyphens (e.g., `-p` or `--help`) to trick DFIR tools into parsing them as operational flags, causing tool crashes or false negatives. Yomi's SIFT wrapper autonomously injects strict end-of-options literal barriers (`--`) into `grep`, `yara`, `ssdeep`, and `radare2`, ensuring arbitrary malicious filenames are always evaluated safely as literal string targets.

- **Forensic Denial of Service (F-DoS) & Thread Exhaustion:** To prevent an adversary from spamming heavy forensic tools to exhaust the server's RAM, Yomi deploys an Atomic Load Shedding Gatekeeper. It caps the Global Thread Pool at 5 workers. Incoming requests beyond this limit are instantly vetoed (0s latency). Critical containment signals (`run_cryogenic_freeze`) operate on a VVIP OS track, bypassing the thread pool entirely for guaranteed microsecond execution.

- **Context Exhaustion Protection (Context Shield):** When tools like `strings_grep` output gigabytes of text, the SIFT Toolkit buffers via non-blocking OS pipes (`fcntl.O_NONBLOCK`) and strictly truncates output at 100,000 characters (100KB). This ensures local, air-gapped LLMs never crash from context window blowout.

- **Evidence Spoliation & Binary Integrity:** Tools are rigidly mapped to `READ_VAULTS` and `WRITE_VAULTS` utilizing absolute structural boundary checks (`os.path.commonpath`). Raw artifact extractions (like TSK `icat`) are strictly written in write-binary (`wb`) mode, so the structural integrity and exact cryptographic hashes of recovered malware are preserved without UTF-8 corruption. *(Note: `READ_VAULTS`/`WRITE_VAULTS` are currently hardcoded absolute path prefixes rather than derived from `yomi_data`'s actual location -- tracked as a portability gap in [`docs/known_issues.md`](known_issues.md) #10.)*

- **Ghost Process Evasion & Bitness Mismatch:** Malware often terminates rapidly to force EDRs to target recycled PIDs (Ghost Processes). Yomi's `os_bridge.py` eliminates TOCTOU gaps by relying purely on atomic OS exception handling (`ProcessLookupError`) instead of user-space polling.

### Supported MITRE ATT&CK Mapping

| **IoE Signature** | **Description** | **MITRE ATT&CK ID** | **Detection Source** |
| --- | --- | --- | --- |
| `PE_INJECT` | Process injection and VAD tampering seen in memory scans | T1055 | Volatility `malfind` |
| `YR_RANSOMWARE` | High-entropy, mass file IO and encryption-related activity | T1486 | TShark / TSK FLS |
| `PROC_BAD_DTB` | DKOM / hidden process indicators from kernel memory | T1014 | Root Cause Hunter |
| `PEB_MASQ` | Process masquerading via fake PEB or process title | T1036.004 | Live process telemetry |
| `C2_BEACON` | External beaconing or command channel activity | T1071 | TShark / Live sockets |

## 3. Advanced Security Architecture

### 3.1 Lightweight Mini-Container Isolation

To reduce the risk of escape when handling potentially malicious samples, Yomi implements a mini-container option within the Lazarus Chamber (`sandbox.py`):

- Linux Namespaces: `pid`, `net`, `mount`
- OverlayFS COW layer: `lowerdir` read-only + `upperdir` writable
- `chroot` against a highly restricted root filesystem
- `unshare -n -m -p -f --mount-proc` (crucially omitting the `-r` flag to prevent container escapes via pseudo-root UID mappings)

### 3.2 Large Output Processing

Yomi never loads large forensic tool output entirely into RAM. The SIFT Toolkit implements OS-level non-blocking file descriptors (`fcntl.O_NONBLOCK`) to read results incrementally without deadlocking the server. Results are dynamically truncated to a 100KB safety limit. To prevent CPU starvation, Yomi executes tools using `start_new_session=True`; if a heavy forensic tool times out, Yomi executes a kernel-level `os.killpg()` to atomically annihilate the tool and all its runaway zombie child processes.

### 3.3 Local Air-Gapped Architecture & Cascade Fallback

Yomi's `OpenClawGateway` implements a seamless, fault-tolerant LLM cascade so triage never halts:
1. **Primary:** Gemini 2.5 Pro
2. **Secondary:** Gemini 2.5 Flash
3. **Tertiary (Air-Gapped Fallback):** Local models (e.g., Llama3 via Ollama)

If the external network connection is severed, Yomi automatically times out on the primary/secondary calls and cascades to the local model.

**Performance Optimization (Zero-Latency Override):** In a known zero-connectivity environment, set `export YOMI_AIR_GAPPED_MODE=true` to bypass the 25-second external API timeout delays and route tactical analysis directly to local hardware.

### 3.4 Detection-to-Decision Cascade Flow

```text
[SWARM / SENTINEL] Patrol detects anomalous Socket/Memory artifacts
|
v
[TRIAD COUNCIL LLM] Evaluates context. Is Epistemic Doubt > 40%?
|
v (Yes, Escalate)
[SHADOW NET] eBPF injected into Kernel. Polls sys_enter_execve / sys_enter_openat
|
v (Malicious Syscall Verified)
[OS BRIDGE] Atomic OS Syscall (SIGSTOP) immediately freezes PID
```

### 3.5 Tool Operational Resilience (The Scalpel & C-Binary Fixes)

Many legacy C-based forensic binaries have rigid operational constraints that crash autonomous agents. For instance, `scalpel` aborts execution if an output directory already exists. Yomi circumvents these legacy limitations via dynamic timestamped execution paths (`scalpel_{unix_timestamp}`) and sequential flag coercion (forcing `-c` positioning), for consistent tool operational resilience during live AI triage.

### 3.6 Terminal Interface Resilience Framework (The OMNISCIENT Shield)

The `dashboard.py` (v10.0) Terminal UI is engineered to survive adversarial environments:
- **Lock Splitting & Asynchronous Rendering:** Eliminates lock-starvation DoS. Heavy log ingestion runs on decoupled background threads, so the UI renders at 60fps even under a barrage of 10,000 logs/sec.
- **Terminal Spoofing Immunity:** Autonomous sanitization of `\r`, `\b`, and Unicode directional overrides (`\u202E`) prevents malware from manipulating ANSI escape codes to hide "CRITICAL" alerts behind fake "SUCCESS" messages.
- **Pre-Truncation ReDoS Barrier:** Log strings are hard-capped at 2,000 characters *before* entering the regex ANSI scrubber, preventing regular expression denial of service (ReDoS) CPU spikes.
- **Zero-Overhead VFS Polling:** The TUI only polls the filesystem when `os.stat().st_size` changes, avoiding the redundant disk I/O bottleneck common in traditional log tailers.

### 3.7 Systemd Graceful Termination & Atomic Rollback

When executing in headless mode, Yomi intercepts kernel `SIGTERM` signals emitted by `systemctl stop`. It uses a globally synchronized `threading.Event()` to instantly break infinite wait loops, guaranteeing a clean Sentinel shutdown and ensuring the final `SHUTDOWN` cryptographic chain-of-custody log is successfully sealed to disk. If Ghost Protocol fails to arm its watchdog due to OS restrictions, Yomi executes an atomic rollback (`SystemExit`) to prevent the engine from operating in a vulnerable, unmonitored cloaked state.

---

For known gaps and the current state of each of these boundaries (what's fixed vs. still open), see [`docs/known_issues.md`](known_issues.md).
