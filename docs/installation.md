<div align="center">
  <h1>YOMI TRIAGE SYSTEM</h1>
  <h2>Prerequisites & Installation Guide</h2>
</div>

## 1. Prerequisites & System Requirements

-   **Host OS:** SANS SIFT Workstation OVA (Ubuntu-based) is required to fully utilize the 200+ DFIR toolchain. Windows/Mac environments will trigger the OSBridge to run in "Minimal/Passive Mode".

-   **Hardware:** Minimum 4 vCPUs, 8GB RAM (16GB recommended for heavy Volatility processing).

-   **Python:** 3.10+

-   **System Dependencies & Compilation Clarification:**
    -   Yomi relies on strictly version-pinned packages (`==`) to prevent Dependency Confusion supply chain attacks.
    -   `psutil` and `setproctitle` require C-extension compilation. In strict Air-Gapped SIFT environments lacking `gcc`, it is recommended to install the OS-level headers first: `sudo apt-get install python3-psutil python3-setproctitle`.
    -   *Process Manipulation:* Handled natively and atomically via OS-level signals (`SIGSTOP`, `SIGCONT`, `kill -9`).
    -   *Deep Kernel Monitoring:* Handled via **eBPF (bcc)** in kernel space (`sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc`). Do NOT install `bcc` via pip.

-   **SIFT Toolchain Dependencies (must be in `PATH`):**
    -   **Volatility 3** (`vol.py` / `vol`)
    -   **Radare2** (`r2`)
    -   **Plaso** (`log2timeline.py`)
    -   **The Sleuth Kit** (`fls`, `img_stat`, `icat`)

## 2. Installation & Deployment Guide

**Step 1: Clone into the SIFT Workstation**

```bash
git clone https://github.com/ArcVielLouvent/yomi-triage-system.git
cd yomi-triage-system
```

**Step 2: Install Python Libraries and OS Packages**

```bash
# Python dependencies
python -m pip install -r requirements.txt

# For Ring-0 Kernel monitoring (eBPF)
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

**Step 3: Environment Configuration**

To maintain operational security and prevent credential dumping during an incident, Yomi strictly utilizes OS-level environment variables. It does not write API keys to disk. Export your credentials before launching:

```bash
export YOMI_GEMINI_API_KEY="your_api_key_here"

# Optional: Override the default local LLM endpoint (defaults to local Ollama)
export YOMI_LOCAL_LLM_URL="your_local_llm_url"
```

See [`docs/security.md`](security.md#1-security--compliance-framework) for the optional KMS-backed and ephemeral HMAC key modes for the audit ledger (`YOMI_AUDIT_HMAC_KMS_PROVIDER`, `YOMI_AUDIT_HMAC_MODE`).

---

Once installed, see [`docs/usage.md`](usage.md) for how to run Yomi.
