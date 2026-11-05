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

**Where Yomi keeps its data (optional)**

By default the evidence ledger, HMAC key, CVE store, reports, remediation scripts, locks and decoys live in `yomi_data/` next to the package. For a `pip`-installed daemon that is inside the virtualenv's `site-packages`. To keep it somewhere predictable, set an absolute path (a relative path is rejected):

```bash
export YOMI_DATA_DIR=/var/lib/yomi-triage
```

For the systemd service, put `Environment=YOMI_DATA_DIR=/var/lib/yomi-triage` in the same override described in [`docs/usage.md`](usage.md). Set it before the first run: existing data is not moved automatically.

**MCP vault boundaries (optional)**

The MCP server only reads and writes inside allowlisted directories. If your case data lives outside the built-in ones (`/tmp`, `/var/tmp`, `/mnt`, `/home`, `/workspace`, `/data`, `/media`, `/opt/yomi` for reads; `/tmp`, `/var/tmp`, `/workspace/output`, `/data/output`, `/opt/yomi/output` for writes), add roots, separated by `:` on Linux:

```bash
export YOMI_MCP_READ_VAULTS=/srv/cases
export YOMI_MCP_WRITE_VAULTS=/srv/cases/output
```

These only add to the built-in lists. Entries must be absolute paths and `/` is refused. The data directory is deliberately not added automatically because it contains the audit HMAC key.

---

Once installed, see [`docs/usage.md`](usage.md) for how to run Yomi.
