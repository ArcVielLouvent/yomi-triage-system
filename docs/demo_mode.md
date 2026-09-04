# Demo Mode

## Table of Contents
1. [Enabling the full feature surface](#1-enabling-the-full-feature-surface)
2. [Walkthrough: what actually happens (real, captured output)](#2-walkthrough-what-actually-happens-real-captured-output)
3. [Testing with real forensic datasets (memory dumps, disk images)](#3-testing-with-real-forensic-datasets-memory-dumps-disk-images)
4. [The one hard rule](#4-the-one-hard-rule)

## 1. Enabling the full feature surface

By default, Yomi's invasive-tier modules (Shadow Net, Sandbox, Mirage, Ghost
Protocol, raw eBPF Sensor) are **disabled**. This is the safe default for
unattended / enterprise deployment -- see `yomi_core/module_registry.py` for
the full rationale per module.

For live demos where you want the complete feature surface visible, source
the demo profile before launch:

```bash
export YOMI_MODULE_SHADOW_NET=true
export YOMI_MODULE_SANDBOX=true
export YOMI_MODULE_MIRAGE=true
export YOMI_MODULE_GHOST=true
export YOMI_MODULE_EBPF_SENSOR=true

sudo -E python3 yomi_core/cli.py --auto
```

Or programmatically via `yomi_core.module_registry.DEMO_PROFILE_ENV`.

If you installed via `scripts/install_yomi_linux.sh` (see
[`docs/usage.md`](usage.md#2-installing-as-a-persistent-daemon-linux)), set
these the same way any other module env var is set on an installed daemon:

```bash
sudo systemctl edit yomi-triage
```
```ini
[Service]
Environment=YOMI_MODULE_SHADOW_NET=true
Environment=YOMI_MODULE_SANDBOX=true
Environment=YOMI_MODULE_MIRAGE=true
Environment=YOMI_MODULE_GHOST=true
Environment=YOMI_MODULE_EBPF_SENSOR=true
```
```bash
sudo systemctl daemon-reload && sudo systemctl restart yomi-triage
```

## 2. Walkthrough: what actually happens (real, captured output)

This section traces one synthetic CRITICAL incident through the entire
pipeline with `DEMO_PROFILE_ENV` active, using the exact same
harmless-subprocess technique `scripts/smoke_test_cli.py` uses (see
[`docs/usage.md` Section 3.2](usage.md#32-proving-the-wired-pipeline-works-end-to-end-the-smoke-test)),
just with every optional module turned on instead of left at defaults. The
ledger excerpt below is **real, captured output** from an actual run, not a
hypothetical example -- reproduce it yourself with the snippet in
[3.2's smoke test](usage.md#32-proving-the-wired-pipeline-works-end-to-end-the-smoke-test)
after exporting `DEMO_PROFILE_ENV`'s variables first.

```
SENTINEL     AUTONOMOUS_CONTAINMENT    CRITICAL THREAT: Executed immediate SIGSTOP...
OMNI_LIBRARY LEDGER_VERIFICATION       Verified immutable audit ledger on startup.
MINDREADER   DECOMPILATION_FALLBACK   Radare2 failed, deploying native string extractor.
MINDREADER   PROFILE_GENERATED        Psychological profile created for PID <pid>
MINDREADER   KNOWLEDGE_UPDATED        New APT signature (CVE-2026-YOMI<pid>) saved...
REVERSER     INITIALIZATION           Remediator engine initialized...
REVERSER     ABORTED                  Refusing remediation on critical system path: /usr/bin/python3...
LAZARUS      CONTAINMENT_SUCCESS      Secured at .../yomi_data/lazarus_chamber/...
LAZARUS      RESURRECTION_ACTIVE      Detonated in isolated PID namespace <ns_pid>.
MIRAGE       HALLUCINATION_DEPLOYED   Synthetic LINUX honeytokens deployed at ...
MIRAGE       HALLUCINATION_DEPLOYED   Synthetic LINUX honeytokens deployed at ...
TELEMETRY    BENCHMARK_RECORDED       Latency Benchmark: 0.4714s | Speed: 2545.3x Faster
HUNTER       ROOT_CAUSE_COMPILED      PID <pid> Hunt Completed.
MITRE_MAPPER MAPPED                   Mapped 1 unique tactics across 1 anomalies.
ROUTER       TRIAGE_ITERATION         Starting triage iteration 1.
TRIAD_COUNCIL APPROVED                 Action 'freeze' on PID <pid> approved with 5.0% doubt.
HARNESS      SUCCESS                  {'status': 'SUCCESS', 'action': 'FROZEN', ...}
WEAVER       NARRATIVE_GENERATED      Converted raw ledger into dynamic human-readable dossier.
DOSSIER      REPORT_SIGNED            Generated Dual-Artifact Dossier. PDF Mode: HMAC-SHA256 | ...
MIRAGE       HALLUCINATION_TEARDOWN   Decoy environment for PID <pid> securely destroyed.
OMNI_LIBRARY LEDGER_VERIFICATION       Verified immutable audit ledger on startup.
MINDREADER   DECOMPILATION_FALLBACK   Radare2 failed, deploying native string extractor.
MINDREADER   PROFILE_GENERATED        Psychological profile created for PID <pid>
LAZARUS      CONTAINER_DESTROYED      Chamber for PID <pid> obliterated.
```

Three things worth understanding about this trace, so it doesn't look like a
bug when you see it yourself:

- **`MINDREADER` and `MIRAGE` each appear twice.** This is intentional
  two-phase analysis, not a duplicate dispatch: the first pass (right after
  `AUTONOMOUS_CONTAINMENT`) is `GuardianOrchestrator`'s pre-detonation
  static analysis on the frozen process's binary. The second pass (after
  `HALLUCINATION_TEARDOWN`) is `sandbox.py`'s own post-detonation
  re-analysis, run once the "detonation window" (the process is woken with
  `SIGCONT` inside an isolated chamber and observed for up to 15 seconds)
  closes -- useful because a dropper's on-disk state can change once it
  actually runs. Both call sites independently check `module_registry`
  (see [`docs/known_issues.md`](known_issues.md) #29), so disabling
  `MIND_READER` or `MIRAGE` suppresses both passes, not just one.
- **Two `HALLUCINATION_DEPLOYED` entries, only one `HALLUCINATION_TEARDOWN`.**
  The two Mirage dispatches above are independent decoys with different
  lifecycles -- `sandbox.py` tears its own down immediately after the
  observation window; the one `GuardianOrchestrator` deployed is cleaned up
  later by the periodic orphan sweep instead. Not data loss, not a security
  gap, just an asymmetry worth recognizing -- tracked as
  [`docs/known_issues.md`](known_issues.md) #30.
- **`REVERSER ABORTED` is expected, not a failure.** In this trace the
  "malware" is a real Python interpreter process (the harmless subprocess
  technique itself), so `/proc/<pid>/exe` resolves to the real Python
  binary -- which correctly lives under a protected system directory
  (`/usr`). Remediator's [`known_issues.md`](known_issues.md) #15
  containment fix refuses to generate a rollback script for it. Against a
  real malware sample living somewhere like `/tmp` or a user's home
  directory, you'd see a `SUCCESS` here instead, with a real generated
  script in `yomi_data/remediation/`.

`Shadow Net` and `Ghost Protocol` don't appear in this specific trace because
this scenario used the instant CRITICAL-containment path (no self-correction
loop, so `SHADOW_NET` never escalates) and ran in the foreground (Ghost
Protocol engages at CLI startup, not per-incident) -- see
`yomi_core/guardian.py`'s module docstring for exactly which dispatch path
each module hangs off of, and [`docs/usage.md` Section 3.1](usage.md#31-the-chain-of-custody-ledger)
for what each `action_type` means.

## 3. Testing with real forensic datasets (memory dumps, disk images)

Everything above uses synthetic, in-memory anomaly data -- deliberately, so
it's safe, fast, and reproducible without needing an actual malware sample or
multi-gigabyte memory image. To exercise Yomi's actual SIFT tool wrappers
(`yomi_mcp/sift_toolkit.py`) against real forensic artifacts, you need a real
dataset. None of this section is run by `./run_tests.sh` or the smoke test --
it requires the real SIFT toolchain installed (see
[`docs/installation.md`](installation.md)) and a downloaded dataset, so
treat it as a manual, one-time verification exercise, not a CI check.

### 3.1 Where to get free, legal test datasets

| Source | What it has | Notes |
| :--- | :--- | :--- |
| [NIST CFReDS](https://cfreds.nist.gov/) | Memory images, disk images, purpose-built for forensic tool testing/validation | US government-run, documented ground truth for many sets |
| [Digital Corpora](https://digitalcorpora.org/) | Memory dumps, disk images, network captures (M57 scenarios, Nitroba, etc.) | Freely downloadable, no registration for most sets |
| [Volatility Foundation's Memory Samples wiki](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) | Small, well-known malware-infected memory images (e.g. `cridex.vmem`) | Maintained by the tool authors themselves; good for a first test since the images are small and the expected findings are documented |

`cridex.vmem` (from the Volatility wiki above) is a good starting point: it's
small, Windows XP, and contains a documented Cridex banking-trojan infection
-- exactly the kind of artifact `run_volatility_pslist`/`run_volatility_netscan`/
`run_volatility_windows_malfind` are built to surface.

### 3.2 Running Yomi's memory-forensics wrappers against a downloaded image

Once you have an image (adjust the path below to wherever you downloaded it):

```bash
python3 -c "
from yomi_mcp.sift_toolkit import SiftArsenal
arsenal = SiftArsenal()
print(arsenal.run_volatility_pslist('/path/to/cridex.vmem'))
print(arsenal.run_volatility_netscan('/path/to/cridex.vmem'))
print(arsenal.run_volatility_windows_malfind('/path/to/cridex.vmem'))
"
```

Or through the MCP tool-call interface Yomi's own LLM cascade uses (matches
the tool names in `yomi_mcp/mcp_server.py`'s schema):

```bash
python3 -c "
from yomi_mcp.mcp_server import YomiMCPServer
server = YomiMCPServer()
result = server.call_tool('run_volatility_pslist', {'memory_dump_path': '/path/to/cridex.vmem'})
print(result)
"
```

**Honesty note on tool failures:** SIFT tool behavior against real images
varies by exact tool version, image format, and profile-detection success --
this is expected, not a Yomi bug. [`docs/dataset_documentation.md`](dataset_documentation.md)
documents a real case from the original hackathon submission where Volatility
failed to parse a provided memory dump due to format/extension mismatches,
and the MCP Vault correctly trapped the I/O error, logged a tool failure to
the ledger, and pivoted rather than letting the LLM hallucinate findings from
empty output. If a tool fails against your downloaded image, check the
returned `dict`'s error message first -- Yomi is designed to report failures
honestly rather than mask them.

### 3.3 Running a disk image through The Sleuth Kit wrappers

Same pattern, using `run_tsk_fls` / `run_tsk_img_stat` / `run_tsk_icat`
against a disk image from [NIST CFReDS](https://cfreds.nist.gov/) or
[Digital Corpora](https://digitalcorpora.org/) (e.g. one of the M57 scenario
images):

```bash
python3 -c "
from yomi_mcp.sift_toolkit import SiftArsenal
arsenal = SiftArsenal()
print(arsenal.run_tsk_img_stat('/path/to/disk.dd'))
print(arsenal.run_tsk_fls('/path/to/disk.dd'))
"
```

### 3.4 Feeding real findings into the full pipeline

The manual, step-by-step walkthrough in
[`docs/dataset_documentation.md`](dataset_documentation.md) (originally
written for SANS hackathon judges, still accurate against the current
codebase per its own provenance note) shows how to chain real tool output
from `swarm.py`, `hunter.py`, and `mind_reader.py` together against a live
frozen PID, culminating in a signed `dossier.py` report -- that document is
the deeper, tool-by-tool reference; this section is the quick-start pointer
to where the underlying data comes from.

## 4. The one hard rule

This file (and the registry it documents) is the enforcement mechanism for
one hard rule going forward: **every module in this codebase must be
reachable and toggleable from one central place.** No module is allowed to
exist in the source tree without an entry in `module_registry.py` and a
decision -- default on, default off, or explicitly deprecated/removed.

Two violations of this rule were found and fixed during Fase 6: Ghost
Protocol and the eBPF Sensor bypassing the registry in `cli.py`
([`docs/known_issues.md`](known_issues.md) #26), and `sandbox.py`'s
post-detonation re-analysis pass bypassing it for `MIND_READER`/`MIRAGE`
(#29) -- both found by actually running full end-to-end scenarios, not by
code review alone. If you add a new module or a new call site for an
existing one, check it against a real `module_registry.is_enabled()` (or
`resolve_active_modules()`) call before it does anything -- and if you're not
sure whether an existing call site does, the fastest way to check is exactly
what surfaced both of the bugs above: actually run
[`scripts/smoke_test_cli.py`](../scripts/smoke_test_cli.py) or the
`DEMO_PROFILE_ENV` walkthrough in [Section 2](#2-walkthrough-what-actually-happens-real-captured-output)
and read the resulting ledger, rather than assuming the code is correct from
inspection alone.
