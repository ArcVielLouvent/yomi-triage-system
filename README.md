<div align="center">
  <h1>YOMI TRIAGE SYSTEM</h1>
  <p><b>Autonomous DFIR Engine</b></p>
  <p><i>Live EDR/eBPF containment, MCP-safe LLM orchestration, and a cryptographic chain of custody -- evolving toward full-depth digital forensics.</i></p>
</div>

---

## What Yomi is

Yomi orchestrates SANS SIFT Workstation forensic tools through a type-safe Model Context Protocol (MCP) server, evaluates evidence through a cascading Epistemic Doubt Engine, and can autonomously freeze a suspect process (`SIGSTOP`) in seconds while sealing every decision into an HMAC-signed, append-only ledger. The LLM is treated as an untrusted reasoning engine; all destructive actions are gated by hardcoded, architectural veto logic, not prompt trust.

Yomi started as a submission to the SANS "Find Evil!" hackathon (KuroTech banner) and did not place in the Top 5. The honest read on why: Yomi's live EDR/eBPF architecture is sound, but the competition rewarded post-mortem forensic *depth*, and Yomi's own capabilities were broader than they were tested. The project is now being rebuilt on that lesson -- narrower claims, deeper test coverage, and closing the one gap none of the five finalists had either: **cross-artifact correlation** across memory, disk, timeline, network, malware/binary, and registry forensics. See [`docs/roadmap/dfir-depth.md`](docs/roadmap/dfir-depth.md) for the full plan and [`docs/phase_log/`](docs/phase_log/) for progress phase by phase.

## Quickstart

```bash
git clone https://github.com/ArcVielLouvent/yomi-triage-system.git
cd yomi-triage-system
python -m pip install -r requirements.txt
export YOMI_GEMINI_API_KEY="your_api_key_here"   # optional -- falls back to local LLM if unset
sudo python3 yomi_core/cli.py --auto
```

Full prerequisites, OS packages, and environment configuration: [`docs/installation.md`](docs/installation.md).

## Documentation

| Topic | Where |
| :--- | :--- |
| System architecture, data flow, module reference | [`docs/architecture.md`](docs/architecture.md) |
| Security & compliance framework, threat model | [`docs/security.md`](docs/security.md) |
| Prerequisites & installation | [`docs/installation.md`](docs/installation.md) |
| Operational commands, tactical playbook, benchmarks | [`docs/usage.md`](docs/usage.md) |
| Demo mode (enabling invasive-tier modules) | [`docs/demo_mode.md`](docs/demo_mode.md) |
| Dataset & reproducibility notes | [`docs/dataset_documentation.md`](docs/dataset_documentation.md) |
| Accuracy report / hallucination defense | [`docs/accuracy_report.md`](docs/accuracy_report.md) |
| Known issues log (bugs, design gaps, fix status) | [`docs/known_issues.md`](docs/known_issues.md) |
| DFIR-depth roadmap (cross-artifact correlation, etc.) | [`docs/roadmap/dfir-depth.md`](docs/roadmap/dfir-depth.md) |
| Phase-by-phase development log | [`docs/phase_log/`](docs/phase_log/) |
| Original SANS hackathon submission (archived) | [`docs/hackathon/sans_submission.md`](docs/hackathon/sans_submission.md) |

## Running the tests

```bash
./run_tests.sh          # lint + unit + integration + benchmarks + smoke
./run_tests.sh quick     # unit tests only, fastest loop
./run_tests.sh smoke     # real end-to-end chain only, no pytest -- see docs/usage.md
```

---

### License & Attribution

This project is licensed under the **MIT License**. See the [`LICENSE`](LICENSE) file for details.

Built under the **KuroTech** banner. Originally submitted to the SANS Institute Find Evil! Hackathon -- see [`docs/hackathon/sans_submission.md`](docs/hackathon/sans_submission.md) for that original framing. Gratitude to the maintainers of the SIFT Workstation, Volatility Foundation, and the open-source DFIR community.
