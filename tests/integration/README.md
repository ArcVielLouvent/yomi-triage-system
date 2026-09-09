# Integration Tests

Grouped by real data-flow chains, not by folder:
- test_chain_sentinel_router_harness.py
- test_chain_swarm_hunter_dossier.py
- test_chain_guardian_full_pipeline.py   (added once Guardian/module_registry exists)

Rule: integration tests may cross module boundaries and use fixtures/fakes for
external binaries (Volatility, Radare2, GPG) so tests still run without a full
SIFT Workstation, but must never require sudo/root or live network access. A
separate `tests/e2e/` (added later) is reserved for actual SIFT VM runs.
